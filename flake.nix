{
  description = "systing - a libbpf based system tracer";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
        };

        # Clang wrapper that dispatches to unwrapped clang for BPF targets.
        # The Nix cc-wrapper adds hardening flags (e.g. -fzero-call-used-regs)
        # that are not supported by the BPF backend. For all other targets the
        # normal wrapped clang is used so linking can find CRT objects and
        # system libraries.
        clangBpfWrapper = pkgs.writeShellScriptBin "clang" ''
          prev=""
          for arg in "$@"; do
            if [ "$prev" = "-target" ] && [ "$arg" = "bpf" ]; then
              exec "${pkgs.llvmPackages.clang-unwrapped}/bin/clang" "$@"
            fi
            case "$arg" in
              --target=bpf|-target=bpf)
                exec "${pkgs.llvmPackages.clang-unwrapped}/bin/clang" "$@"
                ;;
            esac
            prev="$arg"
          done
          exec "${pkgs.llvmPackages.clang}/bin/clang" "$@"
        '';
      in
      {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            rustToolchain
            pkg-config
            cmake
            protobuf
            clangBpfWrapper
          ];

          buildInputs = with pkgs; [
            elfutils     # libelf, libdw - needed by libbpf-sys and blazesym
            zlib         # needed by libbpf-sys
            linuxHeaders # kernel headers (asm/, linux/) for BPF compilation
          ];

          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

          shellHook = ''
            # Make kernel and glibc headers available for BPF compilation.
            # When clang targets BPF (-target bpf), it does not search standard
            # system include paths. CPATH is respected regardless of target and
            # acts like -isystem for all compilations.
            export CPATH="${pkgs.linuxHeaders}/include:${pkgs.glibc.dev}/include''${CPATH:+:$CPATH}"
          '';
        };
      });
}
