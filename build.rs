use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use libbpf_cargo::SkeletonBuilder;

const SRC: [&str; 1] = ["src/bpf/systing_system.bpf.c"];

/// Detect the multiarch include path for Ubuntu/Debian systems.
///
/// On these distros, headers like `asm/errno.h` and `bits/wordsize.h` live
/// under `/usr/include/<triplet>/` (e.g. `/usr/include/x86_64-linux-gnu/`).
/// On Fedora/RHEL they're directly in `/usr/include/asm/`.
///
/// When cross-compiling, the triplet must be the TARGET's, not the build
/// host's: the BPF objects are compiled with the target's `-D__<arch>__`
/// define, and host libc headers plus a foreign arch define fall over in
/// arch-conditional glibc internals. Concretely, compiling for aarch64 on
/// an x86_64 host, x86's `gnu/stubs.h` hits `#include <gnu/stubs-32.h>`
/// (absent on a 64-bit-only install) because under `-target bpf` neither
/// `__x86_64__` nor `__i386__` is defined.
///
/// Returns a `-I<dir>` string if needed, or None.
fn detect_multiarch_include() -> Option<String> {
    // Cross build: prefer the target's header locations. On Debian/Ubuntu
    // these are /usr/include/<triplet> (multiarch, from libc6-dev:<arch>)
    // or /usr/<triplet>/include (cross-toolchain sysroot, shipped alongside
    // gcc-<triplet>). If neither exists, warn and return None rather than
    // silently offering the HOST's headers — setups with a real sysroot
    // pass their own include flags.
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH not set");
    if target_arch != env::consts::ARCH {
        // get_arch_config() already restricts supported targets.
        let triplet = match target_arch.as_str() {
            "x86_64" => "x86_64-linux-gnu",
            "aarch64" => "aarch64-linux-gnu",
            "riscv64" => "riscv64-linux-gnu",
            _ => return None,
        };
        let candidates = [
            format!("/usr/include/{triplet}"),
            format!("/usr/{triplet}/include"),
        ];
        for dir in &candidates {
            if Path::new(dir).exists() {
                return Some(format!("-I{dir}"));
            }
        }
        let deb_arch = match target_arch.as_str() {
            "aarch64" => "arm64",
            "riscv64" => "riscv64",
            "x86_64" => "amd64",
            other => panic!("Unsupported architecture: {other}"),
        };
        println!(
            "cargo:warning=cross-compiling for {target_arch} but neither {} nor {} exists; \
             BPF compilation may fail or pick up host libc headers \
             (on Debian/Ubuntu: apt install libc6-dev:{deb_arch} or the {triplet} cross toolchain)",
            candidates[0], candidates[1],
        );
        return None;
    }

    // Check that both asm/ and bits/ headers are available directly.
    // On some CI environments (GitHub Actions), /usr/include/asm is symlinked
    // to asm-generic but bits/wordsize.h still lives under the multiarch path.
    if Path::new("/usr/include/asm").exists() && Path::new("/usr/include/bits").exists() {
        return None;
    }

    // Try multiple methods to detect the multiarch triplet, in order of
    // reliability and availability across different environments.
    let triplet = None
        // 1. dpkg-architecture (Debian/Ubuntu with dpkg-dev installed)
        .or_else(|| {
            std::process::Command::new("dpkg-architecture")
                .arg("-qDEB_HOST_MULTIARCH")
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
        })
        // 2. cc -dumpmachine (works on any system with a C compiler)
        .or_else(|| {
            std::process::Command::new("cc")
                .arg("-dumpmachine")
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
        });

    triplet
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty() && Path::new(&format!("/usr/include/{t}")).exists())
        .map(|t| format!("-I/usr/include/{t}"))
}

/// The compiler flags every BPF object is compiled with so that a local or CI
/// build produces the release build's program, not merely the same source.
///
/// `-mcpu=v3`: the release build compiles with clang 21, whose default
/// `-mcpu` for the BPF target is v3; a distro clang 18 defaults to v1. The
/// two levels produce different programs from the same source — different
/// register allocation around the same stores — and the verifier judges the
/// program, not the source, so a local or CI build at v1 can load where the
/// release object is rejected (that is how the rss_stat index bound was
/// wrong in a release while every local check passed).
///
/// `-fwrapv`: the release build's toolchain compiles with `-fwrapv` (its
/// hardening set makes signed overflow wrap). That changes the code generated
/// for signed delta arithmetic — the memory recorder's brk/mmap/munmap exit
/// handlers differ in register allocation without it — so pin it too; with
/// both flags the embedded object is instruction-identical to the release's.
/// `SYSTING_BPF_CLANG` (below) closes the remaining compiler-version gap.
const BPF_CFLAGS: &[&str] = &["-mcpu=v3", "-fwrapv"];

/// Optional override for the C compiler used for the BPF objects, so a
/// local or CI build can use the exact compiler the release build uses
/// (`SYSTING_BPF_CLANG=/path/to/clang-21`). Unset or empty: libbpf-cargo's
/// default (`clang` on PATH).
fn bpf_clang_override() -> Option<PathBuf> {
    println!("cargo:rerun-if-env-changed=SYSTING_BPF_CLANG");
    env::var_os("SYSTING_BPF_CLANG")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Compile one BPF object with the compiler pinning every BPF object build
/// shares: the pinned flags ([`BPF_CFLAGS`]) and the `SYSTING_BPF_CLANG`
/// override.
///
/// The pinned flags are prepended here, not by the callers: libbpf-cargo's
/// `clang_args` REPLACES the argument list rather than appending to it, so a
/// caller that assembled its own list (or called `clang_args` twice) would
/// silently compile that object without the pin. Callers pass only their
/// object-specific arguments and never hold the builder, which is what makes
/// the pin structural.
fn compile_bpf_object(source: &str, obj_path: &Path, object_args: &[&OsStr]) {
    let mut clang_args: Vec<&OsStr> = BPF_CFLAGS.iter().map(OsStr::new).collect();
    clang_args.extend_from_slice(object_args);

    let mut builder = SkeletonBuilder::new();
    if let Some(clang) = bpf_clang_override() {
        builder.clang(clang);
    }
    builder
        .source(source)
        .clang_args(clang_args)
        .obj(obj_path)
        .build()
        .unwrap_or_else(|err| panic!("Failed to build BPF object from {source}: {err}"));
}

fn build_pystacks_bpf(out_dir: &Path, arch_define: &str, multiarch_include: &Option<String>) {
    let out_dir_include_arg = format!("-I{}", out_dir.display());

    let bpf_include_arg = format!(
        "-I{}",
        Path::new("src/bpf")
            .canonicalize()
            .expect("src directory exists")
            .display()
    );

    let pystacks_include_arg = format!(
        "-I{}",
        Path::new("src/pystacks/bpf/include")
            .canonicalize()
            .expect("src/pystacks/bpf/include directory exists")
            .display()
    );

    let pystacks_bpf_arg = format!(
        "-I{}",
        Path::new("src/pystacks/bpf")
            .canonicalize()
            .expect("src/pystacks/bpf directory exists")
            .display()
    );

    let obj_path = out_dir.join("pystacks.bpf.o");

    let mut object_args = vec![
        OsStr::new(&out_dir_include_arg),
        OsStr::new(&bpf_include_arg),
        OsStr::new(&pystacks_include_arg),
        OsStr::new(&pystacks_bpf_arg),
        OsStr::new(arch_define),
    ];

    if let Some(ref include_path) = multiarch_include {
        object_args.push(OsStr::new(include_path));
    }

    compile_bpf_object("src/pystacks/bpf/pystacks.bpf.c", &obj_path, &object_args);

    // Generate pystacks skeleton for typed access to BSS variables and maps.
    let pystacks_skel_path = out_dir.join("pystacks.skel.rs");
    SkeletonBuilder::new()
        .obj(&obj_path)
        .generate(&pystacks_skel_path)
        .expect("Failed to generate pystacks skeleton");

    // Track pystacks BPF source files for rebuilds
    println!("cargo:rerun-if-changed=src/pystacks/bpf/pystacks.bpf.c");
    println!("cargo:rerun-if-changed=src/pystacks/bpf/pystacks.bpf.h");
    for entry in std::fs::read_dir("src/pystacks/bpf/include")
        .into_iter()
        .flatten()
        .flatten()
    {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str());
        if matches!(ext, Some("c" | "h")) {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

/// Detect the target architecture and return the corresponding clang define
/// and vmlinux header filename.
///
/// Note: clang does NOT define `__x86_64__` or `__aarch64__` when compiling with
/// `-target bpf`. libbpf-cargo auto-adds `-D__TARGET_ARCH_x86` (used by
/// `bpf/bpf_tracing.h`), but our BPF C code uses `__x86_64__`/`__aarch64__` guards,
/// so we must pass the explicit `-D__<arch>__` define ourselves.
fn get_arch_config() -> (&'static str, &'static str) {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH not set");
    match arch.as_str() {
        "x86_64" => ("-D__x86_64__", "vmlinux_x86_64.h"),
        "aarch64" => ("-D__aarch64__", "vmlinux_aarch64.h"),
        "riscv64" => ("-D__riscv64__", "vmlinux_riscv64.h"),
        _ => panic!(
            "Unsupported architecture: {arch}. Only x86_64, aarch64 and riscv64 are supported."
        ),
    }
}

fn main() {
    let out_dir =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));

    // Detect target architecture for vmlinux header selection and clang defines
    let (arch_define, vmlinux_filename) = get_arch_config();

    // Copy the arch-specific vmlinux header to OUT_DIR as vmlinux.h so that
    // BPF C code can find it via -I$OUT_DIR with `#include "vmlinux.h"` or
    // `#include <vmlinux.h>` unchanged.
    let vmlinux_src = PathBuf::from("src/bpf").join(vmlinux_filename);
    let vmlinux_dst = out_dir.join("vmlinux.h");

    if !vmlinux_src.exists() {
        panic!(
            "Architecture-specific vmlinux header not found: {}\n\
             Generate it on a {} machine with: ./scripts/generate-vmlinux-header.sh",
            vmlinux_src.display(),
            env::var("CARGO_CFG_TARGET_ARCH").unwrap()
        );
    }

    std::fs::copy(&vmlinux_src, &vmlinux_dst)
        .unwrap_or_else(|e| panic!("Failed to copy {}: {e}", vmlinux_src.display()));

    println!("cargo:rerun-if-changed={}", vmlinux_src.display());
    // Defensive: Cargo already re-runs build scripts when the target changes, but
    // this makes the dependency on the target architecture explicit.
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ARCH");

    // Detect multiarch include path once for all BPF compilations
    let multiarch_include = detect_multiarch_include();

    // Build pystacks BPF object
    build_pystacks_bpf(&out_dir, arch_define, &multiarch_include);

    let include_arg = format!("-I{}", out_dir.display());
    let bpf_include_arg = format!(
        "-I{}",
        Path::new("src/bpf")
            .canonicalize()
            .expect("src directory exists")
            .display()
    );
    let pystacks_inc_arg = format!(
        "-I{}",
        Path::new("src/pystacks/bpf/include")
            .canonicalize()
            .expect("pystacks bpf include dir exists")
            .display()
    );
    let pystacks_bpf_arg = format!(
        "-I{}",
        Path::new("src/pystacks/bpf")
            .canonicalize()
            .expect("pystacks bpf dir exists")
            .display()
    );
    for src in SRC {
        let srcpath = Path::new(src);
        let fname = srcpath.file_name().unwrap().to_str().unwrap();
        let prefix = match fname.split_once(".bpf.c") {
            Some((prefix, _)) => prefix,
            None => fname,
        };
        let obj_path = out_dir.join(format!("{prefix}_tmp.bpf.o"));

        let mut object_args = vec![
            OsStr::new(&include_arg),
            OsStr::new(&bpf_include_arg),
            OsStr::new(arch_define),
            OsStr::new("-DSYSTING_PYSTACKS"),
            OsStr::new(&pystacks_inc_arg),
            OsStr::new(&pystacks_bpf_arg),
        ];

        if let Some(ref include_path) = multiarch_include {
            object_args.push(OsStr::new(include_path));
        }

        compile_bpf_object(src, &obj_path, &object_args);

        println!("cargo:rerun-if-changed={src}");
    }

    // Link individual BPF objects into a single object file for skeleton generation.
    let obj_path = out_dir.join("systing_system.bpf.o");

    let mut linker = libbpf_rs::Linker::new(&obj_path).expect("Failed to create BPF linker");
    linker
        .add_file(out_dir.join("systing_system_tmp.bpf.o"))
        .expect("Failed to add systing_system BPF object");

    linker
        .add_file(out_dir.join("pystacks.bpf.o"))
        .expect("Failed to add pystacks BPF object");

    linker.link().expect("Failed to link BPF objects");

    let skel_path = out_dir.join("systing_system.skel.rs");
    SkeletonBuilder::new()
        .obj(obj_path)
        .generate(&skel_path)
        .expect("Failed to build BPF skeleton");
}
