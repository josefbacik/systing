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
/// Returns a `-I/usr/include/<triplet>` string if needed, or None.
fn detect_multiarch_include() -> Option<String> {
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

#[cfg(feature = "pystacks")]
fn build_pystacks_bpf(out_dir: &Path, multiarch_include: &Option<String>) {
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

    let mut clang_args = vec![
        OsStr::new(&bpf_include_arg),
        OsStr::new(&pystacks_include_arg),
        OsStr::new(&pystacks_bpf_arg),
        OsStr::new("-D__x86_64__"),
    ];

    if let Some(ref include_path) = multiarch_include {
        clang_args.push(OsStr::new(include_path));
    }

    SkeletonBuilder::new()
        .source("src/pystacks/bpf/pystacks.bpf.c")
        .clang_args(clang_args)
        .obj(obj_path.to_str().unwrap())
        .build()
        .expect("Failed to build pystacks BPF object");

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

#[cfg(not(feature = "pystacks"))]
fn build_pystacks_bpf(_: &Path, _: &Option<String>) {}

#[cfg(not(feature = "generate-vmlinux-header"))]
fn generate_vmlinux_header() {}

#[cfg(feature = "generate-vmlinux-header")]
fn generate_vmlinux_header() {
    let vmlinux_path = PathBuf::from("src/bpf/").join("vmlinux.h");

    let bpftool_output = std::process::Command::new("bpftool")
        .args([
            "btf",
            "dump",
            "file",
            "/sys/kernel/btf/vmlinux",
            "format",
            "c",
        ])
        .output()
        .expect("Failed to execute bpftool");
    std::fs::write(&vmlinux_path, bpftool_output.stdout).expect("Failed to write vmlinux.h");
}

fn main() {
    let out_dir =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));

    generate_vmlinux_header();

    // Detect multiarch include path once for all BPF compilations
    let multiarch_include = detect_multiarch_include();

    // Build pystacks BPF object (when feature enabled)
    build_pystacks_bpf(&out_dir, &multiarch_include);

    let include_arg = format!("-I{}", out_dir.display());
    let bpf_include_arg = format!(
        "-I{}",
        Path::new("src/bpf")
            .canonicalize()
            .expect("src directory exists")
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

        // allow mut for feature pystacks
        #[allow(unused_mut)]
        let mut clang_args = vec![
            OsStr::new(&bpf_include_arg),
            OsStr::new(&include_arg),
            OsStr::new("-D__x86_64__"),
        ];

        if let Some(ref include_path) = multiarch_include {
            clang_args.push(OsStr::new(include_path));
        }

        #[cfg(feature = "pystacks")]
        {
            clang_args.push(OsStr::new("-DSYSTING_PYSTACKS"));

            let pystacks_inc = format!(
                "-I{}",
                Path::new("src/pystacks/bpf/include")
                    .canonicalize()
                    .expect("pystacks bpf include dir exists")
                    .display()
            );
            // Leak the string so OsStr can reference it for the clang_args lifetime
            let pystacks_inc: &'static str = Box::leak(pystacks_inc.into_boxed_str());
            clang_args.push(OsStr::new(pystacks_inc));

            let pystacks_bpf = format!(
                "-I{}",
                Path::new("src/pystacks/bpf")
                    .canonicalize()
                    .expect("pystacks bpf dir exists")
                    .display()
            );
            let pystacks_bpf: &'static str = Box::leak(pystacks_bpf.into_boxed_str());
            clang_args.push(OsStr::new(pystacks_bpf));
        }

        SkeletonBuilder::new()
            .source(src)
            .clang_args(clang_args)
            .obj(obj_path.to_str().unwrap())
            .build()
            .expect("Failed to build BPF skeleton");

        println!("cargo:rerun-if-changed={src}");
    }

    // Link individual BPF objects into a single object file for skeleton generation.
    let obj_path = out_dir.join("systing_system.bpf.o");

    let mut linker = libbpf_rs::Linker::new(&obj_path).expect("Failed to create BPF linker");
    linker
        .add_file(out_dir.join("systing_system_tmp.bpf.o"))
        .expect("Failed to add systing_system BPF object");

    #[cfg(feature = "pystacks")]
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
