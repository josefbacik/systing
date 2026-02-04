use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use libbpf_cargo::SkeletonBuilder;

const SRC: [&str; 1] = ["src/bpf/systing_system.bpf.c"];

#[cfg(feature = "pystacks")]
fn build_pystacks_bpf(out_dir: &Path) {
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

    // Handle multiarch include paths for Ubuntu/Debian
    let multiarch_include = if !Path::new("/usr/include/asm").exists() {
        std::process::Command::new("dpkg-architecture")
            .arg("-qDEB_HOST_MULTIARCH")
            .output()
            .ok()
            .and_then(|output| {
                if output.status.success() {
                    String::from_utf8(output.stdout).ok()
                } else {
                    None
                }
            })
            .map(|triplet| format!("-I/usr/include/{}", triplet.trim()))
    } else {
        None
    };

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
    // This skeleton is used as a subskeleton opened against the main BPF object.
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
fn build_pystacks_bpf(_: &Path) {}

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

    // Build pystacks BPF object (when feature enabled)
    build_pystacks_bpf(&out_dir);

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

        // Handle multiarch include paths for Ubuntu/Debian
        // On these distros, asm/errno.h is in /usr/include/<triplet>/asm/
        // On Fedora/RHEL, it's directly in /usr/include/asm/
        let multiarch_include = if !Path::new("/usr/include/asm").exists() {
            // Try to detect multiarch triplet using dpkg-architecture
            std::process::Command::new("dpkg-architecture")
                .arg("-qDEB_HOST_MULTIARCH")
                .output()
                .ok()
                .and_then(|output| {
                    if output.status.success() {
                        String::from_utf8(output.stdout).ok()
                    } else {
                        None
                    }
                })
                .map(|triplet| format!("-I/usr/include/{}", triplet.trim()))
        } else {
            None
        };

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
