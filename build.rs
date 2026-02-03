use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use libbpf_cargo::SkeletonBuilder;

const SRC: [&str; 1] = ["src/bpf/systing_system.bpf.c"];

#[cfg(not(feature = "pystacks"))]
fn generate_bindings(_: &PathBuf) {}

#[cfg(feature = "pystacks")]
fn generate_bindings(out_dir: &PathBuf) {
    use std::path::PathBuf;

    use bindgen::builder;
    use pkg_config;

    // Check for required libraries and collect missing ones
    let mut missing_libs = Vec::new();

    if pkg_config::probe_library("fmt").is_err() {
        missing_libs.push("libfmt-dev");
    }
    if pkg_config::probe_library("re2").is_err() {
        missing_libs.push("libre2-dev");
    }
    if pkg_config::probe_library("libcap").is_err() {
        missing_libs.push("libcap-dev");
    }

    if !missing_libs.is_empty() {
        eprintln!("\n===============================================");
        eprintln!("ERROR: Missing required libraries for 'pystacks' feature");
        eprintln!("===============================================\n");
        eprintln!("The following development libraries are required but not found:");
        for lib in &missing_libs {
            eprintln!("  - {lib}");
        }
        eprintln!("\nTo install these libraries on Ubuntu/Debian, run:");
        eprintln!("  sudo apt-get install {}\n", missing_libs.join(" "));
        eprintln!("On Fedora/RHEL, run:");
        eprintln!("  sudo dnf install fmt-devel re2-devel libcap-devel\n");
        eprintln!("On Arch Linux, run:");
        eprintln!("  sudo pacman -S fmt re2 libcap\n");
        eprintln!("===============================================\n");
        panic!("Missing required libraries for pystacks feature. See error message above for installation instructions.");
    }

    // Check if strobelight-libs submodule is initialized
    let submodule_makefile = Path::new("strobelight-libs/strobelight/bpf_lib/python/Makefile");
    if !submodule_makefile.exists() {
        eprintln!("\n===============================================");
        eprintln!("ERROR: strobelight-libs submodule is not initialized");
        eprintln!("===============================================\n");
        eprintln!("The 'pystacks' feature requires the strobelight-libs submodule.");
        eprintln!("Please initialize it by running:\n");
        eprintln!("  git submodule update --init --recursive\n");
        eprintln!("===============================================\n");
        panic!("strobelight-libs submodule not initialized. See error message above.");
    }

    // Track strobelight-libs source files so submodule updates trigger rebuilds
    println!("cargo:rerun-if-changed=strobelight-libs/strobelight/bpf_lib/python/Makefile");
    println!(
        "cargo:rerun-if-changed=strobelight-libs/strobelight/bpf_lib/python/discovery/Makefile"
    );

    let strobelight_dirs = [
        "strobelight-libs/strobelight/bpf_lib/python/discovery",
        "strobelight-libs/strobelight/bpf_lib/python/pystacks",
        "strobelight-libs/strobelight/bpf_lib/python/include",
        "strobelight-libs/strobelight/bpf_lib/python/src",
        "strobelight-libs/strobelight/bpf_lib/util",
        "strobelight-libs/strobelight/bpf_lib/util/pid_info",
        "strobelight-libs/strobelight/bpf_lib/common",
        "strobelight-libs/strobelight/bpf_lib/include",
    ];

    for dir in strobelight_dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str());
            if matches!(ext, Some("cpp" | "c" | "h")) {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo::rustc-link-lib=static=pystacks");
    println!("cargo::rustc-link-lib=static=python_discovery");
    println!("cargo::rustc-link-lib=static=strobelight_util");
    println!("cargo:rustc-link-lib=dylib=stdc++");
    println!("cargo:rustc-link-lib=dylib=fmt");
    println!("cargo:rustc-link-lib=dylib=re2");
    println!("cargo:rustc-link-lib=dylib=elf");
    println!("cargo:rustc-link-lib=dylib=cap");

    let vmlinux_include_arg = format!(
        "-I{}",
        Path::new("src/bpf")
            .canonicalize()
            .expect("src directory exists")
            .display()
    );
    let status = std::process::Command::new("make")
        .env("INSTALL_DIR", out_dir)
        .env("VMLINUX_INCLUDE", &vmlinux_include_arg)
        .arg("-C")
        .arg("strobelight-libs/strobelight/bpf_lib/python")
        .arg("install")
        .status()
        .expect("Failed to run make");

    assert!(status.success(), "Make command failed");

    let pystacks_header: PathBuf = out_dir.join("strobelight/bpf_lib/python/pystacks/pystacks.h");
    let logging_header: PathBuf =
        PathBuf::from("strobelight-libs/strobelight/bpf_lib/include/logging.h");
    let bindings = builder()
        .header(pystacks_header.display().to_string())
        .header(logging_header.display().to_string())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .clang_args([
            format!("-I{}", out_dir.display()),
            vmlinux_include_arg.to_string(),
            "-x".to_string(),
            "c++".to_string(),
            "-std=c++20".to_string(),
        ])
        .allowlist_function("pystacks_.*")
        .allowlist_function("strobelight_lib_set_print")
        .allowlist_type("strobelight_lib_print_level")
        .allowlist_type("strobelight_lib_print_fn_t")
        .raw_line("#![allow(non_upper_case_globals)]")
        .generate()
        .expect("Unable to generate bindings");

    let bindings_path = PathBuf::from("src/pystacks/bindings.rs");
    bindings
        .write_to_file(bindings_path)
        .expect("Couldn't write bindings!");
}

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

    generate_bindings(&out_dir);

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
        clang_args.push(OsStr::new("-DSYSTING_PYSTACKS"));

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
