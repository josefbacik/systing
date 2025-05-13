use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use libbpf_cargo::SkeletonBuilder;

const SRC: [&str; 1] = ["src/bpf/systing_system.bpf.c"];

fn generate_bindings(out_dir: &PathBuf) {
    use std::path::PathBuf;

    use bindgen::builder;
    use pkg_config;

    pkg_config::probe_library("fmt").unwrap_or_else(|_| panic!("Failed to find fmt library"));
    pkg_config::probe_library("re2").unwrap_or_else(|_| panic!("Failed to find re2 library"));
    pkg_config::probe_library("libcap").unwrap_or_else(|_| panic!("Failed to find libcap library"));

    println!("cargo:rerun-if-changed=strobelight-libs/strobelight/bpf_lib");
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
        .env("INSTALL_DIR", &out_dir)
        .env("VMLINUX_INCLUDE", &vmlinux_include_arg)
        .arg("-C")
        .arg("strobelight-libs/strobelight/bpf_lib/python")
        .arg("install")
        .status()
        .expect("Failed to run make");

    assert!(status.success(), "Make command failed");

    let pystacks_header: PathBuf = out_dir.join("strobelight/bpf_lib/python/pystacks/pystacks.h");
    let bindings = builder()
        .header(pystacks_header.display().to_string())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .clang_args([
            format!("-I{}", out_dir.display()),
            vmlinux_include_arg.to_string(),
            "-x".to_string(),
            "c++".to_string(),
        ])
        .allowlist_function("pystacks_.*")
        .generate()
        .expect("Unable to generate bindings");

    let bindings_path = PathBuf::from("src/pystacks_bindings.rs");
    bindings
        .write_to_file(&bindings_path)
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
        let obj_path = out_dir.join(format!("{}_tmp.bpf.o", prefix));

        SkeletonBuilder::new()
            .source(src)
            .clang_args([
                OsStr::new(&bpf_include_arg),
                OsStr::new(&include_arg),
                OsStr::new("-D__x86_64__"),
            ])
            .obj(obj_path.to_str().unwrap())
            .build()
            .expect("Failed to build BPF skeleton");

        println!("cargo:rerun-if-changed={}", src);
    }

    let obj_path = out_dir.join("systing_system.bpf.o");
    let bpftool_output = std::process::Command::new("bpftool")
        .args([
            "gen",
            "object",
            obj_path.to_str().unwrap(),
            out_dir.join("pystacks.bpf.o").to_str().unwrap(),
            out_dir.join("systing_system_tmp.bpf.o").to_str().unwrap(),
        ])
        .output()
        .expect("Failed to link bpf objexts via bpftool");

    let bpft_stdout = String::from_utf8(bpftool_output.stdout).unwrap();
    let bpft_stderr = String::from_utf8(bpftool_output.stderr).unwrap();
    println!("{}", bpft_stdout);
    println!("{}", bpft_stderr);

    let skel_path = out_dir.join("systing_system.skel.rs");
    SkeletonBuilder::new()
        .obj(obj_path)
        .generate(&skel_path)
        .expect("Failed to build BPF skeleton");
}
