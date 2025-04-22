use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use libbpf_cargo::SkeletonBuilder;

const SRC: [&'static str; 1] = [
    "src/bpf/systing_system.bpf.c",
];

fn main() {
    let out_dir =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));

    let vmlinux_path = out_dir.join("vmlinux.h");

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

    let include_arg = format!("-I{}", out_dir.display());
    for src in SRC {
        let srcpath = Path::new(src);
        let fname = srcpath.file_name().unwrap().to_str().unwrap();
        let prefix = match fname.split_once(".bpf.c") {
            Some((prefix, _)) => prefix,
            None => fname,
        };
        let skel_path = out_dir.join(format!("{}.skel.rs", prefix));
        SkeletonBuilder::new()
            .source(src)
            .clang_args([OsStr::new(&include_arg)])
            .build_and_generate(&skel_path)
            .expect("Failed to build BPF skeleton");
        println!("cargo:rerun-if-changed={}", src);
    }
}
