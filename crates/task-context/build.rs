// The library is one C file (see src/task_context.c for why it is C); this
// compiles it into a static archive the Rust binding links.
fn main() {
    println!("cargo:rerun-if-changed=src/task_context.c");
    println!("cargo:rerun-if-changed=include/task_context.h");
    cc::Build::new()
        .file("src/task_context.c")
        .include("include")
        .flag_if_supported("-pthread")
        .compile("task_context_c");
}
