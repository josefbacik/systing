# gopclntab

Parse the Go runtime's function table (pclntab) and resolve program
counters to function names — including in fully stripped Go binaries.

Stripped Go binaries carry no ELF symbol table, but the Go runtime needs
its pclntab at run time for tracebacks and garbage collection, so `strip`
and `-ldflags="-s -w"` always leave the `.gopclntab` section behind.
Symbolizers that only read `.symtab`/`.dynsym` render such binaries as
hex; the pclntab has the real answer. This crate reads it.

Built for and used by [systing](https://github.com/josefbacik/systing)'s
continuous profiler, where it names frames from stripped Go infrastructure
binaries (kubelet, etcd, kube-state-metrics and the like) that would
otherwise be unreadable.

## Scope

- **Name-only resolution today**: pc → function name, entry address, and
  size. The pclntab also encodes source locations and inline trees; those
  are on the roadmap, not implemented.
- **Layouts**: Go 1.16/1.17 and Go 1.18+ (through current), little-endian.
  Go ≤ 1.15 tables and big-endian are rejected as unsupported.
- **One dependency**: the [`object`](https://crates.io/crates/object) crate (read core + ELF format only) for ELF section access.
- **Untrusted input is the design point**: every offset is bounds-checked;
  malformed tables produce errors or lookup misses, never panics. The test
  suite includes truncation sweeps and corrupted-field cases, and the
  parser is validated against binaries produced by the real Go toolchain.

## Usage

```rust,no_run
// From an ELF on disk (bounded reads: headers + the table itself,
// never the whole binary):
let elf = gopclntab::ElfPclntab::from_path("/usr/bin/some-go-binary")?
    .expect("not a Go binary");

// Policy is yours: `has_symtab` reports whether the binary also has a
// symbol table (profilers usually prefer symtab+DWARF when present).
if !elf.has_symtab {
    if let Some(func) = elf.table.find_func(0x4a6e40) {
        println!("{} ({:#x}, {} bytes)", func.name, func.entry, func.size);
    }
}
# Ok::<(), gopclntab::Error>(())
```

`GoPclntab::parse` accepts raw section bytes directly if you already have
them, and `ElfPclntab::from_bytes` works on in-memory ELF images.

## License

MIT.
