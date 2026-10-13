//! The stack every BPF program asks of the verifier, added up from the
//! compiled objects: the guard that a capture which loads today still loads on
//! the oldest kernel line the tracer runs on.
//!
//! The verifier refuses a program whose chain of bpf-to-bpf calls needs more
//! than 512 bytes of stack, all frames together. A frame is as deep as the
//! lowest stack slot its function touches, and where the compiler puts a slot
//! is not written in the source: a helper inlined into a function adds its
//! locals to that function's frame and can move the slots of code that has
//! nothing to do with it. So a change in one helper can make a program that
//! never calls it too deep to load, and the load test does not see it on the
//! kernels it runs on, because how a frame is counted depends on the kernel:
//!
//! - up to 6.8, every frame is rounded up to 32 bytes;
//! - from 6.9, to 16 bytes where the program is to be compiled;
//! - from 6.12, the slots that only save a register around a call the kernel
//!   inlines are not counted;
//! - from 6.13, where the architecture's compiler has it, a tracing program
//!   with a frame of 64 bytes or more is given a stack of its own, and the
//!   limit is then on each frame and no longer on their sum.
//!
//! So the same object is deeper on a 6.6 kernel than on a 6.12 one, and a
//! load test on the second says nothing of the first. This module reads the
//! frames and the calls from the object as the compiler left it and adds
//! every chain up by the oldest rule, with every instruction taken to be
//! live: an upper bound on what any kernel counts at any configuration (the
//! verifier counts a subprogram it pruned as one step, here it counts in
//! full). A chain within the limit here loads, as far as its stack goes,
//! wherever the object is loaded; one past it is refused at some
//! configuration on a kernel that counts by the oldest rule, whatever the
//! load test says on a newer one.
//!
//! What it does not know: a slot reached only through a pointer that was
//! computed in one basic block and offset in another (the compiler forms a
//! stack address with two adjacent instructions, which is what is read here),
//! and anything a kernel adds to a frame after the check.

use std::collections::BTreeMap;

use object::elf::{SHF_EXECINSTR, STT_FUNC, STT_SECTION};
use object::{Object, ObjectSection, ObjectSymbol, RelocationTarget, SectionFlags, SymbolFlags};

/// The verifier's limit on a chain's frames, all together (`MAX_BPF_STACK`).
pub const MAX_STACK_BYTES: u32 = 512;
/// The verifier's limit on the frames in a chain (`MAX_CALL_FRAMES`).
pub const MAX_CALL_FRAMES: usize = 8;
/// What a frame is rounded up to under the oldest rule, and what a function
/// that touches no stack at all still costs.
pub const FRAME_STEP: u32 = 32;

const INSN_SIZE: usize = 8;
const FRAME_POINTER: u8 = 10;

const CLASS_LDX: u8 = 1;
const CLASS_ST: u8 = 2;
const CLASS_STX: u8 = 3;
const CLASS_ALU64: u8 = 7;

const OP_LD_IMM64: u8 = 0x18;
const OP_MOV64_REG: u8 = 0xbf;
const OP_ADD64_IMM: u8 = 0x07;
const OP_CALL: u8 = 0x85;

/// `src_reg` of a call to another BPF function.
const PSEUDO_CALL: u8 = 1;

/// One function of an object: an entry program or a subprogram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    /// A program the kernel attaches (it sits in a section of its own), as
    /// against a subprogram, which sits in `.text`.
    pub entry: bool,
    /// The lowest stack slot the function touches, in bytes below the frame
    /// pointer.
    pub frame: u32,
    /// The functions it calls, and the callbacks it hands to a helper.
    pub callees: Vec<String>,
}

/// The deepest chain that starts at one function the verifier starts at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    /// The function the chain starts at.
    pub entry: String,
    /// The frames of `path`, each rounded up, added.
    pub bytes: u32,
    /// The functions of the chain, the entry first, each with its own frame
    /// as the compiler left it.
    pub path: Vec<(String, u32)>,
    /// The most frames any chain from this entry has, which need not be the
    /// chain that costs the most bytes.
    pub frames: usize,
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:4} bytes in {} frames: ", self.bytes, self.path.len())?;
        for (i, (name, frame)) in self.path.iter().enumerate() {
            if i > 0 {
                write!(f, " > ")?;
            }
            write!(f, "{name}({frame})")?;
        }
        Ok(())
    }
}

/// What one frame costs under the oldest rule.
pub fn charged(frame: u32) -> u32 {
    frame.max(1).div_ceil(FRAME_STEP) * FRAME_STEP
}

struct Insn {
    opcode: u8,
    dst: u8,
    src: u8,
    off: i16,
    imm: i32,
}

fn insn_at(code: &[u8], at: usize) -> Insn {
    let b = &code[at..at + INSN_SIZE];
    Insn {
        opcode: b[0],
        dst: b[1] & 0x0f,
        src: b[1] >> 4,
        off: i16::from_le_bytes([b[2], b[3]]),
        imm: i32::from_le_bytes([b[4], b[5], b[6], b[7]]),
    }
}

fn depth(offset: i64) -> u32 {
    if offset < 0 {
        u32::try_from(-offset).unwrap_or(u32::MAX)
    } else {
        0
    }
}

/// The frame of one function, from its instructions: the lowest slot a load
/// or a store names by the frame pointer, or a stack address formed for a
/// helper to fill (`rX = r10` and, next, `rX += -N`) points at.
pub fn frame_of(code: &[u8]) -> u32 {
    let mut frame = 0u32;
    // The register that was given the frame pointer by the instruction before.
    let mut copy: Option<u8> = None;
    let mut at = 0;
    while at + INSN_SIZE <= code.len() {
        let insn = insn_at(code, at);
        let class = insn.opcode & 0x07;
        let was = copy.take();
        match class {
            CLASS_LDX if insn.src == FRAME_POINTER => {
                frame = frame.max(depth(insn.off.into()));
            }
            CLASS_ST | CLASS_STX if insn.dst == FRAME_POINTER => {
                frame = frame.max(depth(insn.off.into()));
            }
            CLASS_ALU64 => {
                if insn.opcode == OP_MOV64_REG && insn.src == FRAME_POINTER && insn.off == 0 {
                    copy = Some(insn.dst);
                } else if insn.opcode == OP_ADD64_IMM && was == Some(insn.dst) {
                    frame = frame.max(depth(insn.imm.into()));
                }
            }
            _ => {}
        }
        at += if insn.opcode == OP_LD_IMM64 {
            2 * INSN_SIZE
        } else {
            INSN_SIZE
        };
    }
    frame
}

/// Every function of a compiled BPF object, by name, with its frame and the
/// functions it calls. An error names what could not be read; a call whose
/// target cannot be found is one, so that a chain is never short of a frame
/// without the guard saying so.
pub fn functions(object: &[u8]) -> Result<BTreeMap<String, Function>, String> {
    let file = object::File::parse(object).map_err(|e| format!("not an object file: {e}"))?;

    // Where every function starts: (section, offset) -> name.
    let mut starts: BTreeMap<(usize, u64), String> = BTreeMap::new();
    // What a relocation can name: a function, or a section to count into.
    let mut targets: BTreeMap<usize, Target> = BTreeMap::new();
    let mut sized: Vec<(String, usize, u64, u64)> = Vec::new();
    for symbol in file.symbols() {
        let SymbolFlags::Elf { st_info, .. } = symbol.flags() else {
            continue;
        };
        let Some(section) = symbol.section_index() else {
            // Not in this object: a function of the kernel's.
            targets.insert(symbol.index().0, Target::Kernel);
            continue;
        };
        match st_info & 0x0f {
            STT_FUNC => {
                let name = symbol
                    .name()
                    .map_err(|e| format!("a function's name: {e}"))?
                    .to_string();
                starts.insert((section.0, symbol.address()), name.clone());
                targets.insert(symbol.index().0, Target::Function(name.clone()));
                sized.push((name, section.0, symbol.address(), symbol.size()));
            }
            STT_SECTION => {
                targets.insert(symbol.index().0, Target::Section(section.0));
            }
            _ => {}
        }
    }

    let mut found = BTreeMap::new();
    for section in file.sections() {
        let SectionFlags::Elf { sh_flags } = section.flags() else {
            continue;
        };
        if sh_flags & u64::from(SHF_EXECINSTR) == 0 {
            continue;
        }
        let name = section
            .name()
            .map_err(|e| format!("a section's name: {e}"))?;
        let code = section
            .data()
            .map_err(|e| format!("the instructions of {name}: {e}"))?;
        let relocations: BTreeMap<u64, usize> = section
            .relocations()
            .filter_map(|(at, r)| match r.target() {
                RelocationTarget::Symbol(s) => Some((at, s.0)),
                _ => None,
            })
            .collect();
        let here = section.index().0;

        for (function, _, start, size) in sized.iter().filter(|(_, s, _, _)| *s == here) {
            let (start, end) = (*start as usize, (*start + *size) as usize);
            let body = code
                .get(start..end)
                .ok_or_else(|| format!("{function} runs past the end of {name}"))?;
            let mut callees = Vec::new();
            let mut at = 0;
            while at + INSN_SIZE <= body.len() {
                let insn = insn_at(body, at);
                let offset = (start + at) as u64;
                let relocated = relocations.get(&offset).and_then(|s| targets.get(s));
                let call = insn.opcode == OP_CALL && insn.src == PSEUDO_CALL;
                let reference = insn.opcode == OP_LD_IMM64;
                let callee = match (call, reference, relocated) {
                    // A function the linker is to find, by name.
                    (true, _, Some(Target::Function(callee)))
                    | (_, true, Some(Target::Function(callee))) => Some(callee.clone()),
                    // A function of this file: so many instructions into
                    // the section the relocation names...
                    (true, _, Some(Target::Section(index))) => Some(
                        function_at(&starts, *index, pc_relative(0, insn.imm)).ok_or_else(
                            || format!("{function} calls nothing known at {offset:#x}"),
                        )?,
                    ),
                    // ...or, with no relocation, from the call itself.
                    (true, _, None) if !relocations.contains_key(&offset) => Some(
                        function_at(&starts, here, pc_relative(offset, insn.imm)).ok_or_else(
                            || format!("{function} calls nothing known at {offset:#x}"),
                        )?,
                    ),
                    // A callback: the address of a function, in bytes into
                    // its section. The address of anything else in a
                    // section of instructions is not one.
                    (_, true, Some(Target::Section(index))) => u64::try_from(insn.imm)
                        .ok()
                        .and_then(|into| function_at(&starts, *index, Some(into))),
                    _ => None,
                };
                if let Some(callee) = callee {
                    if !callees.contains(&callee) {
                        callees.push(callee);
                    }
                }
                at += if reference { 2 * INSN_SIZE } else { INSN_SIZE };
            }
            found.insert(
                function.clone(),
                Function {
                    entry: name != ".text",
                    frame: frame_of(body),
                    callees,
                },
            );
        }
    }
    Ok(found)
}

enum Target {
    Function(String),
    Section(usize),
    /// A function the kernel exports to BPF programs: it has no frame here.
    Kernel,
}

/// Where a call lands: the instruction after it, and `imm` more.
fn pc_relative(from: u64, imm: i32) -> Option<u64> {
    let slots = i64::try_from(from / INSN_SIZE as u64).ok()? + i64::from(imm) + 1;
    u64::try_from(slots).ok()?.checked_mul(INSN_SIZE as u64)
}

fn function_at(
    starts: &BTreeMap<(usize, u64), String>,
    section: usize,
    offset: Option<u64>,
) -> Option<String> {
    starts.get(&(section, offset?)).cloned()
}

/// The deepest chain from every function the verifier starts at, the
/// costliest first: every entry program, and every function nothing calls (a
/// global function is verified by itself, called or not). An error names a
/// function that is called and not there, or one that reaches itself.
pub fn deepest_chains(functions: &BTreeMap<String, Function>) -> Result<Vec<Chain>, String> {
    /// The deepest chain from `name` down, as if it were an entry.
    fn below(
        functions: &BTreeMap<String, Function>,
        name: &str,
        above: &mut Vec<String>,
    ) -> Result<Chain, String> {
        let function = functions
            .get(name)
            .ok_or_else(|| format!("{name} is called and is not in the object"))?;
        if above.iter().any(|n| n == name) {
            return Err(format!(
                "{name} reaches itself through {}",
                above.join(" > ")
            ));
        }
        above.push(name.to_string());
        let mut chain = Chain {
            entry: name.to_string(),
            bytes: 0,
            path: Vec::new(),
            frames: 0,
        };
        for callee in &function.callees {
            let deeper = below(functions, callee, above)?;
            chain.frames = chain.frames.max(deeper.frames);
            if deeper.bytes > chain.bytes {
                chain.bytes = deeper.bytes;
                chain.path = deeper.path;
            }
        }
        above.pop();
        chain.path.insert(0, (name.to_string(), function.frame));
        chain.bytes += charged(function.frame);
        chain.frames += 1;
        Ok(chain)
    }

    let mut chains = Vec::new();
    for (name, function) in functions {
        let called = functions.values().any(|f| f.callees.contains(name));
        if function.entry || !called {
            chains.push(below(functions, name, &mut Vec::new())?);
        }
    }
    chains.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.entry.cmp(&b.entry)));
    Ok(chains)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; INSN_SIZE] {
        let mut b = [0u8; INSN_SIZE];
        b[0] = opcode;
        b[1] = (src << 4) | dst;
        b[2..4].copy_from_slice(&off.to_le_bytes());
        b[4..8].copy_from_slice(&imm.to_le_bytes());
        b
    }

    fn code(insns: &[[u8; INSN_SIZE]]) -> Vec<u8> {
        insns.concat()
    }

    const STX_DW: u8 = 0x7b;
    const LDX_W: u8 = 0x61;
    const ST_B: u8 = 0x72;
    const MOV64_IMM: u8 = 0xb7;
    const EXIT: u8 = 0x95;

    #[test]
    fn a_frame_is_as_deep_as_the_lowest_slot_named() {
        let body = code(&[
            insn(STX_DW, FRAME_POINTER, 1, -8, 0),
            insn(LDX_W, 2, FRAME_POINTER, -168, 0),
            insn(ST_B, FRAME_POINTER, 0, -24, 7),
            insn(EXIT, 0, 0, 0, 0),
        ]);
        assert_eq!(frame_of(&body), 168);
    }

    #[test]
    fn a_stack_address_made_for_a_helper_counts() {
        let body = code(&[
            insn(STX_DW, FRAME_POINTER, 1, -8, 0),
            insn(OP_MOV64_REG, 3, FRAME_POINTER, 0, 0),
            insn(OP_ADD64_IMM, 3, 0, 0, -120),
            insn(OP_CALL, 0, 0, 0, 112),
            insn(EXIT, 0, 0, 0, 0),
        ]);
        assert_eq!(frame_of(&body), 120);
    }

    #[test]
    fn what_is_not_the_stack_does_not_count() {
        let body = code(&[
            // A load and a store through another register, however far below it.
            insn(LDX_W, 2, 1, -400, 0),
            insn(STX_DW, 1, 2, -400, 0),
            // An addition to a register that is not a copy of the frame
            // pointer, and one to a copy that was since overwritten.
            insn(OP_ADD64_IMM, 4, 0, 0, -300),
            insn(OP_MOV64_REG, 3, FRAME_POINTER, 0, 0),
            insn(MOV64_IMM, 3, 0, 0, 0),
            insn(OP_ADD64_IMM, 3, 0, 0, -200),
            // The second half of a 16-byte instruction is data, whatever it
            // looks like: here, a store 96 bytes below the frame pointer.
            insn(OP_LD_IMM64, 1, 0, 0, 0),
            insn(STX_DW, FRAME_POINTER, 1, -96, 0),
            // A slot above the frame pointer is not this frame's.
            insn(STX_DW, FRAME_POINTER, 1, 16, 0),
            insn(STX_DW, FRAME_POINTER, 1, -16, 0),
            insn(EXIT, 0, 0, 0, 0),
        ]);
        assert_eq!(frame_of(&body), 16);
    }

    #[test]
    fn a_frame_is_charged_in_whole_steps_and_never_nothing() {
        assert_eq!(charged(0), 32);
        assert_eq!(charged(1), 32);
        assert_eq!(charged(32), 32);
        assert_eq!(charged(33), 64);
        assert_eq!(charged(144), 160);
        assert_eq!(charged(160), 160);
        assert_eq!(charged(168), 192);
    }

    fn function(entry: bool, frame: u32, callees: &[&str]) -> Function {
        Function {
            entry,
            frame,
            callees: callees.iter().map(|c| c.to_string()).collect(),
        }
    }

    #[test]
    fn the_deepest_chain_is_the_costliest_and_the_frames_the_most() {
        let functions = BTreeMap::from([
            ("prog".to_string(), function(true, 0, &["wide", "long"])),
            ("wide".to_string(), function(false, 300, &[])),
            ("long".to_string(), function(false, 8, &["leaf"])),
            ("leaf".to_string(), function(false, 40, &[])),
            ("alone".to_string(), function(true, 100, &[])),
            ("unused".to_string(), function(false, 500, &[])),
        ]);
        let chains = deepest_chains(&functions).unwrap();
        assert_eq!(
            chains,
            vec![
                // A function nothing calls is verified by itself.
                Chain {
                    entry: "unused".to_string(),
                    bytes: 512,
                    path: vec![("unused".to_string(), 500)],
                    frames: 1,
                },
                Chain {
                    entry: "prog".to_string(),
                    bytes: 32 + 320,
                    path: vec![("prog".to_string(), 0), ("wide".to_string(), 300)],
                    frames: 3,
                },
                Chain {
                    entry: "alone".to_string(),
                    bytes: 128,
                    path: vec![("alone".to_string(), 100)],
                    frames: 1,
                },
            ]
        );
    }

    #[test]
    fn a_chain_that_cannot_be_followed_is_an_error() {
        let missing = BTreeMap::from([("prog".to_string(), function(true, 0, &["gone"]))]);
        assert!(deepest_chains(&missing).unwrap_err().contains("gone"));

        let round = BTreeMap::from([
            ("prog".to_string(), function(true, 0, &["a"])),
            ("a".to_string(), function(false, 0, &["b"])),
            ("b".to_string(), function(false, 0, &["a"])),
        ]);
        assert!(deepest_chains(&round)
            .unwrap_err()
            .contains("reaches itself"));
    }

    /// The objects this build embeds, as the build script left them.
    const OBJECTS: &[(&str, &[u8])] = &[
        (
            "systing_system.bpf.o",
            include_bytes!(concat!(env!("OUT_DIR"), "/systing_system.bpf.o")),
        ),
        (
            "task_stacks.bpf.o",
            include_bytes!(concat!(env!("OUT_DIR"), "/task_stacks.bpf.o")),
        ),
        (
            "python_function_trace.bpf.o",
            include_bytes!(concat!(env!("OUT_DIR"), "/python_function_trace.bpf.o")),
        ),
    ];

    fn chains_of(object: &str) -> (BTreeMap<String, Function>, Vec<Chain>) {
        let (_, bytes) = OBJECTS
            .iter()
            .find(|(name, _)| *name == object)
            .expect("an embedded object");
        let functions = functions(bytes).unwrap_or_else(|e| panic!("{object}: {e}"));
        let chains = deepest_chains(&functions).unwrap_or_else(|e| panic!("{object}: {e}"));
        (functions, chains)
    }

    /// The gate. Every chain of every program, added up by the rule of the
    /// oldest kernels with every instruction live, fits the verifier's stack;
    /// and no chain is longer than the verifier follows.
    #[test]
    fn every_chain_fits_the_stack_of_the_oldest_kernels() {
        let mut findings = Vec::new();
        for (object, _) in OBJECTS {
            let (_, chains) = chains_of(object);
            eprintln!("{object}: the deepest of {} chains", chains.len());
            for chain in chains.iter().take(8) {
                eprintln!("  {chain}");
            }
            for chain in &chains {
                if chain.bytes > MAX_STACK_BYTES {
                    findings.push(format!(
                        "{object}: {} needs {} bytes of stack where frames are rounded up to \
                         {FRAME_STEP}, the limit is {MAX_STACK_BYTES}: {chain}",
                        chain.entry, chain.bytes
                    ));
                }
                if chain.frames > MAX_CALL_FRAMES {
                    findings.push(format!(
                        "{object}: {} has a chain of {} frames, the limit is {MAX_CALL_FRAMES}",
                        chain.entry, chain.frames
                    ));
                }
            }
        }
        assert!(
            findings.is_empty(),
            "a program is too deep for a kernel that rounds every frame up to {FRAME_STEP} bytes \
             (Linux 6.8 and older), at the configuration that makes all of its code live. Find \
             the frame that grew (`llvm-objdump -d` of the object: a function's frame is the \
             lowest `r10` offset in it) and take what was added out of it; a helper that is \
             inlined puts its locals in its caller's frame.\n{}",
            findings.join("\n")
        );
    }

    /// The read itself: a guard that found no calls would pass whatever the
    /// object held. The main object's programs do call, the path that emits a
    /// running stack is a subprogram many of them share, and the Python walker
    /// below it makes the longest chains there are.
    #[test]
    fn the_calls_of_the_main_object_are_found() {
        let (functions, chains) = chains_of("systing_system.bpf.o");
        let entries = functions.values().filter(|f| f.entry).count();
        assert!(entries > 50, "only {entries} programs were found");
        assert!(
            functions.values().any(|f| !f.entry && f.frame > 0),
            "no subprogram with a frame was found"
        );
        let deepest = chains.iter().map(|c| c.frames).max().unwrap_or(0);
        assert!(
            deepest >= 6,
            "the longest chain found has {deepest} frames: the calls between the linked files \
             were not followed"
        );
    }

    /// The reader of a thread's task context is a function of its own: its
    /// locals are in no frame of a capture that runs without the feature.
    /// Inlined into the path that emits a running stack, they moved that
    /// path's frame from 144 to 168 bytes, one 32-byte step, and a capture
    /// with a trace event stopped loading on Linux 6.6.
    #[test]
    fn the_task_context_reader_is_in_no_frame_but_its_own() {
        let (functions, _) = chains_of("systing_system.bpf.o");
        let reader = functions.get("task_context_read_current").expect(
            "task_context_read_current is not a function of the object: it was inlined into \
             its caller, whose frame now holds its locals",
        );
        assert!(!reader.entry);
        assert!(
            functions
                .values()
                .any(|f| f.callees.iter().any(|c| c == "task_context_read_current")),
            "nothing calls the reader"
        );
    }

    /// The same for the reader of a Go program's goroutine.
    #[test]
    fn the_go_context_reader_is_in_no_frame_but_its_own() {
        let (functions, _) = chains_of("systing_system.bpf.o");
        let reader = functions.get("go_context_read_current").expect(
            "go_context_read_current is not a function of the object: it was inlined into \
             its caller, whose frame now holds its locals",
        );
        assert!(!reader.entry);
        assert!(
            functions
                .values()
                .any(|f| f.callees.iter().any(|c| c == "go_context_read_current")),
            "nothing calls the reader"
        );
    }
}
