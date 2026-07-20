//! Bounded rendering of pathological symbol names.
//!
//! Demangled Rust and C++ names embed the full monomorphized argument
//! list: deeply nested iterator adapters and expression templates
//! legitimately demangle to multi-kilobyte strings (observed up to ~28 KiB
//! for a single instantiation). Stacks are materialized as arrays of frame
//! strings, so one hot kilobyte-scale name repeated across millions of
//! recorded frames comes to dominate recorder memory and the size of
//! everything downstream — while carrying no more grouping identity than
//! its own first and last path segments.
//!
//! [`shorten_name`] bounds that cost while keeping the parts a reader or a
//! grouping query actually uses. Names at most [`ELIDE_GATE`] bytes pass
//! through byte-verbatim. Longer names have their balanced `<…>` and `(…)`
//! argument groups collapsed — `a::b<X<Y>, Z>::c(P)` becomes
//! `a::b<...>::c(...)` — preserving both the path head and the trailing
//! function segment. A name whose leading character opens a `<` group is
//! Rust's qualified-self syntax (`<Type as Trait>::method`); that group is
//! the identity being named, so it stays open and its child groups
//! collapse instead. Only if a name still exceeds `SHORTENED_MAX` after
//! elision — or its brackets do not balance — does it fall back to a
//! middle cut that keeps the head and tail with an 8-hex hash of the full
//! original name spliced in for grouping identity.
//!
//! Properties relied on downstream:
//! - deterministic and process-independent: the same full name always
//!   shortens to the same string (the fallback hash is FNV-1a, not a
//!   seeded hasher);
//! - prefix-preserving: bytes before the first collapsed group are
//!   verbatim, so prefix matches against untransformed heads keep working;
//! - instantiation-merging: monomorphizations of one source function
//!   (same path and function segment, different arguments) shorten to the
//!   same string, aggregating the family under its source function.

use std::borrow::Cow;

/// Names at most this many bytes are always rendered byte-verbatim.
pub const ELIDE_GATE: usize = 256;

/// Bound on the elided form. Elision keeps everything outside argument
/// groups, so a result exceeding this (kilobytes of path segments, or a
/// name whose brackets never balanced) falls back to [`middle_cut`].
const SHORTENED_MAX: usize = 1024;

/// Middle-cut geometry: bytes of head and tail kept around the hash.
const CUT_HEAD: usize = 192;
const CUT_TAIL: usize = 64;

/// Render `name` within a bounded size, preserving its head and function
/// segment. See the module docs for the exact scheme.
pub fn shorten_name(name: &str) -> Cow<'_, str> {
    if name.len() <= ELIDE_GATE {
        return Cow::Borrowed(name);
    }
    match elide_arg_groups(name) {
        Some(elided) if elided.len() <= SHORTENED_MAX => Cow::Owned(elided),
        Some(elided) => Cow::Owned(middle_cut(&elided, name)),
        None => Cow::Owned(middle_cut(name, name)),
    }
}

/// True if the byte before position `i` allows `<` to open a generic /
/// template argument group: an identifier character or `:` (turbofish).
/// Anything else — space, `<` (the second char of `operator<<`), an
/// operator symbol — leaves the `<` literal.
fn ident_or_colon_before(bytes: &[u8], i: usize) -> bool {
    i > 0 && matches!(bytes[i - 1], b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b':')
}

/// True if the bytes immediately before position `i` spell the standalone
/// keyword `operator`: C++ `operator<`, `operator<<`, `operator<=>` and
/// `operator()` must not be taken as group openers.
fn preceded_by_operator(bytes: &[u8], i: usize) -> bool {
    const TOKEN: &[u8] = b"operator";
    let Some(start) = i.checked_sub(TOKEN.len()) else {
        return false;
    };
    if &bytes[start..i] != TOKEN {
        return false;
    }
    // A standalone keyword, not the tail of an identifier like `my_operator`.
    start == 0
        || !matches!(
            bytes[start - 1],
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_'
        )
}

/// Collapse balanced `<…>` and `(…)` groups to `<...>` / `(...)`.
///
/// Returns `None` when the brackets do not balance (truncated or exotic
/// symtab strings) — the caller falls back to [`middle_cut`], so a scan
/// failure can never produce an unbounded or non-deterministic result.
fn elide_arg_groups(name: &str) -> Option<String> {
    let bytes = name.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(name.len().min(SHORTENED_MAX));
    // Expected closers for currently-open groups, innermost last.
    let mut open: Vec<u8> = Vec::new();
    // While `Some(d)`, bytes are dropped until `open` shrinks back to
    // length `d` (the collapsed group and everything nested in it).
    let mut suppress_at: Option<usize> = None;

    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b'<' | b'(' => {
                let opens = if c == b'<' {
                    (i == 0 || ident_or_colon_before(bytes, i)) && !preceded_by_operator(bytes, i)
                } else {
                    !preceded_by_operator(bytes, i)
                };
                if !opens {
                    if suppress_at.is_none() {
                        out.push(c);
                    }
                    i += 1;
                    continue;
                }
                let closer = if c == b'<' { b'>' } else { b')' };
                if suppress_at.is_none() {
                    if c == b'<' && i == 0 {
                        // Rust qualified-self (`<Type as Trait>::method`):
                        // the group IS the identity being named — keep it
                        // open; groups nested directly inside it collapse.
                        out.push(c);
                    } else {
                        // Top-level group (or first level inside the
                        // qualified-self group): collapse it.
                        suppress_at = Some(open.len());
                        out.push(c);
                        out.extend_from_slice(b"...");
                    }
                }
                open.push(closer);
            }
            b'>' | b')' => {
                // `->` inside function-pointer types must not close `<`.
                if c == b'>' && i > 0 && bytes[i - 1] == b'-' {
                    if suppress_at.is_none() {
                        out.push(c);
                    }
                    i += 1;
                    continue;
                }
                match open.last() {
                    Some(&expected) if expected == c => {
                        open.pop();
                        if suppress_at == Some(open.len()) {
                            suppress_at = None;
                            out.push(c);
                        } else if suppress_at.is_none() {
                            // Closing the qualified-self group itself.
                            out.push(c);
                        }
                    }
                    Some(_) => return None, // mismatched pair
                    None => {
                        // Stray closer at depth 0 (`operator>`, spaceship
                        // remnants): literal.
                        out.push(c);
                    }
                }
            }
            _ => {
                if suppress_at.is_none() {
                    out.push(c);
                }
            }
        }
        i += 1;
    }
    if !open.is_empty() {
        return None;
    }
    Some(String::from_utf8(out).expect("elided output is rebuilt from valid UTF-8 slices"))
}

/// Deterministic fallback for names elision cannot bound: keep the head
/// and tail, splice in an 8-hex FNV-1a hash of the FULL original name so
/// distinct originals stay distinct.
fn middle_cut(s: &str, full_original: &str) -> String {
    let marker = format!("...#{:08x}...", stable_hash32(full_original));
    if s.len() <= CUT_HEAD + CUT_TAIL + marker.len() {
        return s.to_string();
    }
    let mut head_end = CUT_HEAD;
    while !s.is_char_boundary(head_end) {
        head_end -= 1;
    }
    let mut tail_start = s.len() - CUT_TAIL;
    while !s.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    format!("{}{}{}", &s[..head_end], marker, &s[tail_start..])
}

/// FNV-1a, folded to 32 bits. Chosen over `DefaultHasher` because the
/// result must be identical across processes and hosts: the shortened
/// spelling is a grouping key downstream.
fn stable_hash32(s: &str) -> u32 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in s.as_bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (h ^ (h >> 32)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A generic argument blob big enough to push any name past the gate.
    fn big_args() -> String {
        let mut s = String::from("alloc::vec::Vec<u64>");
        while s.len() < 400 {
            s = format!("core::iter::adapters::map::Map<{s}, alloc::string::String>");
        }
        s
    }

    #[test]
    fn short_names_pass_verbatim() {
        for name in [
            "memcpy",
            "alloc::vec::Vec<u64>::push",
            "<core::option::Option<u32> as core::fmt::Debug>::fmt",
            "Eigen::TensorEvaluator<int>::evalProduct(long)",
            "unknown ([gvisor:runtime]) <0x7f00>",
        ] {
            assert!(name.len() <= ELIDE_GATE);
            let out = shorten_name(name);
            assert!(matches!(out, Cow::Borrowed(_)), "{name} was not borrowed");
            assert_eq!(out, name);
        }
    }

    #[test]
    fn gate_is_inclusive() {
        let at_gate = format!("f<{}>", "a".repeat(ELIDE_GATE - 3));
        assert_eq!(at_gate.len(), ELIDE_GATE);
        assert_eq!(shorten_name(&at_gate), at_gate);

        let over_gate = format!("f<{}>", "a".repeat(ELIDE_GATE - 2));
        assert_eq!(over_gate.len(), ELIDE_GATE + 1);
        assert_eq!(shorten_name(&over_gate), "f<...>");
    }

    #[test]
    fn turbofish_function_generics_collapse() {
        let name = format!("rayon_core::registry::in_worker::<{}>", big_args());
        assert_eq!(
            shorten_name(&name),
            "rayon_core::registry::in_worker::<...>"
        );
    }

    #[test]
    fn trailing_closure_segment_is_preserved() {
        let name = format!(
            "rayon_core::join::join_context::<{}>::{{closure#0}}",
            big_args()
        );
        assert_eq!(
            shorten_name(&name),
            "rayon_core::join::join_context::<...>::{closure#0}"
        );
    }

    #[test]
    fn qualified_self_keeps_type_and_trait_heads() {
        let name = format!(
            "<core::iter::adapters::map::Map<{}> as core::iter::traits::iterator::Iterator>::next",
            big_args()
        );
        assert_eq!(
            shorten_name(&name),
            "<core::iter::adapters::map::Map<...> as core::iter::traits::iterator::Iterator>::next"
        );
    }

    #[test]
    fn cpp_templates_and_params_collapse() {
        let name = format!(
            "void Eigen::TensorEvaluator<{}>::evalProductSequential({})",
            big_args(),
            big_args()
        );
        assert_eq!(
            shorten_name(&name),
            "void Eigen::TensorEvaluator<...>::evalProductSequential(...)"
        );
    }

    #[test]
    fn cpp_operators_stay_literal() {
        let name = format!("ns::Matrix<{}>::operator<<(std::ostream&, int)", big_args());
        assert_eq!(shorten_name(&name), "ns::Matrix<...>::operator<<(...)");

        let call = format!("ns::Functor<{}>::operator()(int, long)", big_args());
        assert_eq!(shorten_name(&call), "ns::Functor<...>::operator()(...)");
    }

    #[test]
    fn identifiers_ending_in_operator_still_open_groups() {
        let name = format!("ns::my_operator<{}>::run", big_args());
        assert_eq!(shorten_name(&name), "ns::my_operator<...>::run");
    }

    #[test]
    fn arrows_inside_generics_do_not_unbalance() {
        let name = format!(
            "ns::apply::<fn(alloc::vec::Vec<{}>) -> core::option::Option<u64>>::call",
            big_args()
        );
        assert_eq!(shorten_name(&name), "ns::apply::<...>::call");
    }

    #[test]
    fn comparison_lt_stays_literal() {
        // A `<` after a space (const-expression remnant) is not an opener;
        // brackets still balance around it.
        let name = format!("ns::check<{}>::assert_lt::{{shim: a < b}}", big_args());
        assert_eq!(
            shorten_name(&name),
            "ns::check<...>::assert_lt::{shim: a < b}"
        );
    }

    #[test]
    fn unbalanced_names_fall_back_to_middle_cut() {
        let name = format!("broken<{}", "x".repeat(600));
        let out = shorten_name(&name);
        assert!(out.len() < name.len());
        assert!(out.starts_with("broken<xxxx"), "head preserved: {out}");
        assert!(out.ends_with(&"x".repeat(CUT_TAIL)), "tail preserved");
        assert!(out.contains("...#"), "hash marker present: {out}");
        // Deterministic, and distinct originals stay distinct.
        assert_eq!(shorten_name(&name), out);
        let other = format!("broken<{}", "y".repeat(600));
        assert_ne!(shorten_name(&other), out);
    }

    #[test]
    fn bracket_free_monsters_fall_back_to_middle_cut() {
        let name = "very::long::path::".repeat(80);
        assert!(name.len() > SHORTENED_MAX);
        let out = shorten_name(&name);
        assert!(out.len() <= CUT_HEAD + CUT_TAIL + 16);
        assert!(out.starts_with("very::long::path::"));
        assert!(out.contains("...#"));
    }

    #[test]
    fn elided_but_still_long_names_fall_back_bounded() {
        // Groups collapse but kilobytes of bare path remain.
        let name = format!("{}<{}>::run", "seg::".repeat(300), big_args());
        let out = shorten_name(&name);
        assert!(
            out.len() <= CUT_HEAD + CUT_TAIL + 16,
            "bounded: {}",
            out.len()
        );
        assert!(out.starts_with("seg::seg::"));
        assert!(
            out.ends_with("::run"),
            "function tail survives the cut: {out}"
        );
    }

    #[test]
    fn monomorphizations_of_one_function_merge() {
        let a = format!("pool::execute::<{}>", big_args());
        let b = format!("pool::execute::<fn({}) -> u8>", big_args());
        assert_eq!(shorten_name(&a), shorten_name(&b));
        assert_eq!(shorten_name(&a), "pool::execute::<...>");
    }

    #[test]
    fn different_functions_never_merge() {
        let a = format!("pool::execute::<{}>", big_args());
        let b = format!("pool::execute_now::<{}>", big_args());
        assert_ne!(shorten_name(&a), shorten_name(&b));
    }

    #[test]
    fn mismatched_pairs_fall_back() {
        let name = format!("odd<{})::end", "q".repeat(500));
        let out = shorten_name(&name);
        assert!(out.contains("...#"), "mismatch routed to middle cut: {out}");
    }

    #[test]
    fn multibyte_input_cuts_on_char_boundaries() {
        // Unbalanced so the middle cut runs over multibyte content.
        let name = format!("bad<{}", "α".repeat(400));
        let out = shorten_name(&name);
        assert!(out.contains("...#"));
        // Would panic on a non-boundary slice; also must stay valid UTF-8.
        assert!(out.chars().count() > 0);
    }

    #[test]
    fn anonymous_namespace_prefix_collapses_but_stays_balanced() {
        let name = format!("(anonymous namespace)::detail::run<{}>", big_args());
        assert_eq!(shorten_name(&name), "(...)::detail::run<...>");
    }
}
