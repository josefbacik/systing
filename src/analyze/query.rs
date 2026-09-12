/// Convert a DuckDB value to a properly typed JSON value.
pub(super) fn duckdb_value_to_json(value: duckdb::types::Value) -> serde_json::Value {
    match value {
        duckdb::types::Value::Null => serde_json::Value::Null,
        duckdb::types::Value::Boolean(b) => serde_json::Value::Bool(b),
        duckdb::types::Value::TinyInt(n) => serde_json::json!(n),
        duckdb::types::Value::SmallInt(n) => serde_json::json!(n),
        duckdb::types::Value::Int(n) => serde_json::json!(n),
        duckdb::types::Value::BigInt(n) => serde_json::json!(n),
        duckdb::types::Value::HugeInt(n) => {
            if let Ok(n64) = i64::try_from(n) {
                serde_json::json!(n64)
            } else {
                serde_json::Value::String(n.to_string())
            }
        }
        duckdb::types::Value::UTinyInt(n) => serde_json::json!(n),
        duckdb::types::Value::USmallInt(n) => serde_json::json!(n),
        duckdb::types::Value::UInt(n) => serde_json::json!(n),
        duckdb::types::Value::UBigInt(n) => serde_json::json!(n),
        duckdb::types::Value::Float(n) => {
            if n.is_finite() {
                serde_json::json!(n)
            } else {
                serde_json::Value::String(n.to_string())
            }
        }
        duckdb::types::Value::Double(n) => {
            if n.is_finite() {
                serde_json::json!(n)
            } else {
                serde_json::Value::String(n.to_string())
            }
        }
        duckdb::types::Value::Text(s) => serde_json::Value::String(s),
        other => serde_json::Value::String(format!("{other:?}")),
    }
}

/// Convert a DuckDB value to a display string.
pub(super) fn duckdb_value_to_string(value: duckdb::types::Value) -> String {
    match value {
        duckdb::types::Value::Null => "NULL".to_string(),
        duckdb::types::Value::Boolean(b) => b.to_string(),
        duckdb::types::Value::TinyInt(n) => n.to_string(),
        duckdb::types::Value::SmallInt(n) => n.to_string(),
        duckdb::types::Value::Int(n) => n.to_string(),
        duckdb::types::Value::BigInt(n) => n.to_string(),
        duckdb::types::Value::HugeInt(n) => n.to_string(),
        duckdb::types::Value::UTinyInt(n) => n.to_string(),
        duckdb::types::Value::USmallInt(n) => n.to_string(),
        duckdb::types::Value::UInt(n) => n.to_string(),
        duckdb::types::Value::UBigInt(n) => n.to_string(),
        duckdb::types::Value::Float(n) => n.to_string(),
        duckdb::types::Value::Double(n) => n.to_string(),
        duckdb::types::Value::Text(s) => s,
        other => format!("{other:?}"),
    }
}

/// What a query's text turned out to be once comments and statement
/// terminators are removed.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum StatementShape {
    /// Nothing but whitespace, comments and terminators.
    Empty,
    /// More than one `;`-separated statement.
    Multiple,
    /// A `$` outside a quoted run: a dollar-quoted string (`$$ ... $$`,
    /// `$tag$ ... $tag$`) or a `$n` parameter. Neither has a use through
    /// this path, and a dollar-quoted string can hide a quote character or
    /// a `;` from this scan — so the text is refused rather than guessed at.
    Dollar,
    /// A character outside the ASCII range that sits outside every quoted
    /// run and comment. DuckDB replaces a set of Unicode spaces (U+00A0,
    /// U+2000–U+200B, U+202F, U+205F, U+2060, U+3000, U+FEFF) outside
    /// quotes with a space BEFORE it lexes the text, and its lexer folds
    /// every other non-ASCII byte into identifiers; neither is something
    /// this scan should track version by version, and a zero-width space
    /// that DuckDB reads as whitespace would let a word this scan keys on
    /// (`IN (` + `SELECT`) hide behind a character that is not whitespace
    /// to it. The schemas a trace database carries are ASCII, so such a
    /// character has no use outside a literal; the text is refused.
    NonAscii(char),
    /// A `PIVOT` (or `PIVOT_WIDER`) that is not the one fully understood
    /// shape — a single top-level pivot whose every pivot column names a
    /// literal `IN (...)` list. DuckDB expands any statement holding a pivot
    /// column without literal entries into two statements — a `CREATE TYPE
    /// __pivot_enum_<uuid> AS ENUM (...)` that scans the source for the
    /// column's values (or runs the `IN (<subquery>)` given as the list),
    /// then the query — wherever the pivot sits in the statement, and the
    /// binding's `prepare` executes the first one, outside the row cap and
    /// before the second is bound; a successful run also leaves that type
    /// behind in the temp catalog. The text is refused; a top-level pivot
    /// with its values named (`ON col IN (...)`) is one statement and runs
    /// wrapped like any other row reader.
    PivotWithoutIn,
    /// Exactly one statement. `text` is that statement without comments and
    /// without leading or trailing terminators; `must_wrap` says whether it
    /// can read rows from a table — `SELECT`, `WITH`, `FROM`, `VALUES`,
    /// `TABLE`, `PIVOT`, `UNPIVOT`, and `CALL` / `EXECUTE`, which run
    /// whatever they name — and so may only run inside the
    /// `SELECT * FROM (...) LIMIT n` wrapper.
    Single { text: String, must_wrap: bool },
}

/// Whether `c` can continue an identifier in DuckDB's lexer: ASCII letters,
/// digits and `_`, and every character outside ASCII (the lexer admits
/// every byte at or above 0x80 into an identifier).
fn continues_identifier(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || !c.is_ascii()
}

/// Whether the `'` at `chars[i]` opens an escape-string literal (`E'...'`),
/// inside which a backslash escapes the character after it. DuckDB's lexer
/// starts one at `[eE]` immediately followed by a quote, but only when that
/// `E` begins a token of its own: an `E` that ends a longer identifier is
/// part of the identifier (`name'x'` is the identifier `name` and an
/// ordinary string), while the `E` after a numeric literal is not — `1E'x'`
/// lexes as the number `1` and an escape string, because the exponent form
/// of a number needs digits after its `E`. So the run of identifier
/// characters ending at the `E` is read the way the lexer reads it: leading
/// digits are a number (with an exponent when `[eE]` is followed by
/// digits), and the `E` is the prefix only when nothing else stands between
/// the number, or the run's start, and it.
fn opens_escape_string(chars: &[char], i: usize) -> bool {
    if i == 0 || !matches!(chars[i - 1], 'e' | 'E') {
        return false;
    }
    let mut start = i - 1;
    while start > 0 && continues_identifier(chars[start - 1]) {
        start -= 1;
    }
    // `run` ends with the `E` itself.
    let run = &chars[start..i];
    let mut p = 0;
    loop {
        let digits = run[p..].iter().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 {
            break;
        }
        p += digits;
        let exponent = match run.get(p) {
            Some('e' | 'E') => run[p + 1..]
                .iter()
                .take_while(|c| c.is_ascii_digit())
                .count(),
            _ => 0,
        };
        if exponent == 0 {
            break;
        }
        p += 1 + exponent;
    }
    p == run.len() - 1
}

/// The index just past the quoted run that opens at `chars[open]` (a `'` or
/// a `"`), or `chars.len()` when the run never closes. A doubled quote
/// inside the run is an escaped quote and does not end it; inside an
/// escape-string literal (a `'` run that `opens_escape_string` says is one)
/// a backslash also escapes the character after it, so `E'\''` is one
/// string here as it is to DuckDB's lexer. Every scan in this module walks
/// quoted runs through this one function, so they cannot disagree with
/// each other about where a run ends.
fn quoted_run_end(chars: &[char], open: usize) -> usize {
    let quote = chars[open];
    let escapes = quote == '\'' && opens_escape_string(chars, open);
    let mut i = open + 1;
    while i < chars.len() {
        let c = chars[i];
        if escapes && c == '\\' {
            i += 2;
            continue;
        }
        if c == quote {
            if chars.get(i + 1) == Some(&quote) {
                i += 2;
                continue;
            }
            return i + 1;
        }
        i += 1;
    }
    chars.len()
}

/// Whether `text` (comments already stripped) carries the `PIVOT` /
/// `PIVOT_WIDER` keyword anywhere outside a quoted run, and how many times.
/// `UNPIVOT` and identifiers that merely contain the word (`pivot_count`)
/// are not it.
fn pivot_keyword_count(text: &str) -> usize {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    let mut count = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' || c == '"' {
            i = quoted_run_end(&chars, i);
            continue;
        }
        if c.is_ascii_alphanumeric() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let word: String = chars[start..i]
                .iter()
                .collect::<String>()
                .to_ascii_lowercase();
            if word == "pivot" || word == "pivot_wider" {
                count += 1;
            }
            continue;
        }
        i += 1;
    }
    count
}

/// Whether a `PIVOT` / `PIVOT_WIDER` statement (`text`, comments already
/// stripped, the pivot keyword its first word) is the one shape that is
/// known not to make DuckDB build an enum: in its own `ON` clause — the
/// first `ON` at the statement's own nesting depth, after the source, up to
/// the clause's end (`USING`, `GROUP`, `ORDER`, `LIMIT`, or the end of the
/// text) — every comma-separated element is a plain column or expression
/// followed by an `IN (` whose list is LITERAL values. DuckDB (1.5.4,
/// `transform_pivot_stmt.cpp`) generates `CREATE TYPE __pivot_enum_<uuid>
/// AS ENUM (...)` for every pivot column that has no literal entries, and
/// the binding's `prepare` executes that statement outside the row cap:
/// a column without a list scans the source for its distinct values; a
/// column listed as `IN (<subquery>)` runs that subquery as the enum's
/// source. So an `IN (` counts only in the ON clause itself (not in a
/// parenthesised source subquery, a WHERE clause, a comment or a literal —
/// the bypass this closes: `PIVOT (SELECT * FROM t WHERE id IN (3)) ON
/// bucket USING count(id)` is still expanded), only when its list does not
/// open with a query keyword, and only as the list of a plain element — a
/// `CASE ... END` or a `[`/`{` literal in the clause hides the `IN (` of a
/// nested expression, so those are refused. A pivot whose `ON` clause this
/// scan cannot find is refused with the rest.
fn pivot_is_fully_listed(text: &str) -> bool {
    /// A token at the statement's own nesting depth.
    enum Tok {
        /// A word (lowercased).
        Word(String),
        /// The `IN` keyword followed by `(`, with the first word inside the
        /// parens (`None` when the list is empty or opens with something
        /// that is not a word — a literal, a nested paren) and whether the
        /// list is empty.
        InList(Option<String>, bool),
        Comma,
    }
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    // The statement may sit inside outer parens (`( PIVOT ... )`): its own
    // depth is where its first word is.
    let mut depth = 0i32;
    while i < chars.len() && (chars[i].is_whitespace() || chars[i] == '(') {
        if chars[i] == '(' {
            depth += 1;
        }
        i += 1;
    }
    let base = depth;
    let mut toks: Vec<Tok> = Vec::new();
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\'' | '"' => {
                i = quoted_run_end(&chars, i);
            }
            '(' | '[' | '{' => {
                depth += 1;
                i += 1;
            }
            ')' | ']' | '}' => {
                depth -= 1;
                i += 1;
            }
            ',' if depth == base => {
                toks.push(Tok::Comma);
                i += 1;
            }
            _ if c.is_ascii_alphanumeric() || c == '_' => {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                if depth == base {
                    let word: String = chars[start..i]
                        .iter()
                        .collect::<String>()
                        .to_ascii_lowercase();
                    let mut j = i;
                    while j < chars.len() && chars[j].is_whitespace() {
                        j += 1;
                    }
                    let paren = chars.get(j) == Some(&'(');
                    if word == "in" && paren {
                        // The first word inside the list, and whether the
                        // list has anything in it at all.
                        let mut k = j + 1;
                        while k < chars.len() && chars[k].is_whitespace() {
                            k += 1;
                        }
                        let empty = chars.get(k) == Some(&')');
                        let mut first = String::new();
                        while k < chars.len()
                            && (chars[k].is_ascii_alphanumeric() || chars[k] == '_')
                        {
                            first.push(chars[k].to_ascii_lowercase());
                            k += 1;
                        }
                        let first = if first.is_empty() { None } else { Some(first) };
                        toks.push(Tok::InList(first, empty));
                    } else {
                        toks.push(Tok::Word(word));
                    }
                }
            }
            _ => i += 1,
        }
    }
    // The pivot's own ON clause: from the first top-level `ON` after the
    // first word to the first clause keyword after it. A second top-level
    // `ON` before that keyword means the first one was a join's, in a
    // source written without parentheses (`PIVOT t JOIN u ON ... ON col`):
    // its predicate is not a value list, so the pivot is refused rather
    // than read from the wrong clause; the same source in parentheses
    // reads fine.
    let Some(on) = toks
        .iter()
        .skip(1)
        .position(|t| matches!(t, Tok::Word(w) if w == "on"))
        .map(|p| p + 1)
    else {
        return false;
    };
    let clause = &toks[on + 1..];
    let end = clause
        .iter()
        .position(|t| matches!(t, Tok::Word(w) if matches!(w.as_str(), "using" | "group" | "order" | "limit")))
        .unwrap_or(clause.len());
    let clause = &clause[..end];
    // Words that make an element something other than a plain column or
    // expression with a literal list: a CASE expression (its `IN (` belongs
    // to a branch, not to the pivot column), a join's `ON`, a nested query.
    // `PIVOT_LONGER` is DuckDB's other spelling of `UNPIVOT`.
    const NOT_A_PLAIN_ELEMENT: &[&str] = &[
        "case",
        "when",
        "then",
        "else",
        "end",
        "on",
        "select",
        "from",
        "with",
        "values",
        "table",
        "pivot",
        "pivot_wider",
        "unpivot",
        "pivot_longer",
        "union",
        "intersect",
        "except",
    ];
    // A list that opens with a query keyword is a subquery, and DuckDB
    // builds the enum from it.
    const QUERY_KEYWORD: &[&str] = &[
        "select",
        "with",
        "from",
        "values",
        "table",
        "pivot",
        "pivot_wider",
        "unpivot",
        "pivot_longer",
        "describe",
        "show",
        "summarize",
    ];
    !clause.is_empty()
        && !clause
            .iter()
            .any(|t| matches!(t, Tok::Word(w) if NOT_A_PLAIN_ELEMENT.contains(&w.as_str())))
        && clause.split(|t| matches!(t, Tok::Comma)).all(|element| {
            let lists = element
                .iter()
                .filter(|t| matches!(t, Tok::InList(..)))
                .count();
            lists == 1
                && element.iter().any(|t| {
                    matches!(t, Tok::InList(first, empty)
                        if !empty && !first.as_deref().is_some_and(|w| QUERY_KEYWORD.contains(&w)))
                })
        })
}

/// Classify `sql` for the row cap: strip `--` and `/* */` comments (nested
/// block comments included), drop leading and trailing `;`, and report
/// whether what remains is one statement. Single- and double-quoted strings
/// are passed through untouched, so a `;` or `--` inside a literal is not a
/// separator or a comment.
///
/// This scan has to agree with DuckDB's own lexer about where statements
/// end, because the binding's `prepare` executes every statement but the
/// last of the text it is given. It models the string forms the lexer has
/// — an ordinary quoted run with `''` as an escaped quote, and the
/// escape-string literal `E'...'`, inside which a backslash also escapes
/// the character after it (`quoted_run_end`, `opens_escape_string`) — and
/// refuses outright the two constructs it does not model rather than guess
/// at them: a dollar-quoted string, inside which a `'` would make this scan
/// believe it is in a literal while DuckDB is not (refused with every other
/// bare `$`, `Dollar`), and any non-ASCII character outside a quoted run or
/// comment, where DuckDB's pre-lexing replacement of certain Unicode spaces
/// would make it read whitespace where this scan reads a character
/// (`NonAscii`).
pub(super) fn statement_shape(sql: &str) -> StatementShape {
    let mut out = String::with_capacity(sql.len());
    // Byte offsets in `out` of every `;` that separates statements.
    let mut separators: Vec<usize> = Vec::new();
    let chars: Vec<char> = sql.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        match c {
            '\'' | '"' => {
                // Copy the quoted run verbatim (its closing quote included
                // when it has one).
                let end = quoted_run_end(&chars, i);
                out.extend(&chars[i..end]);
                i = end;
            }
            '$' => return StatementShape::Dollar,
            '-' if next == Some('-') => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                out.push(' ');
            }
            '/' if next == Some('*') => {
                let mut depth = 1usize;
                i += 2;
                while i < chars.len() && depth > 0 {
                    if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                        depth += 1;
                        i += 2;
                    } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                out.push(' ');
            }
            ';' => {
                // A terminator only counts once a statement precedes it;
                // leading ones are dropped here and trailing ones are
                // trimmed below.
                if !out.trim().is_empty() {
                    separators.push(out.len());
                    out.push(';');
                }
                i += 1;
            }
            // Outside every quoted run and comment the text is keywords,
            // identifiers, numbers and punctuation, all ASCII in a trace
            // database's schemas; a non-ASCII character here is one DuckDB
            // may read as whitespace (its stripped Unicode spaces) or as
            // part of an identifier, and this scan cannot know which.
            _ if !c.is_ascii() => return StatementShape::NonAscii(c),
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }

    let text = out
        .trim()
        .trim_end_matches(|c: char| c == ';' || c.is_whitespace());
    if text.is_empty() {
        return StatementShape::Empty;
    }
    // Separators followed only by whitespace and comments were trimmed off
    // the end; one inside the remaining text splits statements.
    let start = out.len() - out.trim_start().len();
    let end = start + text.len();
    if separators.iter().any(|&p| p >= start && p < end) {
        return StatementShape::Multiple;
    }
    let first_word: String = text
        .trim_start_matches(|c: char| c == '(' || c.is_whitespace())
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect::<String>()
        .to_ascii_lowercase();
    // A pivot makes DuckDB generate an enum-building statement ahead of the
    // query for every pivot column without a literal value list — wherever
    // the pivot sits in the statement (nested under a SELECT, a WITH, a FROM
    // or a set operation, the parser hoists it the same way) — and `prepare`
    // would execute that statement. Only the one shape this scan fully
    // understands is let through: a single top-level pivot whose every
    // column names a literal `IN (...)` list; refuse the rest before
    // anything reaches the binding.
    let pivots = pivot_keyword_count(text);
    if pivots > 0
        && !(pivots == 1
            && matches!(first_word.as_str(), "pivot" | "pivot_wider")
            && pivot_is_fully_listed(text))
    {
        return StatementShape::PivotWithoutIn;
    }
    // Every statement that reads rows runs wrapped; `pivot_wider` is the
    // spelled-out form of `pivot` and `pivot_longer` that of `unpivot`, and
    // each reads rows the same way as the word it stands for.
    let must_wrap = matches!(
        first_word.as_str(),
        "select"
            | "with"
            | "from"
            | "values"
            | "table"
            | "pivot"
            | "pivot_wider"
            | "unpivot"
            | "pivot_longer"
            | "call"
            | "execute"
    );
    StatementShape::Single {
        text: text.to_string(),
        must_wrap,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single(sql: &str) -> (String, bool) {
        match statement_shape(sql) {
            StatementShape::Single { text, must_wrap } => (text, must_wrap),
            other => panic!("expected a single statement for {sql:?}, got {other:?}"),
        }
    }

    #[test]
    fn test_statement_shape_strips_comments_and_terminators() {
        assert_eq!(
            single("SELECT bucket FROM t; -- all of them"),
            ("SELECT bucket FROM t".to_string(), true)
        );
        assert_eq!(
            single("SELECT bucket FROM t;\n-- note\n"),
            ("SELECT bucket FROM t".to_string(), true)
        );
        assert_eq!(
            single("SELECT bucket FROM t; /* x */"),
            ("SELECT bucket FROM t".to_string(), true)
        );
        assert_eq!(
            single(";SELECT bucket FROM t"),
            ("SELECT bucket FROM t".to_string(), true)
        );
        assert_eq!(
            single("/* a /* nested */ b */ SELECT 1"),
            ("SELECT 1".to_string(), true)
        );
        assert_eq!(
            single("  ;; \n WITH b AS (SELECT 1) SELECT * FROM b ; ; "),
            ("WITH b AS (SELECT 1) SELECT * FROM b".to_string(), true)
        );
    }

    #[test]
    fn test_statement_shape_keeps_literals_intact() {
        assert_eq!(
            single("SELECT '--not a comment; really' AS s, \"we;ird\" FROM t"),
            (
                "SELECT '--not a comment; really' AS s, \"we;ird\" FROM t".to_string(),
                true
            )
        );
        assert_eq!(
            single("SELECT 'it''s; fine' FROM t"),
            ("SELECT 'it''s; fine' FROM t".to_string(), true)
        );
        // An escape-string literal is one string through its `\'`, as it is
        // to DuckDB, and comes out untouched like every other literal.
        assert_eq!(
            single("SELECT E'it\\'s; fine' FROM t"),
            ("SELECT E'it\\'s; fine' FROM t".to_string(), true)
        );
        assert_eq!(
            single("SELECT e'a\\\\' AS s, E'\\'' AS q FROM t"),
            ("SELECT e'a\\\\' AS s, E'\\'' AS q FROM t".to_string(), true)
        );
    }

    #[test]
    fn test_statement_shape_reads_escape_strings_as_duckdb_does() {
        // DuckDB's lexer reads `E'\''` as ONE string (a backslash escapes
        // the quote after it). A scan that ended the string at the `\'`
        // would take everything from there to the next lone `'` as a
        // literal — code to DuckDB — and a `;` or a PIVOT in that span
        // would reach `prepare` hidden: the first two statements below are
        // the ones `prepare` would have EXECUTED.
        for sql in [
            "SELECT E'\\''; SET memory_limit = '100GB'; SELECT E'\\''",
            "SELECT e'\\''; SET memory_limit = '100GB'; SELECT e'\\''",
            // The escape-string prefix after a numeric literal: `1E'` is
            // the number 1 and an escape string (an exponent needs digits).
            "SELECT 1E'\\''; SET memory_limit = '100GB'; SELECT 1E'\\''",
            "SELECT 1e5E'\\''; SET memory_limit = '100GB'; SELECT 1e5E'\\''",
        ] {
            assert_eq!(statement_shape(sql), StatementShape::Multiple, "{sql:?}");
        }
        assert_eq!(
            statement_shape(
                "SELECT E'\\'' AS q FROM (PIVOT t ON bucket USING count(id)) WHERE '' = ''"
            ),
            StatementShape::PivotWithoutIn
        );
        assert_eq!(
            pivot_keyword_count("SELECT E'\\'' AS q FROM (PIVOT t ON a) WHERE '' = ''"),
            1
        );
        // The other way round: inside the escape string a `;` and a PIVOT
        // are literal text, so this is one statement, and the pivot
        // column's list of escape-string literals is a literal list.
        assert_eq!(
            pivot_keyword_count("SELECT E'\\' PIVOT t ON a; ' FROM t"),
            0
        );
        assert_eq!(
            single("SELECT E'\\'; SELECT 2 --' AS s FROM t"),
            ("SELECT E'\\'; SELECT 2 --' AS s FROM t".to_string(), true)
        );
        assert!(single("PIVOT t ON comm IN (E'\\'', e'a\\\\b') USING count(id)").1);
        // An `E` that ends a longer identifier is part of the identifier —
        // `name'...'` is the identifier `name` and an ordinary string, in
        // which a backslash is just a character — so the `;` after it is a
        // separator to DuckDB and to this scan.
        for sql in [
            "SELECT name'\\'; SELECT 2 --'",
            "SELECT x1E'\\'; SELECT 2 --'",
            "SELECT _e'\\'; SELECT 2 --'",
            "SELECT 1ee'\\'; SELECT 2 --'",
        ] {
            assert_eq!(statement_shape(sql), StatementShape::Multiple, "{sql:?}");
        }
        assert!(opens_escape_string(&['E', '\''], 1));
        assert!(opens_escape_string(&[' ', 'e', '\''], 2));
        assert!(opens_escape_string(&['1', 'E', '\''], 2));
        assert!(opens_escape_string(&['1', 'e', '5', 'E', '\''], 4));
        assert!(opens_escape_string(&['1', 'e', '\''], 2));
        assert!(!opens_escape_string(&['a', 'E', '\''], 2));
        assert!(!opens_escape_string(&['_', 'E', '\''], 2));
        assert!(!opens_escape_string(&['1', '_', 'E', '\''], 3));
        assert!(!opens_escape_string(&['1', 'e', 'e', '\''], 3));
        assert!(!opens_escape_string(&['é', 'E', '\''], 2));
        assert!(!opens_escape_string(&['E', ' ', '\''], 2));
        assert!(!opens_escape_string(&['\''], 0));
        // The run's end: just past the closing quote, or the text's end when
        // the run never closes.
        let run = |s: &str, open: usize| quoted_run_end(&s.chars().collect::<Vec<_>>(), open);
        assert_eq!(run("E'\\''", 1), 5);
        assert_eq!(run("x'\\'; ", 1), 4);
        assert_eq!(run("'a''b' c", 0), 6);
        assert_eq!(run("\"a\"\"b\" c", 0), 6);
        assert_eq!(run("E'a\\\\'", 1), 6);
        assert_eq!(run("E'a\\", 1), 4);
        assert_eq!(run("'never", 0), 6);
    }

    #[test]
    fn test_statement_shape_refuses_non_ascii_outside_literals() {
        // DuckDB replaces certain Unicode spaces outside quotes with a space
        // before it lexes, and Rust's `char::is_whitespace` excludes three of
        // them (U+200B, U+2060, U+FEFF): to this scan `\u{200B}SELECT` is a
        // word that is not `select`, to DuckDB it is `IN (<subquery>)`. Every
        // non-ASCII character outside a quoted run or a comment is refused,
        // so no such disagreement can be reached.
        for (sql, ch) in [
            (
                "PIVOT t ON bucket IN (\u{200B}SELECT DISTINCT bucket FROM t) USING count(id)",
                '\u{200B}',
            ),
            (
                "PIVOT t ON bucket IN (\u{2060}SELECT id FROM t) USING count(id)",
                '\u{2060}',
            ),
            (
                "PIVOT t ON bucket IN (\u{FEFF}SELECT id FROM t) USING count(id)",
                '\u{FEFF}',
            ),
            ("SELECT 1\u{00A0}; SET memory_limit = '100GB'", '\u{00A0}'),
            ("SELECT \u{E9}t\u{E9} FROM t", '\u{E9}'),
            ("SELECT 1 \u{2014} 2", '\u{2014}'),
        ] {
            assert_eq!(
                statement_shape(sql),
                StatementShape::NonAscii(ch),
                "{sql:?}"
            );
        }
        // Inside a literal, a quoted identifier or a comment it is text.
        assert_eq!(
            single("SELECT '\u{E9}\u{200B}' AS s, \"\u{FC}n\" FROM t -- \u{2014}\n"),
            (
                "SELECT '\u{E9}\u{200B}' AS s, \"\u{FC}n\" FROM t".to_string(),
                true
            )
        );
        assert_eq!(
            single("/* \u{2014} \u{200B} */ SELECT 1"),
            ("SELECT 1".to_string(), true)
        );
    }

    #[test]
    fn test_statement_shape_treats_pivot_longer_as_unpivot() {
        // `PIVOT_LONGER` is DuckDB's other spelling of `UNPIVOT`: as a list
        // it is a subquery (the enum would be built by running it), and as
        // a statement it reads rows and runs wrapped.
        for sql in [
            "PIVOT t ON bucket IN (PIVOT_LONGER t ON id INTO NAME k VALUE v) USING count(id)",
            "PIVOT t ON bucket IN ( pivot_longer t ON id INTO NAME k VALUE v ) USING count(id)",
        ] {
            assert_eq!(
                statement_shape(sql),
                StatementShape::PivotWithoutIn,
                "{sql:?}"
            );
        }
        assert!(single("PIVOT_LONGER t ON bucket INTO NAME k VALUE v").1);
        assert!(single("pivot_longer t on bucket into name k value v").1);
    }

    #[test]
    fn test_statement_shape_classifies_multiple_and_empty() {
        assert_eq!(
            statement_shape("SELECT 1; SELECT 2"),
            StatementShape::Multiple
        );
        assert_eq!(
            statement_shape("SELECT id FROM t; SET memory_limit = '100GB'"),
            StatementShape::Multiple
        );
        assert_eq!(
            statement_shape("SELECT 'a' ; -- x\n SELECT 'b'"),
            StatementShape::Multiple
        );
        assert_eq!(statement_shape("  -- nothing\n;"), StatementShape::Empty);
        assert_eq!(statement_shape(""), StatementShape::Empty);
    }

    #[test]
    fn test_statement_shape_refuses_bare_dollar() {
        // A dollar-quoted string holding a quote character is the one
        // shape under which this scan would think it is inside a literal
        // while DuckDB is not; every bare `$` is refused instead.
        for sql in [
            "SELECT $$'$$; SET memory_limit='100GB'; SELECT $$'$$",
            "SELECT $$'$$) AS x; SET memory_limit='100GB'; SELECT * FROM (SELECT $$'$$",
            "SELECT $tag$a'b$tag$",
            "SELECT $$a--b$$",
            "SELECT id FROM t WHERE id = $1",
            "SELECT a$b FROM t",
        ] {
            assert_eq!(statement_shape(sql), StatementShape::Dollar, "{sql:?}");
        }
        // Inside a quoted run or a comment a `$` is just a character.
        assert_eq!(
            single("SELECT '$$; SET x' AS s, \"a$b\" FROM t /* $5 */ -- $$"),
            ("SELECT '$$; SET x' AS s, \"a$b\" FROM t".to_string(), true)
        );
    }

    #[test]
    fn test_statement_shape_must_wrap_keywords() {
        for sql in [
            "select 1",
            "WITH x AS (SELECT 1) SELECT * FROM x",
            "FROM t SELECT id",
            "VALUES (1), (2)",
            "TABLE t",
            "(SELECT 1) UNION ALL (SELECT 2)",
            "(\n  (SELECT 1)\n)",
            "PIVOT t ON bucket IN (0, 1) USING count(id)",
            "CALL pragma_table_info('t')",
            "EXECUTE q",
        ] {
            assert!(single(sql).1, "{sql:?} must run wrapped");
        }
        for sql in [
            "SHOW TABLES",
            "PRAGMA table_info('t')",
            "DESCRIBE t",
            "SUMMARIZE t",
            "SET memory_limit = '1GB'",
            "EXPLAIN SELECT 1",
        ] {
            assert!(!single(sql).1, "{sql:?} takes the raw path");
        }
    }

    #[test]
    fn test_statement_shape_refuses_pivot_without_an_in_list() {
        // DuckDB expands a pivot with no value list into `CREATE TYPE ... AS
        // ENUM (SELECT DISTINCT ...)` + the SELECT, and the binding's
        // `prepare` executes the first of the two — so the shape is refused
        // before it can reach `prepare`. Only a list in the pivot's own ON
        // clause counts: one in the source subquery, a WHERE clause, a
        // comment or a literal leaves the pivot column unlisted.
        for sql in [
            "PIVOT t ON bucket",
            "PIVOT t ON bucket USING count(id)",
            "pivot_wider t on bucket using sum(id) group by id",
            "PIVOT t ON bucket USING count(id) -- IN (0, 1) in a comment",
            "PIVOT t ON bucket USING count(id) WHERE s = 'IN (x)'",
            "( PIVOT t ON bucket USING count(id) )",
            // The bypass this closes: the only `IN (` sits in the source subquery.
            "PIVOT (SELECT * FROM t WHERE id IN (3, 4, 5)) ON bucket USING count(id)",
            "PIVOT (SELECT * FROM t WHERE id IN (3)) ON bucket USING count(id) GROUP BY id",
            // Not runnable DuckDB (a WHERE after USING) — and the ON clause
            // names no list either way.
            "PIVOT t ON bucket USING count(id) WHERE id IN (1, 2)",
            // Two pivot columns, one of them unlisted.
            "PIVOT t ON bucket IN (0, 1), id USING count(*)",
            "PIVOT t ON bucket, id IN (1) USING count(*)",
            // No ON clause at all.
            "PIVOT t USING count(id)",
            // A join source written without parentheses: the first ON is
            // the join's, so its predicate must not vouch for the pivot
            // column (write the source as a parenthesised subquery).
            "PIVOT t JOIN u ON u.k IN (1) ON bucket USING count(*)",
            "PIVOT t JOIN u ON t.k = u.k ON bucket IN (0) USING count(*)",
            // A pivot nested inside another statement: DuckDB hoists its
            // enum the same way, so a pivot is accepted only at the top
            // level, listed or not.
            "SELECT * FROM (PIVOT t ON bucket USING count(id))",
            "SELECT * FROM (PIVOT t ON bucket IN (0) USING count(id))",
            "WITH p AS (PIVOT t ON bucket USING count(id)) SELECT * FROM p",
            "FROM (PIVOT t ON bucket USING count(id))",
            "(SELECT 1) UNION ALL (PIVOT t ON bucket USING count(id))",
            "PIVOT (PIVOT t ON bucket USING count(id)) ON bucket IN (0) USING count(*)",
            // `IN (<subquery>)` is a legal list, and DuckDB builds the enum
            // by running that subquery.
            "PIVOT t ON bucket IN (SELECT id FROM t) USING count(id)",
            "PIVOT t ON bucket IN ( select id FROM t ) USING count(id)",
            "PIVOT t ON bucket IN (WITH x AS (SELECT 1) SELECT * FROM x) USING count(id)",
            "PIVOT t ON bucket IN (FROM t SELECT id) USING count(id)",
            "PIVOT t ON bucket IN (VALUES (1), (2)) USING count(id)",
            "PIVOT t ON bucket IN () USING count(id)",
            // An `IN (` inside a CASE or a list / struct literal is not the
            // column's list, and the column itself has none.
            "PIVOT t ON CASE WHEN bucket IN (0) THEN 'a' ELSE 'b' END USING count(id)",
            "PIVOT t ON [bucket IN (0)] USING count(id)",
            "PIVOT t ON {'k': bucket IN (0)} USING count(id)",
            "PIVOT t ON bucket IN (0) IN (1) USING count(id)",
        ] {
            assert_eq!(
                statement_shape(sql),
                StatementShape::PivotWithoutIn,
                "{sql:?}"
            );
        }
        // With every pivot column's values named the statement is one
        // statement; it runs wrapped like every other row reader. `IN(`
        // without a space, an expression pivot column, a quoted column, a
        // parenthesised source, outer parens and literal lists of every
        // kind (numbers, strings, NULL, a typed literal, a function of
        // literals) all read the same.
        for sql in [
            "PIVOT t ON bucket IN (0, 1) USING count(id)",
            "PIVOT t ON bucket IN(0, 1) USING count(id)",
            "pivot_wider t on bucket in (0) using sum(id)",
            "PIVOT t ON bucket IN (0, 1) USING count(id) GROUP BY id",
            "PIVOT t ON bucket IN (0), id IN (1, 2) USING count(*)",
            "PIVOT t ON lower(comm) IN ('a', 'b') USING count(*) GROUP BY id",
            "PIVOT t ON \"bucket\" IN (0) USING count(id)",
            "PIVOT t ON bucket IN (NULL, 1) USING count(id)",
            "PIVOT t ON day IN (DATE '2024-01-01', DATE '2024-01-02') USING count(id)",
            "PIVOT t ON comm IN (lower('A'), 'b') USING count(id)",
            "PIVOT (SELECT * FROM t WHERE id IN (3, 4)) ON bucket IN (0, 1) USING count(id)",
            "PIVOT (SELECT * FROM t JOIN u ON t.k = u.k) ON bucket IN (0) USING count(*)",
            "( PIVOT t ON bucket IN (0) USING count(id) )",
        ] {
            assert!(single(sql).1, "{sql:?} must run wrapped");
        }
        // A word that merely starts with `in` is not the keyword, and
        // `UNPIVOT` creates no type, so neither is refused; nor is the word
        // inside a literal or as part of an identifier.
        assert!(single("UNPIVOT t ON bucket INTO NAME k VALUE v").1);
        assert!(single("SELECT index_col FROM t").1);
        assert!(single("SELECT pivot_count, 'PIVOT t ON x' AS s FROM t").1);
        assert_eq!(
            pivot_keyword_count("SELECT pivot_count, 'PIVOT t' FROM t"),
            0
        );
        assert_eq!(pivot_keyword_count("PIVOT (PIVOT_WIDER t ON a) ON b"), 2);
    }

    #[test]
    fn test_duckdb_value_to_json_types() {
        assert_eq!(
            duckdb_value_to_json(duckdb::types::Value::Null),
            serde_json::Value::Null
        );
        assert_eq!(
            duckdb_value_to_json(duckdb::types::Value::Boolean(true)),
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            duckdb_value_to_json(duckdb::types::Value::Int(42)),
            serde_json::json!(42)
        );
        assert_eq!(
            duckdb_value_to_json(duckdb::types::Value::BigInt(-100)),
            serde_json::json!(-100)
        );
        assert_eq!(
            duckdb_value_to_json(duckdb::types::Value::Double(1.23)),
            serde_json::json!(1.23)
        );
        assert_eq!(
            duckdb_value_to_json(duckdb::types::Value::Text("hello".to_string())),
            serde_json::json!("hello")
        );
    }

    #[test]
    fn test_duckdb_value_to_json_nan() {
        let val = duckdb_value_to_json(duckdb::types::Value::Double(f64::NAN));
        assert!(val.is_string());
    }

    #[test]
    fn test_duckdb_value_to_json_huge_int() {
        // Fits in i64
        assert_eq!(
            duckdb_value_to_json(duckdb::types::Value::HugeInt(42)),
            serde_json::json!(42)
        );
        // Too large for i64
        let big = i128::MAX;
        let val = duckdb_value_to_json(duckdb::types::Value::HugeInt(big));
        assert!(val.is_string());
        assert_eq!(val.as_str().unwrap(), big.to_string());
    }
}
