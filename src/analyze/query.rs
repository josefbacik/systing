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
    /// A `PIVOT` (or `PIVOT_WIDER`) statement with no `IN (...)` list. DuckDB
    /// expands that form into two statements — a `CREATE TYPE
    /// __pivot_enum_<uuid> AS ENUM (SELECT DISTINCT ...)` that scans the
    /// pivot column, then the SELECT — and the binding's `prepare` executes
    /// the first one, outside the row cap and before the second is bound; a
    /// successful run also leaves that type behind in the temp catalog. The
    /// text is refused; the same pivot with its values named (`ON col IN
    /// (...)`) is one statement and runs wrapped like any other row reader.
    PivotWithoutIn,
    /// Exactly one statement. `text` is that statement without comments and
    /// without leading or trailing terminators; `must_wrap` says whether it
    /// can read rows from a table — `SELECT`, `WITH`, `FROM`, `VALUES`,
    /// `TABLE`, `PIVOT`, `UNPIVOT`, and `CALL` / `EXECUTE`, which run
    /// whatever they name — and so may only run inside the
    /// `SELECT * FROM (...) LIMIT n` wrapper.
    Single { text: String, must_wrap: bool },
}

/// Whether `text` (comments already stripped) contains an `IN (` token
/// outside a quoted run — the `PIVOT ... ON col IN (...)` value list that
/// keeps DuckDB from expanding the pivot into an enum-building statement.
/// An `IN (...)` anywhere else in the text (a WHERE clause) also counts:
/// this scan errs toward accepting a pivot whose ON clause it cannot place,
/// and the row cap and the memory bound still hold for it.
fn has_in_list(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' || c == '"' {
            i += 1;
            while i < chars.len() && chars[i] != c {
                i += 1;
            }
            i += 1;
            continue;
        }
        let word_start = i == 0 || !(chars[i - 1].is_ascii_alphanumeric() || chars[i - 1] == '_');
        if word_start
            && c.eq_ignore_ascii_case(&'i')
            && matches!(chars.get(i + 1), Some(n) if n.eq_ignore_ascii_case(&'n'))
            && !matches!(chars.get(i + 2), Some(n) if n.is_ascii_alphanumeric() || *n == '_')
        {
            let mut j = i + 2;
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            if chars.get(j) == Some(&'(') {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Classify `sql` for the row cap: strip `--` and `/* */` comments (nested
/// block comments included), drop leading and trailing `;`, and report
/// whether what remains is one statement. Single- and double-quoted strings
/// are passed through untouched, so a `;` or `--` inside a literal is not a
/// separator or a comment.
///
/// This scan has to agree with DuckDB's own lexer about where statements
/// end, because the binding's `prepare` executes every statement but the
/// last of the text it is given. The scan is built so that every place it
/// can disagree errs toward seeing MORE separators (and refusing): an
/// escape-string literal (`E'...'`) whose `\'` extends the string in DuckDB
/// ends it here, so a `;` DuckDB hides is one this scan refuses; and the one
/// construct that would go the other way — a dollar-quoted string, inside
/// which a `'` makes this scan believe it is in a literal while DuckDB is
/// not — is refused outright with every other bare `$` (`Dollar`).
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
                // Copy the quoted run verbatim; a doubled quote is an escape.
                out.push(c);
                i += 1;
                while i < chars.len() {
                    out.push(chars[i]);
                    if chars[i] == c {
                        if chars.get(i + 1) == Some(&c) {
                            out.push(c);
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
                i += 1;
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
    // A pivot that names no `IN (...)` list is parser-expanded by DuckDB
    // into an enum-building statement ahead of the SELECT, which `prepare`
    // would execute; refuse it before anything reaches the binding.
    if matches!(first_word.as_str(), "pivot" | "pivot_wider") && !has_in_list(text) {
        return StatementShape::PivotWithoutIn;
    }
    // Every statement that reads rows runs wrapped; `pivot_wider` is the
    // spelled-out form of `pivot` and reads rows the same way.
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
        // before it can reach `prepare`.
        for sql in [
            "PIVOT t ON bucket",
            "PIVOT t ON bucket USING count(id)",
            "pivot_wider t on bucket using sum(id) group by id",
            "PIVOT t ON bucket USING count(id) -- IN (0, 1) in a comment",
            "PIVOT t ON bucket USING count(id) WHERE s = 'IN (x)'",
            "( PIVOT t ON bucket USING count(id) )",
        ] {
            assert_eq!(
                statement_shape(sql),
                StatementShape::PivotWithoutIn,
                "{sql:?}"
            );
        }
        // With the values named the statement is one statement; it runs
        // wrapped like every other row reader. `IN(` without a space and an
        // `IN (...)` elsewhere in the text both count.
        for sql in [
            "PIVOT t ON bucket IN (0, 1) USING count(id)",
            "PIVOT t ON bucket IN(0, 1) USING count(id)",
            "pivot_wider t on bucket in (0) using sum(id)",
            "PIVOT t ON bucket USING count(id) WHERE id IN (1, 2)",
        ] {
            assert!(single(sql).1, "{sql:?} must run wrapped");
        }
        // A word that merely starts with `in` is not the keyword, and
        // `UNPIVOT` creates no type, so neither is refused.
        assert!(single("UNPIVOT t ON bucket INTO NAME k VALUE v").1);
        assert!(single("SELECT index_col FROM t").1);
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
