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

#[cfg(test)]
mod tests {
    use super::*;

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
