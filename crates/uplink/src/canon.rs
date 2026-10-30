//! Canonical JSON: the bytes the Cargo Bay server signs. It follows JavaScript's
//! `JSON.stringify` exactly (cargo-bay `core/canonical-json.mjs`): keys sorted by UTF-16 code
//! units, no whitespace, a hand-written string escaper.

use serde_json::Value;

/// The canonical text of `value`. Errors for a number JavaScript would not print as an integer
/// or a plain decimal integer (manifests and key lists only carry integers).
pub fn canonical(value: &Value) -> Result<String, String> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut String) -> Result<(), String> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                let f = n.as_f64().ok_or("number is not finite")?;
                if f.is_finite() && f.fract() == 0.0 && f.abs() < 1e21 {
                    out.push_str(&format!("{f:.0}"));
                } else {
                    return Err(format!("number {n} has no canonical form"));
                }
            }
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by_key(|k| k.encode_utf16().collect::<Vec<u16>>());
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                if let Some(v) = map.get(key) {
                    write_value(v, out)?;
                }
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn small_cases() {
        assert_eq!(canonical(&json!({"b": [3, {"z": 1, "a": 2}], "a": "x y"})).unwrap(), r#"{"a":"x y","b":[3,{"a":2,"z":1}]}"#);
        assert_eq!(canonical(&json!("\u{1}\n\u{7f}")).unwrap(), "\"\\u0001\\n\u{7f}\"");
        assert_eq!(canonical(&json!({"n": "Café —"})).unwrap(), "{\"n\":\"Café —\"}");
        assert_eq!(canonical(&json!({"b": 1, "a": [true, null, "x"]})).unwrap(), r#"{"a":[true,null,"x"],"b":1}"#);
        assert!(canonical(&json!(1.5)).is_err());
    }

    #[test]
    fn keys_sort_by_utf16_units() {
        // U+1F600 is the surrogate pair D83D DE00, which sorts before U+FF5E.
        let v = json!({"\u{ff5e}": 1, "\u{1f600}": 2});
        assert_eq!(canonical(&v).unwrap(), "{\"\u{1f600}\":2,\"\u{ff5e}\":1}");
    }
}
