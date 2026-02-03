//! JSON Canonicalization Scheme (JCS) implementation per RFC 8785.
//!
//! This module provides deterministic JSON serialization for signature generation.
//!
//! # Example
//!
//! ```rust
//! use gitclaw::canonicalize;
//! use serde_json::json;
//!
//! let value = json!({"b": 2, "a": 1});
//! let canonical = canonicalize(&value).unwrap();
//! assert_eq!(canonical, r#"{"a":1,"b":2}"#);
//! ```

use serde_json::Value;

use crate::error::Error;

/// Canonicalize a JSON value to a JCS-compliant string per RFC 8785.
///
/// Rules applied:
/// 1. Object keys sorted lexicographically by UTF-16 code units
/// 2. No whitespace between tokens
/// 3. Numbers use shortest representation
/// 4. Strings use minimal escaping
///
/// # Errors
///
/// Returns an error if the value contains NaN or Infinity floats.
pub fn canonicalize(value: &Value) -> Result<String, Error> {
    canonicalize_value(value)
}

fn canonicalize_value(value: &Value) -> Result<String, Error> {
    match value {
        Value::Null => Ok("null".to_string()),
        Value::Bool(b) => Ok(if *b { "true" } else { "false" }.to_string()),
        Value::Number(n) => canonicalize_number(n),
        Value::String(s) => Ok(canonicalize_string(s)),
        Value::Array(arr) => canonicalize_array(arr),
        Value::Object(obj) => canonicalize_object(obj),
    }
}

/// Canonicalize an object with keys sorted by UTF-16 code units.
fn canonicalize_object(obj: &serde_json::Map<String, Value>) -> Result<String, Error> {
    // Sort keys by UTF-16 code units (Rust's default string comparison works for this)
    let mut keys: Vec<&String> = obj.keys().collect();
    keys.sort_by(|a, b| {
        // Compare by UTF-16 code units
        let a_units: Vec<u16> = a.encode_utf16().collect();
        let b_units: Vec<u16> = b.encode_utf16().collect();
        a_units.cmp(&b_units)
    });

    let mut result = String::from("{");
    let mut first = true;

    for key in keys {
        if !first {
            result.push(',');
        }
        first = false;

        result.push_str(&canonicalize_string(key));
        result.push(':');
        result.push_str(&canonicalize_value(&obj[key])?);
    }

    result.push('}');
    Ok(result)
}

/// Canonicalize an array.
fn canonicalize_array(arr: &[Value]) -> Result<String, Error> {
    let mut result = String::from("[");
    let mut first = true;

    for item in arr {
        if !first {
            result.push(',');
        }
        first = false;
        result.push_str(&canonicalize_value(item)?);
    }

    result.push(']');
    Ok(result)
}

/// Escape and quote a string according to JSON spec with minimal escaping.
///
/// Only escapes characters that MUST be escaped per JSON spec:
/// - Control characters (U+0000 to U+001F)
/// - Backslash and double quote
fn canonicalize_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 2);
    result.push('"');

    for ch in s.chars() {
        match ch {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\u{0008}' => result.push_str("\\b"),  // backspace
            '\u{0009}' => result.push_str("\\t"),  // tab
            '\u{000A}' => result.push_str("\\n"),  // newline
            '\u{000C}' => result.push_str("\\f"),  // form feed
            '\u{000D}' => result.push_str("\\r"),  // carriage return
            c if c < '\u{0020}' => {
                // Other control characters
                use std::fmt::Write;
                write!(result, "\\u{:04x}", c as u32).ok();
            }
            c => result.push(c),
        }
    }

    result.push('"');
    result
}

/// Canonicalize a number using shortest representation per RFC 8785.
fn canonicalize_number(n: &serde_json::Number) -> Result<String, Error> {
    // Handle integers
    if let Some(i) = n.as_i64() {
        return Ok(i.to_string());
    }
    if let Some(u) = n.as_u64() {
        return Ok(u.to_string());
    }

    // Handle floats
    if let Some(f) = n.as_f64() {
        if f.is_nan() || f.is_infinite() {
            return Err(Error::Canonicalization(format!(
                "Cannot canonicalize {f}: not valid JSON"
            )));
        }

        // Handle negative zero
        if f == 0.0 {
            return Ok("0".to_string());
        }

        // Use the shortest representation
        // serde_json already produces a good representation, but we need to ensure
        // it matches RFC 8785 requirements
        Ok(format_float(f))
    } else {
        Err(Error::Canonicalization(
            "Number is neither integer nor float".to_string(),
        ))
    }
}

/// Format a float using the shortest representation per RFC 8785.
fn format_float(f: f64) -> String {
    // Try standard representation first
    let standard = format!("{f}");

    // If it doesn't contain a decimal point or exponent, it's an integer representation
    if !standard.contains('.') && !standard.contains('e') && !standard.contains('E') {
        return standard;
    }

    // For very small or very large numbers, use exponential notation if shorter
    let abs = f.abs();
    if abs != 0.0 && !(1e-6..1e21).contains(&abs) {
        let exp = format!("{f:e}");
        // Clean up exponential notation (remove leading zeros in exponent)
        let exp_clean = clean_exponential(&exp);
        if exp_clean.len() < standard.len() {
            return exp_clean;
        }
    }

    // Remove trailing zeros after decimal point
    clean_decimal(&standard)
}

/// Clean up decimal representation by removing unnecessary trailing zeros.
fn clean_decimal(s: &str) -> String {
    if let Some(dot_pos) = s.find('.') {
        let mut result = s.to_string();
        // Remove trailing zeros
        while result.ends_with('0') && result.len() > dot_pos + 2 {
            result.pop();
        }
        // Remove trailing decimal point if no fractional part
        if result.ends_with('.') {
            result.pop();
        }
        result
    } else {
        s.to_string()
    }
}

/// Clean up exponential notation.
fn clean_exponential(s: &str) -> String {
    // Split on 'e' or 'E'
    let parts: Vec<&str> = s.split(['e', 'E']).collect();
    if parts.len() != 2 {
        return s.to_string();
    }

    let mantissa = clean_decimal(parts[0]);
    let exp_str = parts[1];

    // Parse exponent and format without leading zeros
    if let Ok(exp) = exp_str.parse::<i32>() {
        if exp >= 0 {
            format!("{mantissa}e+{exp}")
        } else {
            format!("{mantissa}e{exp}")
        }
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_null() {
        assert_eq!(canonicalize(&json!(null)).unwrap(), "null");
    }

    #[test]
    fn test_booleans() {
        assert_eq!(canonicalize(&json!(true)).unwrap(), "true");
        assert_eq!(canonicalize(&json!(false)).unwrap(), "false");
    }

    #[test]
    fn test_integers() {
        assert_eq!(canonicalize(&json!(42)).unwrap(), "42");
        assert_eq!(canonicalize(&json!(-100)).unwrap(), "-100");
        assert_eq!(canonicalize(&json!(0)).unwrap(), "0");
    }

    #[test]
    fn test_strings() {
        assert_eq!(canonicalize(&json!("hello")).unwrap(), "\"hello\"");
        assert_eq!(canonicalize(&json!("")).unwrap(), "\"\"");
        assert_eq!(
            canonicalize(&json!("with \"quotes\"")).unwrap(),
            "\"with \\\"quotes\\\"\""
        );
    }

    #[test]
    fn test_string_escaping() {
        assert_eq!(canonicalize(&json!("a\nb")).unwrap(), "\"a\\nb\"");
        assert_eq!(canonicalize(&json!("a\tb")).unwrap(), "\"a\\tb\"");
        assert_eq!(canonicalize(&json!("a\\b")).unwrap(), "\"a\\\\b\"");
    }

    #[test]
    fn test_arrays() {
        assert_eq!(canonicalize(&json!([])).unwrap(), "[]");
        assert_eq!(canonicalize(&json!([1, 2, 3])).unwrap(), "[1,2,3]");
        assert_eq!(
            canonicalize(&json!(["a", "b"])).unwrap(),
            "[\"a\",\"b\"]"
        );
    }

    #[test]
    fn test_objects_sorted_keys() {
        let obj = json!({"b": 2, "a": 1});
        assert_eq!(canonicalize(&obj).unwrap(), "{\"a\":1,\"b\":2}");
    }

    #[test]
    fn test_nested_objects() {
        let obj = json!({"outer": {"inner": 1}});
        assert_eq!(
            canonicalize(&obj).unwrap(),
            "{\"outer\":{\"inner\":1}}"
        );
    }

    #[test]
    fn test_no_whitespace() {
        let obj = json!({"a": 1, "b": [1, 2, 3], "c": {"nested": true}});
        let canonical = canonicalize(&obj).unwrap();
        // Should not contain spaces outside of strings
        assert!(!canonical.contains(" "));
    }

    #[test]
    fn test_negative_zero() {
        // -0.0 should become "0"
        let val: Value = serde_json::from_str("-0.0").unwrap();
        assert_eq!(canonicalize(&val).unwrap(), "0");
    }
}
