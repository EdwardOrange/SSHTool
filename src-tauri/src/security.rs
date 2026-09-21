use crate::error::{AppError, AppResult};

const SERVICE: &str = "com.sshoperations.terminal";

pub fn store_secret(id: &str, value: &str) -> AppResult<()> { keyring::Entry::new(SERVICE, id).map_err(|e| AppError::Other(e.to_string()))?.set_password(value).map_err(|e| AppError::Other(format!("Credential Manager 写入失败：{e}"))) }
pub fn read_secret(id: &str) -> AppResult<String> { keyring::Entry::new(SERVICE, id).map_err(|e| AppError::Other(e.to_string()))?.get_password().map_err(|e| AppError::NotFound(format!("凭据 {id}：{e}"))) }
pub fn delete_secret(id: &str) -> AppResult<()> { keyring::Entry::new(SERVICE, id).map_err(|e| AppError::Other(e.to_string()))?.delete_credential().map_err(|e| AppError::Other(e.to_string())) }

pub fn redact(input: &str) -> String {
    // Search only with ASCII case folding. `str::to_lowercase()` can expand a
    // Unicode scalar to multiple bytes, making the resulting byte offsets
    // invalid for `replace_range` (and causing the audit task to panic).
    let mut result = input.to_owned();
    for name in ["password", "passwd", "token", "secret", "access_token", "refresh_token", "api_key", "access-token", "refresh-token", "api-key"] {
        // Common CLI spellings use a separate argument instead of '='.
        // Only match a complete option, so --password-file is not mistaken
        // for a secret argument.
        let marker = format!("--{name}");
        let mut cursor = 0;
        while let Some(start) = find_ascii_case_insensitive(&result, &marker, cursor) {
            let after = start + marker.len();
            cursor = after;
            if !result.as_bytes().get(after).is_some_and(u8::is_ascii_whitespace) { continue; }
            let mut value_start = after;
            while result.as_bytes().get(value_start).is_some_and(u8::is_ascii_whitespace) { value_start += 1; }
            let end = shell_value_end(&result, value_start);
            if end > value_start {
                result.replace_range(value_start..end, "[REDACTED]");
                cursor = value_start + "[REDACTED]".len();
            }
        }
        // JSON responses and request bodies are also common in command logs.
        // Preserve quotes and the rest of the object instead of accidentally
        // retaining the secret or masking all subsequent fields.
        let marker = format!("\"{name}\"");
        cursor = 0;
        while let Some(start) = find_ascii_case_insensitive(&result, &marker, cursor) {
            let mut value_start = start + marker.len();
            cursor = value_start;
            while result.as_bytes().get(value_start).is_some_and(u8::is_ascii_whitespace) { value_start += 1; }
            if result.as_bytes().get(value_start) != Some(&b':') { continue; }
            value_start += 1;
            while result.as_bytes().get(value_start).is_some_and(u8::is_ascii_whitespace) { value_start += 1; }
            let end = json_value_end(&result, value_start);
            if end > value_start {
                result.replace_range(value_start..end, "\"[REDACTED]\"");
                cursor = value_start + "\"[REDACTED]\"".len();
            }
        }
    }
    for marker in ["password=", "passwd=", "token=", "secret=", "api_key=", "api-key=", "Authorization:"] {
        let mut cursor = 0;
        while let Some(marker_start) = find_ascii_case_insensitive(&result, marker, cursor) {
            let mut value_start = marker_start + marker.len();
            while result.as_bytes().get(value_start).is_some_and(|b| b.is_ascii_whitespace()) {
                value_start += 1;
            }
            let end = if marker.eq_ignore_ascii_case("Authorization:") {
                result[value_start..]
                    .char_indices()
                    .find(|(_, c)| *c == '\r' || *c == '\n' || *c == '&' || *c == ';')
                    .map(|(offset, _)| value_start + offset)
                    .unwrap_or(result.len())
            } else {
                shell_value_end(&result, value_start)
            };
            if value_start >= end {
                cursor = marker_start + marker.len();
                continue;
            }
            result.replace_range(value_start..end, "[REDACTED]");
            cursor = value_start + "[REDACTED]".len();
        }
    }
    result
}

fn json_value_end(input: &str, start: usize) -> usize {
    // A credential can itself be an object or an array. Parse one complete
    // value, including escaped strings and nested structures, without needing
    // the surrounding command/output to be a JSON document. If the value is
    // truncated or malformed, mask the rest rather than exposing its tail.
    let mut values = serde_json::Deserializer::from_str(&input[start..]).into_iter::<serde_json::Value>();
    if matches!(values.next(), Some(Ok(_))) {
        start + values.byte_offset()
    } else {
        input.len()
    }
}

fn shell_value_end(input: &str, start: usize) -> usize {
    // Shell values can concatenate quoted and unquoted segments, including
    // the standard 'first'\''second' spelling produced by shell_quote().
    // Stopping at the first closing quote leaks the rest of that secret.
    let bytes = input.as_bytes();
    let mut quote = None;
    let mut index = start;
    while index < bytes.len() {
        let byte = bytes[index];
        match quote {
            Some(b'\'') => { if byte == b'\'' { quote = None; } }
            Some(b'"') => {
                if byte == b'"' { quote = None; }
                else if byte == b'\\' { index = (index + 1).min(bytes.len()); }
            }
            _ => {
                if byte.is_ascii_whitespace() || matches!(byte, b'&' | b';' | b'|') { break; }
                if matches!(byte, b'\'' | b'"') { quote = Some(byte); }
                else if byte == b'\\' { index = (index + 1).min(bytes.len()); }
            }
        }
        index += 1;
    }
    index.min(bytes.len())
}

fn find_ascii_case_insensitive(haystack: &str, needle: &str, from: usize) -> Option<usize> {
    if needle.is_empty() || from > haystack.len() {
        return None;
    }
    let bytes = haystack.as_bytes();
    let needle = needle.as_bytes();
    bytes[from..].windows(needle.len()).position(|window| {
        window.iter().zip(needle).all(|(left, right)| left.eq_ignore_ascii_case(right))
    }).map(|offset| from + offset)
}
pub fn shell_quote(value: &str) -> AppResult<String> { if value.contains('\0') || value.contains('\n') || value.contains('\r') { return Err(AppError::Validation("值中包含禁止的控制字符".into())); } Ok(format!("'{}'", value.replace('\'', "'\\''"))) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_shell_values() { assert_eq!(shell_quote("a'b").unwrap(), "'a'\\''b'"); }

    #[test]
    fn rejects_newlines() { assert!(shell_quote("a\nb").is_err()); }

    #[test]
    fn redacts_secrets_without_unicode_panics() {
        assert!(!redact("password=hunter2 token=abc").contains("hunter2"));
        assert_eq!(redact("Authorization: Bearer TEST_TOKEN"), "Authorization: [REDACTED]");
        assert_eq!(redact("password='TEST VALUE'"), "password=[REDACTED]");
        assert!(!redact("İİİtoken=x").contains("=x"));
    }

    #[test]
    fn redacts_entire_shell_values_including_escaped_and_concatenated_segments() {
        assert_eq!(redact(r#"password='first'\''second' next=public"#), "password=[REDACTED] next=public");
        assert_eq!(redact(r#"token="first"second; echo done"#), "token=[REDACTED]; echo done");
        assert_eq!(redact(r#"secret=first\ second | cat"#), "secret=[REDACTED] | cat");
        assert_eq!(redact("token='中文'后缀&echo ok"), "token=[REDACTED]&echo ok");
        assert_eq!(redact(r#"password="ends\\" next=public"#), "password=[REDACTED] next=public");
        assert_eq!(redact("token=value\\"), "token=[REDACTED]");
    }

    #[test]
    fn redacts_cli_and_json_credentials_and_preserves_public_fields() {
        assert_eq!(redact("client --password '中文 secret' --token abc --password-file key.txt"),
            "client --password [REDACTED] --token [REDACTED] --password-file key.txt");
        let input = r#"{"password" : "first\"second", "token":"中文", "api_key":1234, "public":"kept"}"#;
        let result = redact(input);
        let value: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(value["password"], "[REDACTED]");
        assert_eq!(value["token"], "[REDACTED]");
        assert_eq!(value["api_key"], "[REDACTED]");
        assert_eq!(value["public"], "kept");
        assert_eq!(redact(&result), result);
        assert_eq!(redact("client --api-key cli-secret api_key=assignment-secret --refresh-token refresh-secret"),
            "client --api-key [REDACTED] api_key=[REDACTED] --refresh-token [REDACTED]");
    }

    #[test]
    fn redacts_complete_nested_json_secrets_and_fails_closed_for_malformed_values() {
        let input = r#"{"secret":{"a":"first","b":["second",{"c":"third"}]},"token":["fourth",["fifth"]],"public":"kept"}"#;
        let redacted = redact(input);
        let value: serde_json::Value = serde_json::from_str(&redacted).unwrap();
        assert_eq!(value, serde_json::json!({"secret":"[REDACTED]","token":"[REDACTED]","public":"kept"}));
        for input in [r#"{"secret":{"a":"first","b":"second""#, r#"{"secret":["first",malformed,"second"]}"#] {
            let redacted = redact(input);
            assert!(!redacted.contains("first"));
            assert!(!redacted.contains("second"));
            assert!(redacted.contains("[REDACTED]"));
        }
    }
}
