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
    for marker in ["password=", "passwd=", "token=", "secret=", "Authorization:"] {
        let mut cursor = 0;
        while let Some(marker_start) = find_ascii_case_insensitive(&result, marker, cursor) {
            let mut value_start = marker_start + marker.len();
            while result.as_bytes().get(value_start).is_some_and(|b| b.is_ascii_whitespace()) {
                value_start += 1;
            }
            let end = if result.as_bytes().get(value_start) == Some(&b'\'') || result.as_bytes().get(value_start) == Some(&b'"') {
                let quote = result.as_bytes()[value_start];
                let mut index = value_start + 1;
                while index < result.len() {
                    if result.as_bytes()[index] == quote && result.as_bytes().get(index.saturating_sub(1)) != Some(&b'\\') {
                        index += 1;
                        break;
                    }
                    index += 1;
                }
                index
            } else if marker.eq_ignore_ascii_case("Authorization:") {
                result[value_start..]
                    .char_indices()
                    .find(|(_, c)| *c == '\r' || *c == '\n' || *c == '&' || *c == ';')
                    .map(|(offset, _)| value_start + offset)
                    .unwrap_or(result.len())
            } else {
                result[value_start..]
                    .char_indices()
                    .find(|(_, c)| c.is_whitespace() || *c == '&' || *c == ';')
                    .map(|(offset, _)| value_start + offset)
                    .unwrap_or(result.len())
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
}
