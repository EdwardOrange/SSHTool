use crate::error::{AppError, AppResult};

const SERVICE: &str = "com.sshoperations.terminal";

pub fn store_secret(id: &str, value: &str) -> AppResult<()> {
    keyring::Entry::new(SERVICE, id)
        .map_err(|e| AppError::Other(e.to_string()))?
        .set_password(value)
        .map_err(|e| AppError::Other(format!("Credential Manager 写入失败：{e}")))
}

pub fn read_secret(id: &str) -> AppResult<String> {
    keyring::Entry::new(SERVICE, id)
        .map_err(|e| AppError::Other(e.to_string()))?
        .get_password()
        .map_err(|e| AppError::NotFound(format!("凭据 {id}：{e}")))
}

pub fn delete_secret(id: &str) -> AppResult<()> {
    keyring::Entry::new(SERVICE, id)
        .map_err(|e| AppError::Other(e.to_string()))?
        .delete_credential()
        .map_err(|e| AppError::Other(e.to_string()))
}

pub fn redact(input: &str) -> String {
    let mut result = input.to_string();
    for marker in [
        "password=",
        "passwd=",
        "token=",
        "secret=",
        "Authorization:",
    ] {
        while let Some(pos) = result.to_lowercase().find(&marker.to_lowercase()) {
            let start = pos + marker.len();
            let end = result[start..]
                .find(|c: char| c.is_whitespace() || c == '&' || c == ';')
                .map(|i| start + i)
                .unwrap_or(result.len());
            result.replace_range(start..end, "••••••••");
        }
    }
    result
}

pub fn shell_quote(value: &str) -> AppResult<String> {
    if value.contains('\0') || value.contains('\n') || value.contains('\r') {
        return Err(AppError::Validation("值中包含禁止的控制字符".into()));
    }
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quotes_shell_values() {
        assert_eq!(shell_quote("a'b").unwrap(), "'a'\\''b'");
    }
    #[test]
    fn rejects_newlines() {
        assert!(shell_quote("a\nb").is_err());
    }
    #[test]
    fn redacts_secrets() {
        assert!(!redact("password=hunter2 token=abc").contains("hunter2"));
    }
}
