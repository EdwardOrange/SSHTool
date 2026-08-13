use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("数据库错误：{0}")]
    Database(#[from] rusqlite::Error),
    #[error("SSH 错误：{0}")]
    Ssh(String),
    #[error("I/O 错误：{0}")]
    Io(#[from] std::io::Error),
    #[error("无效输入：{0}")]
    Validation(String),
    #[error("未找到：{0}")]
    NotFound(String),
    #[error("权限不足：{0}")]
    Permission(String),
    #[error("需要 sudo 密码")]
    SudoRequired,
    #[error("操作状态已变化，请重新生成计划")]
    StalePlan,
    #[error("{0}")]
    Other(String),
}

impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Payload<'a> {
            kind: &'a str,
            message: String,
        }
        let kind = match self {
            Self::Database(_) => "database",
            Self::Ssh(_) => "ssh",
            Self::Io(_) => "io",
            Self::Validation(_) => "validation",
            Self::NotFound(_) => "notFound",
            Self::Permission(_) => "permission",
            Self::SudoRequired => "sudoRequired",
            Self::StalePlan => "stalePlan",
            Self::Other(_) => "other",
        };
        Payload {
            kind,
            message: self.to_string(),
        }
        .serialize(serializer)
    }
}

pub type AppResult<T> = Result<T, AppError>;
