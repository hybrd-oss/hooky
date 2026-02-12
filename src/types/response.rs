use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Serialize)]
pub struct CliResponse<T: Serialize> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub timestamp: DateTime<Utc>,
}

impl<T: Serialize> CliResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            data: Some(data),
            error: None,
            timestamp: Utc::now(),
        }
    }
}

impl CliResponse<()> {
    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            data: None,
            error: Some(msg.into()),
            timestamp: Utc::now(),
        }
    }
}
