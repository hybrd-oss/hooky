use crate::safe_codex::decision::Decision;
use anyhow::{Context, Result};
use chrono::Utc;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct AuditEvent {
    pub timestamp: chrono::DateTime<Utc>,
    pub event: String,
    pub command: String,
    pub decision: Decision,
}

pub fn append_event(path: &Path, event: &AuditEvent) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open audit log at {}", path.display()))?;

    let line = serde_json::to_string(event).context("failed to serialize audit event")?;
    writeln!(file, "{line}").context("failed to append audit event")?;
    Ok(())
}
