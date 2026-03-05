use crate::hooky::decision::Decision;
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

/// Delete all audit log entries with a date before today (UTC).
/// Returns the number of entries removed.
pub fn clean_before_today(path: &Path) -> Result<usize> {
    if !path.exists() {
        return Ok(0);
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let today = Utc::now().date_naive();
    let mut kept: Vec<&str> = Vec::new();
    let mut removed = 0usize;

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let keep = serde_json::from_str::<serde_json::Value>(line)
            .ok()
            .and_then(|v| v.get("timestamp")?.as_str().map(str::to_owned))
            .and_then(|ts| ts.parse::<chrono::DateTime<Utc>>().ok())
            .is_none_or(|ts| ts.date_naive() >= today);

        if keep {
            kept.push(line);
        } else {
            removed += 1;
        }
    }

    let new_content = if kept.is_empty() {
        String::new()
    } else {
        let mut s = kept.join("\n");
        s.push('\n');
        s
    };

    std::fs::write(path, new_content)
        .with_context(|| format!("failed to write {}", path.display()))?;

    Ok(removed)
}
