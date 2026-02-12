use crate::safe_codex::config::{Config, EngineConfig};
use crate::safe_codex::evaluator::command_exists;
use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub ok: bool,
    pub checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize)]
pub struct DoctorCheck {
    pub name: String,
    pub ok: bool,
    pub details: String,
}

pub fn run(config: &Config) -> Result<DoctorReport> {
    let mut checks = Vec::new();

    checks.push(DoctorCheck {
        name: "config-version".to_string(),
        ok: config.version == 1,
        details: format!("version={}", config.version),
    });

    checks.push(DoctorCheck {
        name: "audit-log-path".to_string(),
        ok: true,
        details: format!("{}", config.audit.log_path.display()),
    });

    for engine in &config.engines {
        match engine {
            EngineConfig::ClaudeHooks { enabled, hooks_dir } => {
                let ok = !enabled || hooks_dir.exists();
                checks.push(DoctorCheck {
                    name: "engine-claude-hooks".to_string(),
                    ok,
                    details: format!(
                        "enabled={}, hooks_dir={}{}",
                        enabled,
                        hooks_dir.display(),
                        if *enabled && !ok {
                            " (missing hooks dir)"
                        } else {
                            ""
                        }
                    ),
                });
            }
            EngineConfig::Dcg { enabled, cmd, .. } => {
                let ok = !enabled || command_exists(cmd);
                checks.push(DoctorCheck {
                    name: "engine-dcg".to_string(),
                    ok,
                    details: format!(
                        "enabled={}, cmd={}{}",
                        enabled,
                        cmd,
                        if *enabled && !ok {
                            " (command not found)"
                        } else {
                            ""
                        }
                    ),
                });
            }
            EngineConfig::Native { enabled, rules } => {
                let ok = !enabled || !rules.is_empty();
                checks.push(DoctorCheck {
                    name: "engine-native".to_string(),
                    ok,
                    details: format!("enabled={}, rules={}", enabled, rules.len()),
                });
            }
            EngineConfig::LocalHooks {
                enabled,
                pre_command,
                post_command,
            } => {
                let mut ok = true;
                if *enabled {
                    if let Some(pre) = pre_command {
                        if !pre.exists() {
                            ok = false;
                        }
                    }
                    if let Some(post) = post_command {
                        if !post.exists() {
                            ok = false;
                        }
                    }
                }
                checks.push(DoctorCheck {
                    name: "engine-local-hooks".to_string(),
                    ok,
                    details: format!(
                        "enabled={enabled}, pre={pre_command:?}, post={post_command:?}"
                    ),
                });
            }
        }
    }

    Ok(DoctorReport {
        ok: checks.iter().all(|check| check.ok),
        checks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::safe_codex::config::{AuditConfig, CombineConfig, Mode};
    use std::path::PathBuf;

    #[test]
    fn doctor_fails_when_enabled_claude_hooks_dir_missing() {
        let config = Config {
            version: 1,
            mode: Mode::Enforce,
            engines: vec![EngineConfig::ClaudeHooks {
                enabled: true,
                hooks_dir: PathBuf::from("/definitely/missing/path"),
            }],
            combine: CombineConfig::default(),
            audit: AuditConfig {
                log_path: PathBuf::from(".safe-codex-log.jsonl"),
            },
        };

        let report = run(&config).expect("doctor should return report");
        assert!(!report.ok);
        assert_eq!(report.checks[2].name, "engine-claude-hooks");
    }
}
