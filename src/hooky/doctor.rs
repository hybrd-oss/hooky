use crate::hooky::config::{Config, EngineConfig};
use crate::hooky::evaluator::command_exists;
use anyhow::Result;
use serde::Serialize;

fn format_size(bytes: u64) -> String {
    if bytes < 1_024 {
        format!("{bytes}B")
    } else if bytes < 1_024 * 1_024 {
        #[allow(clippy::cast_precision_loss)]
        let kb = bytes as f64 / 1_024.0;
        format!("{kb:.1}KB")
    } else {
        #[allow(clippy::cast_precision_loss)]
        let mb = bytes as f64 / (1_024.0 * 1_024.0);
        format!("{mb:.1}MB")
    }
}

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

    let log_size = std::fs::metadata(&config.audit.log_path)
        .map_or_else(|_| "not found".to_string(), |m| format_size(m.len()));
    checks.push(DoctorCheck {
        name: "audit-log-path".to_string(),
        ok: true,
        details: format!("{} ({})", config.audit.log_path.display(), log_size),
    });

    for engine in &config.engines {
        match engine {
            EngineConfig::ClaudeHooks {
                enabled,
                hooks_dirs,
            } => {
                let all_missing = hooks_dirs.iter().all(|d| !d.exists());
                checks.push(DoctorCheck {
                    name: "engine-claude-hooks".to_string(),
                    details: format!(
                        "enabled={}, hooks_dirs=[{}]{}",
                        enabled,
                        hooks_dirs
                            .iter()
                            .map(|d| d.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", "),
                        if *enabled && all_missing {
                            " (no hooks dirs found; engine will be skipped)"
                        } else {
                            ""
                        }
                    ),
                    // Missing Claude hooks should not fail doctor:
                    // evaluator treats absent hook scripts as no-op.
                    ok: true,
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
                            " (command not found — install DCG: curl -fsSL \"https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/install.sh?$(date +%s)\" | bash -s -- --easy-mode)"
                        } else {
                            ""
                        }
                    ),
                });
            }
            EngineConfig::Native { enabled, rules, .. } => {
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
    use crate::hooky::config::{AuditConfig, CombineConfig, Mode};
    use std::path::PathBuf;

    #[test]
    fn doctor_allows_when_enabled_claude_hooks_dirs_all_missing() {
        let config = Config {
            version: 1,
            mode: Mode::Enforce,
            shims: crate::hooky::config::ShimsConfig::default(),
            engines: vec![EngineConfig::ClaudeHooks {
                enabled: true,
                hooks_dirs: vec![
                    PathBuf::from("/definitely/missing/path"),
                    PathBuf::from("/also/missing"),
                ],
            }],
            combine: CombineConfig::default(),
            audit: AuditConfig {
                log_path: PathBuf::from(".hooky/.hooky-log.jsonl"),
            },
        };

        let report = run(&config).expect("doctor should return report");
        assert!(report.ok);
        assert_eq!(report.checks[2].name, "engine-claude-hooks");
        assert!(report.checks[2].details.contains("engine will be skipped"));
        assert!(report.checks[2]
            .details
            .contains("/definitely/missing/path"));
        assert!(report.checks[2].details.contains("/also/missing"));
    }

    #[test]
    fn doctor_shows_all_hooks_dirs_in_details() {
        let config = Config {
            version: 1,
            mode: Mode::Enforce,
            shims: crate::hooky::config::ShimsConfig::default(),
            engines: vec![EngineConfig::ClaudeHooks {
                enabled: true,
                hooks_dirs: vec![
                    PathBuf::from("/first/hooks"),
                    PathBuf::from("/second/hooks"),
                ],
            }],
            combine: CombineConfig::default(),
            audit: AuditConfig {
                log_path: PathBuf::from(".hooky/.hooky-log.jsonl"),
            },
        };

        let report = run(&config).expect("doctor should return report");
        let check = &report.checks[2];
        assert_eq!(check.name, "engine-claude-hooks");
        assert!(check.details.contains("hooks_dirs=["));
        assert!(check.details.contains("/first/hooks"));
        assert!(check.details.contains("/second/hooks"));
    }
}
