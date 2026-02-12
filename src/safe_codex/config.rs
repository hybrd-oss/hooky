use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default = "default_engines")]
    pub engines: Vec<EngineConfig>,
    #[serde(default)]
    pub combine: CombineConfig,
    #[serde(default)]
    pub audit: AuditConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Enforce,
    Audit,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EngineConfig {
    ClaudeHooks {
        #[serde(default = "default_true")]
        enabled: bool,
        #[serde(default = "default_claude_hooks_dir")]
        hooks_dir: PathBuf,
    },
    Dcg {
        #[serde(default)]
        enabled: bool,
        #[serde(default = "default_dcg_cmd")]
        cmd: String,
        #[serde(default)]
        args: Vec<String>,
    },
    Native {
        #[serde(default = "default_true")]
        enabled: bool,
        #[serde(default)]
        rules: Vec<NativeRule>,
    },
    LocalHooks {
        #[serde(default)]
        enabled: bool,
        pre_command: Option<PathBuf>,
        post_command: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NativeRule {
    pub id: String,
    pub action: NativeAction,
    pub pattern: String,
    pub rewrite: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeAction {
    Block,
    Rewrite,
    Confirm,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CombineConfig {
    #[serde(default)]
    pub rewrite_mode: RewriteMode,
}

impl Default for CombineConfig {
    fn default() -> Self {
        Self {
            rewrite_mode: RewriteMode::First,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RewriteMode {
    #[default]
    First,
    Chain,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuditConfig {
    #[serde(default = "default_audit_path")]
    pub log_path: PathBuf,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_path: default_audit_path(),
        }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let effective_path = path.unwrap_or_else(|| Path::new(".safe-codex.yml"));

        if !effective_path.exists() {
            return Ok(Self::default());
        }

        let raw = fs::read_to_string(effective_path).with_context(|| {
            format!(
                "failed to read safe-codex config at {}",
                effective_path.display()
            )
        })?;

        let parsed: Self = serde_yaml::from_str(&raw).with_context(|| {
            format!(
                "failed to parse safe-codex config at {}",
                effective_path.display()
            )
        })?;

        Ok(parsed.with_defaults_applied())
    }

    #[must_use]
    pub fn with_defaults_applied(mut self) -> Self {
        if self.engines.is_empty() {
            self.engines = default_engines();
        }

        for engine in &mut self.engines {
            if let EngineConfig::Native { rules, .. } = engine {
                if rules.is_empty() {
                    *rules = default_native_rules();
                }
            }
        }

        self
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: default_version(),
            mode: Mode::Enforce,
            engines: default_engines(),
            combine: CombineConfig::default(),
            audit: AuditConfig::default(),
        }
    }
}

fn default_version() -> u32 {
    1
}

fn default_true() -> bool {
    true
}

fn default_dcg_cmd() -> String {
    "dcg".to_string()
}

fn default_claude_hooks_dir() -> PathBuf {
    PathBuf::from(".claude/hooks")
}

fn default_audit_path() -> PathBuf {
    PathBuf::from(".safe-codex-log.jsonl")
}

fn default_engines() -> Vec<EngineConfig> {
    vec![
        EngineConfig::ClaudeHooks {
            enabled: true,
            hooks_dir: default_claude_hooks_dir(),
        },
        EngineConfig::Dcg {
            enabled: false,
            cmd: default_dcg_cmd(),
            args: Vec::new(),
        },
        EngineConfig::Native {
            enabled: true,
            rules: default_native_rules(),
        },
        EngineConfig::LocalHooks {
            enabled: false,
            pre_command: None,
            post_command: None,
        },
    ]
}

fn default_native_rules() -> Vec<NativeRule> {
    vec![
        NativeRule {
            id: "block-no-verify".to_string(),
            action: NativeAction::Block,
            pattern: r"(--no-verify|--no-gpg-sign|-n\b.*commit)".to_string(),
            rewrite: None,
        },
        NativeRule {
            id: "block-skip-env".to_string(),
            action: NativeAction::Block,
            pattern: r"^\s*SKIP=".to_string(),
            rewrite: None,
        },
        NativeRule {
            id: "block-force-push".to_string(),
            action: NativeAction::Block,
            pattern: r"\bgit\s+push\b.*\s--force(\s|$)".to_string(),
            rewrite: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_expected_engine_order() {
        let config = Config::default();
        assert_eq!(config.engines.len(), 4);

        assert!(matches!(
            config.engines[0],
            EngineConfig::ClaudeHooks { .. }
        ));
        assert!(matches!(config.engines[1], EngineConfig::Dcg { .. }));
        assert!(matches!(config.engines[2], EngineConfig::Native { .. }));
        assert!(matches!(config.engines[3], EngineConfig::LocalHooks { .. }));
    }

    #[test]
    fn empty_native_rules_are_filled_with_defaults() {
        let config = Config {
            version: 1,
            mode: Mode::Enforce,
            engines: vec![EngineConfig::Native {
                enabled: true,
                rules: Vec::new(),
            }],
            combine: CombineConfig::default(),
            audit: AuditConfig::default(),
        }
        .with_defaults_applied();

        match &config.engines[0] {
            EngineConfig::Native { rules, .. } => {
                assert!(!rules.is_empty());
            },
            _ => panic!("expected native engine"),
        }
    }
}
