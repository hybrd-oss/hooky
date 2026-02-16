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
    #[serde(default)]
    pub shims: ShimsConfig,
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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MergeStrategy {
    #[default]
    Extend,
    Replace,
    Prepend,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ShimsConfig {
    #[serde(default = "default_shim_commands")]
    pub commands: Vec<String>,
}

impl Default for ShimsConfig {
    fn default() -> Self {
        Self {
            commands: default_shim_commands(),
        }
    }
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
        #[serde(default)]
        config: Option<PathBuf>,
        #[serde(default)]
        with_packs: Vec<String>,
        #[serde(default)]
        explain: bool,
    },
    Native {
        #[serde(default = "default_true")]
        enabled: bool,
        #[serde(default)]
        rules: Vec<NativeRule>,
        #[serde(default)]
        merge_strategy: MergeStrategy,
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
        let effective_path = path.unwrap_or_else(|| Path::new(".hooky.yml"));

        if !effective_path.exists() {
            return Ok(Self::default());
        }

        let raw = fs::read_to_string(effective_path).with_context(|| {
            format!(
                "failed to read hooky config at {}",
                effective_path.display()
            )
        })?;

        let parsed: Self = serde_yaml::from_str(&raw).with_context(|| {
            format!(
                "failed to parse hooky config at {}",
                effective_path.display()
            )
        })?;

        let base_dir = effective_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));

        Ok(parsed
            .with_defaults_applied()
            .resolve_relative_paths(base_dir))
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

    /// Load global configuration from ~/.hooky/config.yml
    pub fn load_global() -> Result<Option<Self>> {
        let global_path = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("failed to determine home directory"))?
            .join(".hooky")
            .join("config.yml");

        if !global_path.exists() {
            return Ok(None);
        }

        let config = Self::load(Some(&global_path))?;
        Ok(Some(config))
    }

    /// Load local configuration from project directory
    pub fn load_local(path: Option<&Path>) -> Result<Option<Self>> {
        let local_path = path.unwrap_or_else(|| Path::new(".hooky.yml"));

        if !local_path.exists() {
            return Ok(None);
        }

        let config = Self::load(Some(local_path))?;
        Ok(Some(config))
    }

    /// Load and merge global and local configurations
    pub fn load_merged(project_path: Option<&Path>) -> Result<Self> {
        let global_config = Self::load_global()?;
        let local_config = Self::load_local(project_path)?;

        Ok(Self::merge(global_config, local_config))
    }

    /// Merge global and local configurations with precedence rules
    fn merge(global: Option<Self>, local: Option<Self>) -> Self {
        match (global, local) {
            (None, None) => Self::default(),
            (Some(g), None) => g,
            (None, Some(l)) => l,
            (Some(g), Some(l)) => merge_configs(&g, l),
        }
    }

    fn resolve_relative_paths(mut self, base_dir: &Path) -> Self {
        self.audit.log_path = resolve_path(&self.audit.log_path, base_dir);

        for engine in &mut self.engines {
            match engine {
                EngineConfig::ClaudeHooks { hooks_dir, .. } => {
                    *hooks_dir = resolve_path(hooks_dir, base_dir);
                }
                EngineConfig::Dcg { config, .. } => {
                    if let Some(path) = config.as_mut() {
                        *path = resolve_path(path, base_dir);
                    }
                }
                EngineConfig::LocalHooks {
                    pre_command,
                    post_command,
                    ..
                } => {
                    if let Some(path) = pre_command.as_mut() {
                        *path = resolve_path(path, base_dir);
                    }
                    if let Some(path) = post_command.as_mut() {
                        *path = resolve_path(path, base_dir);
                    }
                }
                EngineConfig::Native { .. } => {}
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
            shims: ShimsConfig::default(),
            engines: default_engines(),
            combine: CombineConfig::default(),
            audit: AuditConfig::default(),
        }
    }
}

/// Merge global and local configurations
fn merge_configs(global: &Config, local: Config) -> Config {
    Config {
        // Version: use local if set, otherwise global
        version: if local.version == default_version() {
            global.version
        } else {
            local.version
        },
        // Mode: local always overrides global
        mode: local.mode,
        // Shims: local overrides global (later we may want to merge these)
        shims: local.shims,
        // Engines: merge by type
        engines: merge_engines(&global.engines, &local.engines),
        // Combine: local overrides global
        combine: local.combine,
        // Audit: local always wins (logs stay project-local)
        audit: local.audit,
    }
}

/// Merge engine configurations by type
fn merge_engines(global: &[EngineConfig], local: &[EngineConfig]) -> Vec<EngineConfig> {
    let mut merged = Vec::new();

    // Process each engine type
    for engine_type in ["claude_hooks", "dcg", "native", "local_hooks"] {
        let global_engine = find_engine_by_type(global, engine_type);
        let local_engine = find_engine_by_type(local, engine_type);

        if let Some(engine) = merge_engine(global_engine, local_engine) {
            merged.push(engine);
        }
    }

    // If no engines were merged, use default engines
    if merged.is_empty() {
        default_engines()
    } else {
        merged
    }
}

/// Find an engine by its type name
fn find_engine_by_type<'a>(
    engines: &'a [EngineConfig],
    type_name: &str,
) -> Option<&'a EngineConfig> {
    engines.iter().find(|e| {
        matches!(
            (e, type_name),
            (EngineConfig::ClaudeHooks { .. }, "claude_hooks")
                | (EngineConfig::Dcg { .. }, "dcg")
                | (EngineConfig::Native { .. }, "native")
                | (EngineConfig::LocalHooks { .. }, "local_hooks")
        )
    })
}

/// Merge two engine configurations of the same type
fn merge_engine(
    global: Option<&EngineConfig>,
    local: Option<&EngineConfig>,
) -> Option<EngineConfig> {
    match (global, local) {
        (None, None) => None,
        (Some(g), None) => Some(g.clone()),
        (None, Some(l)) => Some(l.clone()),
        (Some(g), Some(l)) => Some(merge_same_engine(g, l)),
    }
}

/// Merge two engines of the same type
fn merge_same_engine(global: &EngineConfig, local: &EngineConfig) -> EngineConfig {
    match (global, local) {
        (
            EngineConfig::Native {
                enabled: _g_enabled,
                rules: g_rules,
                merge_strategy: _,
            },
            EngineConfig::Native {
                enabled: l_enabled,
                rules: l_rules,
                merge_strategy: l_strategy,
            },
        ) => {
            // For native engine, merge rules according to strategy
            let merged_rules = match l_strategy {
                MergeStrategy::Replace => l_rules.clone(),
                MergeStrategy::Extend => {
                    // Local rules first (higher precedence)
                    let mut rules = l_rules.clone();
                    rules.extend(g_rules.clone());
                    rules
                }
                MergeStrategy::Prepend => {
                    // Global rules first
                    let mut rules = g_rules.clone();
                    rules.extend(l_rules.clone());
                    rules
                }
            };

            EngineConfig::Native {
                enabled: *l_enabled,
                rules: merged_rules,
                merge_strategy: l_strategy.clone(),
            }
        }
        // For other engine types, local completely overrides global
        (_, l) => l.clone(),
    }
}

fn resolve_path(path: &Path, base_dir: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
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
    PathBuf::from(".hooky/.hooky-log.jsonl")
}

fn default_shim_commands() -> Vec<String> {
    vec![
        "git".to_string(),
        "rm".to_string(),
        "mv".to_string(),
        "curl".to_string(),
        "bash".to_string(),
        "sh".to_string(),
    ]
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
            config: None,
            with_packs: Vec::new(),
            explain: false,
        },
        EngineConfig::Native {
            enabled: true,
            rules: default_native_rules(),
            merge_strategy: MergeStrategy::default(),
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
    use std::fs;

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
            shims: ShimsConfig::default(),
            engines: vec![EngineConfig::Native {
                enabled: true,
                rules: Vec::new(),
                merge_strategy: MergeStrategy::default(),
            }],
            combine: CombineConfig::default(),
            audit: AuditConfig::default(),
        }
        .with_defaults_applied();

        match &config.engines[0] {
            EngineConfig::Native { rules, .. } => {
                assert!(!rules.is_empty());
            }
            _ => panic!("expected native engine"),
        }
    }

    #[test]
    fn test_merge_extends_rules() {
        let global = Config {
            version: 1,
            mode: Mode::Enforce,
            shims: ShimsConfig::default(),
            engines: vec![EngineConfig::Native {
                enabled: true,
                rules: vec![NativeRule {
                    id: "global-rule".to_string(),
                    action: NativeAction::Block,
                    pattern: "global".to_string(),
                    rewrite: None,
                }],
                merge_strategy: MergeStrategy::Extend,
            }],
            combine: CombineConfig::default(),
            audit: AuditConfig::default(),
        };

        let local = Config {
            version: 1,
            mode: Mode::Enforce,
            shims: ShimsConfig::default(),
            engines: vec![EngineConfig::Native {
                enabled: true,
                rules: vec![NativeRule {
                    id: "local-rule".to_string(),
                    action: NativeAction::Block,
                    pattern: "local".to_string(),
                    rewrite: None,
                }],
                merge_strategy: MergeStrategy::Extend,
            }],
            combine: CombineConfig::default(),
            audit: AuditConfig::default(),
        };

        let merged = merge_configs(&global, local);

        match &merged.engines[0] {
            EngineConfig::Native { rules, .. } => {
                assert_eq!(rules.len(), 2);
                assert_eq!(rules[0].id, "local-rule");
                assert_eq!(rules[1].id, "global-rule");
            }
            _ => panic!("expected native engine"),
        }
    }

    #[test]
    fn test_merge_replaces_rules() {
        let global = Config {
            version: 1,
            mode: Mode::Enforce,
            shims: ShimsConfig::default(),
            engines: vec![EngineConfig::Native {
                enabled: true,
                rules: vec![NativeRule {
                    id: "global-rule".to_string(),
                    action: NativeAction::Block,
                    pattern: "global".to_string(),
                    rewrite: None,
                }],
                merge_strategy: MergeStrategy::Extend,
            }],
            combine: CombineConfig::default(),
            audit: AuditConfig::default(),
        };

        let local = Config {
            version: 1,
            mode: Mode::Enforce,
            shims: ShimsConfig::default(),
            engines: vec![EngineConfig::Native {
                enabled: true,
                rules: vec![NativeRule {
                    id: "local-rule".to_string(),
                    action: NativeAction::Block,
                    pattern: "local".to_string(),
                    rewrite: None,
                }],
                merge_strategy: MergeStrategy::Replace,
            }],
            combine: CombineConfig::default(),
            audit: AuditConfig::default(),
        };

        let merged = merge_configs(&global, local);

        match &merged.engines[0] {
            EngineConfig::Native { rules, .. } => {
                assert_eq!(rules.len(), 1);
                assert_eq!(rules[0].id, "local-rule");
            }
            _ => panic!("expected native engine"),
        }
    }

    #[test]
    fn test_local_overrides_global_mode() {
        let global = Config {
            version: 1,
            mode: Mode::Enforce,
            shims: ShimsConfig::default(),
            engines: vec![],
            combine: CombineConfig::default(),
            audit: AuditConfig::default(),
        };

        let local = Config {
            version: 1,
            mode: Mode::Audit,
            shims: ShimsConfig::default(),
            engines: vec![],
            combine: CombineConfig::default(),
            audit: AuditConfig::default(),
        };

        let merged = merge_configs(&global, local);
        assert!(matches!(merged.mode, Mode::Audit));
    }

    #[test]
    fn test_merge_with_prepend_strategy() {
        let global = Config {
            version: 1,
            mode: Mode::Enforce,
            shims: ShimsConfig::default(),
            engines: vec![EngineConfig::Native {
                enabled: true,
                rules: vec![NativeRule {
                    id: "global-rule".to_string(),
                    action: NativeAction::Block,
                    pattern: "global".to_string(),
                    rewrite: None,
                }],
                merge_strategy: MergeStrategy::Extend,
            }],
            combine: CombineConfig::default(),
            audit: AuditConfig::default(),
        };

        let local = Config {
            version: 1,
            mode: Mode::Enforce,
            shims: ShimsConfig::default(),
            engines: vec![EngineConfig::Native {
                enabled: true,
                rules: vec![NativeRule {
                    id: "local-rule".to_string(),
                    action: NativeAction::Block,
                    pattern: "local".to_string(),
                    rewrite: None,
                }],
                merge_strategy: MergeStrategy::Prepend,
            }],
            combine: CombineConfig::default(),
            audit: AuditConfig::default(),
        };

        let merged = merge_configs(&global, local);

        match &merged.engines[0] {
            EngineConfig::Native { rules, .. } => {
                assert_eq!(rules.len(), 2);
                // With Prepend, global rules come first
                assert_eq!(rules[0].id, "global-rule");
                assert_eq!(rules[1].id, "local-rule");
            }
            _ => panic!("expected native engine"),
        }
    }

    #[test]
    fn test_load_merged_with_no_configs() {
        // This tests the case where neither global nor local configs exist
        // It should return the default config
        let merged = Config::merge(None, None);
        assert_eq!(merged.version, 1);
        assert!(matches!(merged.mode, Mode::Enforce));
    }

    #[test]
    fn test_load_merged_with_only_global() {
        let global = Config {
            version: 1,
            mode: Mode::Audit,
            shims: ShimsConfig::default(),
            engines: vec![],
            combine: CombineConfig::default(),
            audit: AuditConfig::default(),
        };

        let merged = Config::merge(Some(global), None);
        assert!(matches!(merged.mode, Mode::Audit));
    }

    #[test]
    fn test_load_merged_with_only_local() {
        let local = Config {
            version: 1,
            mode: Mode::Audit,
            shims: ShimsConfig::default(),
            engines: vec![],
            combine: CombineConfig::default(),
            audit: AuditConfig::default(),
        };

        let merged = Config::merge(None, Some(local));
        assert!(matches!(merged.mode, Mode::Audit));
    }

    #[test]
    fn default_shims_config_has_expected_commands() {
        let shims = ShimsConfig::default();
        assert_eq!(shims.commands.len(), 6);
        assert!(shims.commands.contains(&"git".to_string()));
        assert!(shims.commands.contains(&"rm".to_string()));
        assert!(shims.commands.contains(&"mv".to_string()));
        assert!(shims.commands.contains(&"curl".to_string()));
        assert!(shims.commands.contains(&"bash".to_string()));
        assert!(shims.commands.contains(&"sh".to_string()));
    }

    #[test]
    fn default_config_includes_shims() {
        let config = Config::default();
        assert_eq!(config.shims.commands.len(), 6);
        assert!(config.shims.commands.contains(&"git".to_string()));
    }

    #[test]
    fn load_resolves_default_relative_paths_against_config_directory() {
        let temp = tempfile::tempdir().expect("tempdir should be created");
        let config_dir = temp.path().join("nested");
        fs::create_dir_all(&config_dir).expect("config dir should exist");
        let config_path = config_dir.join("hooky.yml");
        fs::write(&config_path, "version: 1\n").expect("config should be written");

        let config = Config::load(Some(&config_path)).expect("config should load");

        assert_eq!(
            config.audit.log_path,
            config_dir.join(".hooky/.hooky-log.jsonl")
        );
        let claude_hooks = config
            .engines
            .iter()
            .find_map(|engine| match engine {
                EngineConfig::ClaudeHooks { hooks_dir, .. } => Some(hooks_dir),
                _ => None,
            })
            .expect("default claude hooks engine should exist");
        assert_eq!(claude_hooks, &config_dir.join(".claude/hooks"));
    }

    #[test]
    fn load_resolves_explicit_relative_engine_paths_against_config_directory() {
        let temp = tempfile::tempdir().expect("tempdir should be created");
        let config_dir = temp.path().join("workspace");
        fs::create_dir_all(&config_dir).expect("config dir should exist");
        let config_path = config_dir.join(".hooky.yml");

        let config_yaml = r"
version: 1
engines:
  - type: claude_hooks
    enabled: true
    hooks_dir: custom/hooks
  - type: dcg
    enabled: true
    cmd: dcg
    config: security/dcg.toml
  - type: native
    enabled: true
    rules:
      - id: block
        action: block
        pattern: dangerous
  - type: local_hooks
    enabled: true
    pre_command: scripts/pre.sh
    post_command: scripts/post.sh
audit:
  log_path: logs/hooky.jsonl
";
        fs::write(&config_path, config_yaml).expect("config should be written");

        let config = Config::load(Some(&config_path)).expect("config should load");

        let claude_hooks = config
            .engines
            .iter()
            .find_map(|engine| match engine {
                EngineConfig::ClaudeHooks { hooks_dir, .. } => Some(hooks_dir),
                _ => None,
            })
            .expect("claude hooks should exist");
        assert_eq!(claude_hooks, &config_dir.join("custom/hooks"));

        let dcg_config = config
            .engines
            .iter()
            .find_map(|engine| match engine {
                EngineConfig::Dcg { config, .. } => config.as_ref(),
                _ => None,
            })
            .expect("dcg config should exist");
        assert_eq!(dcg_config, &config_dir.join("security/dcg.toml"));

        let (pre, post) = config
            .engines
            .iter()
            .find_map(|engine| match engine {
                EngineConfig::LocalHooks {
                    pre_command,
                    post_command,
                    ..
                } => Some((pre_command.as_ref(), post_command.as_ref())),
                _ => None,
            })
            .expect("local hooks should exist");
        assert_eq!(
            pre.expect("pre command should exist"),
            &config_dir.join("scripts/pre.sh")
        );
        assert_eq!(
            post.expect("post command should exist"),
            &config_dir.join("scripts/post.sh")
        );

        assert_eq!(config.audit.log_path, config_dir.join("logs/hooky.jsonl"));
    }
}
