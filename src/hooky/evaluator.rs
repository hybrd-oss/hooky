use crate::hooky::config::{ArgvMatch, Config, EngineConfig, NativeAction};
use crate::hooky::decision::{Decision, DecisionKind};
use anyhow::{anyhow, bail, Context, Result};
use regex::Regex;
use serde_json::json;
use std::ffi::OsStr;
use std::path::Path;
use std::process::{Command, Stdio};

struct ArgvContext<'a> {
    bin: &'a str,
    args: &'a [String],
}

pub fn evaluate_shell_command(command: &str, config: &Config) -> Result<Decision> {
    evaluate_command(command, None, config)
}

pub fn evaluate_argv_command(bin: &str, args: &[String], config: &Config) -> Result<Decision> {
    let joined = std::iter::once(bin.to_string())
        .chain(args.iter().cloned())
        .collect::<Vec<String>>()
        .join(" ");
    let ctx = ArgvContext { bin, args };
    evaluate_command(&joined, Some(&ctx), config)
}

fn evaluate_command(
    command: &str,
    argv: Option<&ArgvContext>,
    config: &Config,
) -> Result<Decision> {
    let mut pending_confirm = false;

    for engine in &config.engines {
        let Some(decision) = run_engine(engine, command, argv)? else {
            continue;
        };

        match decision.kind {
            DecisionKind::Block => return Ok(decision),
            DecisionKind::Rewrite => {
                return Ok(Decision::block(
                    "rewrite decisions are disabled; deny-only mode",
                    "combiner",
                    decision.rule_id.clone(),
                ));
            }
            DecisionKind::Confirm => {
                pending_confirm = true;
            }
            DecisionKind::Allow => {}
        }
    }

    if pending_confirm {
        return Ok(Decision {
            kind: DecisionKind::Confirm,
            reason: "one or more engines requested confirmation".to_string(),
            rule_id: None,
            rewritten_command: None,
            engine: "combiner".to_string(),
        });
    }

    Ok(Decision::allow("no rules matched", "combiner"))
}

fn run_engine(
    engine: &EngineConfig,
    command: &str,
    argv: Option<&ArgvContext>,
) -> Result<Option<Decision>> {
    match engine {
        EngineConfig::ClaudeHooks { enabled, hooks_dir } => {
            if !enabled {
                return Ok(None);
            }
            run_claude_hook_engine(command, hooks_dir)
        }
        EngineConfig::Dcg {
            enabled,
            cmd,
            args,
            config,
            with_packs,
            explain,
        } => {
            if !enabled {
                return Ok(None);
            }
            run_dcg_engine(command, cmd, args, config.as_deref(), with_packs, *explain)
        }
        EngineConfig::Native { enabled, rules, .. } => {
            if !enabled {
                return Ok(None);
            }
            Ok(run_native_engine(command, rules.as_slice(), argv)?)
        }
        EngineConfig::LocalHooks { enabled, .. } => {
            if !enabled {
                return Ok(None);
            }
            bail!("local_hooks engine configured but not implemented yet");
        }
    }
}

fn run_claude_hook_engine(command: &str, hooks_dir: &Path) -> Result<Option<Decision>> {
    let hook_path = hooks_dir.join("block-no-verify.sh");

    if !hook_path.exists() {
        return Ok(None);
    }

    let payload = json!({
        "tool_input": {
            "command": command,
        }
    });

    let payload_string =
        serde_json::to_string(&payload).context("failed to serialize hook payload")?;

    let mut child = Command::new("/bin/bash")
        .arg(&hook_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to start hook {}", hook_path.display()))?;

    if let Some(stdin) = &mut child.stdin {
        use std::io::Write;
        stdin
            .write_all(payload_string.as_bytes())
            .context("failed writing hook stdin")?;
    }

    let output = child
        .wait_with_output()
        .with_context(|| format!("failed waiting for hook {}", hook_path.display()))?;

    if output.status.success() {
        return Ok(Some(Decision::allow(
            "claude hook allowed command",
            "claude_hooks",
        )));
    }

    let reason = combined_text(&output.stdout, &output.stderr)
        .unwrap_or_else(|| "claude hook blocked command".to_string());

    Ok(Some(Decision::block(
        reason,
        "claude_hooks",
        Some("block-no-verify".to_string()),
    )))
}

fn run_dcg_engine(
    command: &str,
    cmd: &str,
    args: &[String],
    config_path: Option<&Path>,
    with_packs: &[String],
    explain: bool,
) -> Result<Option<Decision>> {
    if !command_exists(cmd) {
        bail!("dcg engine command not found: {cmd}");
    }

    let expanded_args = build_dcg_test_args(command, args, config_path, with_packs, explain);

    let child = Command::new(cmd)
        .args(&expanded_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to start dcg engine command: {cmd}"))?;

    let output = child
        .wait_with_output()
        .context("failed waiting for dcg command")?;

    Ok(Some(parse_dcg_decision(
        command,
        output.status.success(),
        &output.stdout,
        &output.stderr,
    )))
}

fn build_dcg_test_args(
    command: &str,
    passthrough_args: &[String],
    config_path: Option<&Path>,
    with_packs: &[String],
    explain: bool,
) -> Vec<String> {
    let mut args = vec![
        "test".to_string(),
        "--format".to_string(),
        "json".to_string(),
        "--no-color".to_string(),
    ];

    if let Some(path) = config_path {
        args.push("--config".to_string());
        args.push(path.display().to_string());
    }

    for pack in with_packs {
        args.push("--with-packs".to_string());
        args.push(pack.clone());
    }

    if explain {
        args.push("--explain".to_string());
    }

    let mut has_placeholder = false;
    for arg in passthrough_args {
        if arg.contains("{command}") {
            has_placeholder = true;
            args.push(arg.replace("{command}", command));
        } else {
            args.push(arg.clone());
        }
    }

    if !has_placeholder {
        args.push(command.to_string());
    }
    args
}

fn parse_dcg_decision(command: &str, success: bool, stdout: &[u8], stderr: &[u8]) -> Decision {
    if let Ok(json_value) = serde_json::from_slice::<serde_json::Value>(stdout) {
        if let Some(decision) = parse_dcg_json(command, &json_value) {
            return decision;
        }
    }

    let text = combined_text(stdout, stderr)
        .unwrap_or_default()
        .to_lowercase();
    if text.contains("block") || text.contains("deny") {
        return Decision::block("dcg blocked command", "dcg", Some("dcg-block".to_string()));
    }
    if text.contains("confirm") {
        return Decision {
            kind: DecisionKind::Confirm,
            reason: "dcg requires confirmation".to_string(),
            rule_id: Some("dcg-confirm".to_string()),
            rewritten_command: None,
            engine: "dcg".to_string(),
        };
    }
    if text.contains("rewrite") {
        return Decision::rewrite(
            "dcg rewrote command",
            "dcg",
            Some("dcg-rewrite".to_string()),
            command,
        );
    }

    if success {
        return Decision::allow("dcg allowed command", "dcg");
    }

    let reason = combined_text(stdout, stderr).unwrap_or_else(|| "dcg blocked command".to_string());
    Decision::block(reason, "dcg", Some("dcg-block".to_string()))
}

fn parse_dcg_json(command: &str, value: &serde_json::Value) -> Option<Decision> {
    let obj = value.as_object()?;
    let decision_str = obj
        .get("decision")
        .or_else(|| obj.get("kind"))
        .or_else(|| obj.get("action"))?
        .as_str()?
        .to_lowercase();

    let reason = obj
        .get("reason")
        .or_else(|| obj.get("message"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("dcg decision")
        .to_string();

    let rule_id = obj
        .get("rule_id")
        .and_then(serde_json::Value::as_str)
        .map(std::string::ToString::to_string);

    match decision_str.as_str() {
        "allow" => Some(Decision::allow(reason, "dcg")),
        "block" | "deny" => Some(Decision::block(reason, "dcg", rule_id)),
        "confirm" => Some(Decision {
            kind: DecisionKind::Confirm,
            reason,
            rule_id,
            rewritten_command: None,
            engine: "dcg".to_string(),
        }),
        "rewrite" => {
            let rewritten_command = obj
                .get("rewritten_command")
                .or_else(|| obj.get("rewrite"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or(command);

            Some(Decision::rewrite(reason, "dcg", rule_id, rewritten_command))
        }
        _ => None,
    }
}

fn combined_text(stdout: &[u8], stderr: &[u8]) -> Option<String> {
    let stdout_text = String::from_utf8_lossy(stdout).trim().to_string();
    let stderr_text = String::from_utf8_lossy(stderr).trim().to_string();

    if !stdout_text.is_empty() {
        return Some(stdout_text);
    }
    if !stderr_text.is_empty() {
        return Some(stderr_text);
    }
    None
}

fn matches_argv(m: &ArgvMatch, ctx: &ArgvContext) -> bool {
    // Check binary name
    if !m.bin.is_empty() {
        let actual = ctx.bin.rsplit('/').next().unwrap_or(ctx.bin);
        if actual != m.bin {
            return false;
        }
    }
    // Check subcommand present in args
    if !m.subcommands.is_empty()
        && !m
            .subcommands
            .iter()
            .any(|sc| ctx.args.iter().any(|a| a == sc))
    {
        return false;
    }
    // Check at least one blocked flag present in args
    if m.flags.is_empty() {
        return false;
    }
    m.flags.iter().any(|f| ctx.args.iter().any(|a| a == f))
}

fn run_native_engine(
    command: &str,
    rules: &[crate::hooky::config::NativeRule],
    argv: Option<&ArgvContext>,
) -> Result<Option<Decision>> {
    for rule in rules {
        // When both argv context and argv_match are available, use structural matching
        let matched = if let (Some(m), Some(ctx)) = (&rule.argv_match, argv) {
            matches_argv(m, ctx)
        } else {
            let regex = Regex::new(&rule.pattern)
                .with_context(|| format!("invalid regex for native rule {}", rule.id))?;
            regex.is_match(command)
        };

        if !matched {
            continue;
        }

        match rule.action {
            NativeAction::Block => {
                return Ok(Some(Decision::block(
                    format!("blocked by native rule {}", rule.id),
                    "native",
                    Some(rule.id.clone()),
                )));
            }
            NativeAction::Rewrite => {
                if let Some(rewrite) = &rule.rewrite {
                    return Ok(Some(Decision::rewrite(
                        format!("rewritten by native rule {}", rule.id),
                        "native",
                        Some(rule.id.clone()),
                        rewrite.clone(),
                    )));
                }
                return Err(anyhow!(
                    "native rewrite rule {} matched but no rewrite target was configured",
                    rule.id
                ));
            }
            NativeAction::Confirm => {
                return Ok(Some(Decision {
                    kind: DecisionKind::Confirm,
                    reason: format!("confirmation required by native rule {}", rule.id),
                    rule_id: Some(rule.id.clone()),
                    rewritten_command: None,
                    engine: "native".to_string(),
                }));
            }
        }
    }

    Ok(None)
}

pub fn command_exists(command: &str) -> bool {
    Command::new("which")
        .arg(OsStr::new(command))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooky::config::{AuditConfig, CombineConfig, NativeRule};
    use std::path::PathBuf;

    fn config_with_native_rules(rules: Vec<NativeRule>) -> Config {
        Config {
            version: 1,
            mode: crate::hooky::config::Mode::Enforce,
            shims: crate::hooky::config::ShimsConfig::default(),
            engines: vec![EngineConfig::Native {
                enabled: true,
                rules,
                merge_strategy: crate::hooky::config::MergeStrategy::default(),
            }],
            combine: CombineConfig::default(),
            audit: AuditConfig {
                log_path: PathBuf::from(".hooky/.hooky-log.jsonl"),
            },
        }
    }

    #[test]
    fn native_block_rule_blocks_command() {
        let config = config_with_native_rules(vec![NativeRule {
            id: "block-no-verify".to_string(),
            action: NativeAction::Block,
            pattern: "--no-verify".to_string(),
            rewrite: None,
            argv_match: None,
        }]);

        let decision = evaluate_shell_command("git commit --no-verify -m test", &config)
            .expect("evaluation should succeed");

        assert_eq!(decision.kind, DecisionKind::Block);
        assert_eq!(decision.rule_id.as_deref(), Some("block-no-verify"));
    }

    #[test]
    fn native_rewrite_rule_is_blocked_in_deny_only_mode() {
        let config = config_with_native_rules(vec![NativeRule {
            id: "force-to-lease".to_string(),
            action: NativeAction::Rewrite,
            pattern: "--force".to_string(),
            rewrite: Some("git push --force-with-lease".to_string()),
            argv_match: None,
        }]);

        let decision = evaluate_shell_command("git push origin main --force", &config)
            .expect("evaluation should succeed");

        assert_eq!(decision.kind, DecisionKind::Block);
        assert_eq!(decision.engine, "combiner");
        assert_eq!(decision.rule_id.as_deref(), Some("force-to-lease"));
    }

    #[test]
    fn rewrite_then_block_still_returns_block() {
        let config = Config {
            version: 1,
            mode: crate::hooky::config::Mode::Enforce,
            shims: crate::hooky::config::ShimsConfig::default(),
            engines: vec![
                EngineConfig::Native {
                    enabled: true,
                    rules: vec![NativeRule {
                        id: "rewrite-force".to_string(),
                        action: NativeAction::Rewrite,
                        pattern: "--force".to_string(),
                        rewrite: Some("git push --force-with-lease".to_string()),
                        argv_match: None,
                    }],
                    merge_strategy: crate::hooky::config::MergeStrategy::default(),
                },
                EngineConfig::Native {
                    enabled: true,
                    rules: vec![NativeRule {
                        id: "block-force".to_string(),
                        action: NativeAction::Block,
                        pattern: "--force".to_string(),
                        rewrite: None,
                        argv_match: None,
                    }],
                    merge_strategy: crate::hooky::config::MergeStrategy::default(),
                },
            ],
            combine: CombineConfig::default(),
            audit: AuditConfig {
                log_path: PathBuf::from(".hooky/.hooky-log.jsonl"),
            },
        };

        let decision = evaluate_shell_command("git push origin main --force", &config)
            .expect("evaluation should succeed");

        assert_eq!(decision.kind, DecisionKind::Block);
        assert_eq!(decision.rule_id.as_deref(), Some("rewrite-force"));
    }

    #[test]
    fn confirm_returned_when_no_block_or_rewrite() {
        let config = config_with_native_rules(vec![NativeRule {
            id: "confirm-danger".to_string(),
            action: NativeAction::Confirm,
            pattern: "rm -rf".to_string(),
            rewrite: None,
            argv_match: None,
        }]);

        let decision =
            evaluate_shell_command("rm -rf tmp", &config).expect("evaluation should succeed");

        assert_eq!(decision.kind, DecisionKind::Confirm);
    }

    #[test]
    fn dcg_json_block_parses_to_block_decision() {
        let output = br#"{"decision":"block","reason":"danger","rule_id":"dcg-1"}"#;
        let decision = parse_dcg_decision("echo hi", true, output, b"");

        assert_eq!(decision.kind, DecisionKind::Block);
        assert_eq!(decision.rule_id.as_deref(), Some("dcg-1"));
        assert_eq!(decision.engine, "dcg");
    }

    #[test]
    fn dcg_plain_text_allow_uses_exit_status() {
        let decision = parse_dcg_decision("echo hi", true, b"", b"");
        assert_eq!(decision.kind, DecisionKind::Allow);
    }

    #[test]
    fn argv_blocks_git_commit_no_verify() {
        let config = Config::default();
        let decision = evaluate_argv_command(
            "git",
            &[
                "commit".into(),
                "--no-verify".into(),
                "-m".into(),
                "test".into(),
            ],
            &config,
        )
        .expect("evaluation should succeed");
        assert_eq!(decision.kind, DecisionKind::Block);
    }

    #[test]
    fn argv_blocks_git_commit_short_n() {
        let config = Config::default();
        let decision = evaluate_argv_command(
            "git",
            &["commit".into(), "-n".into(), "-m".into(), "test".into()],
            &config,
        )
        .expect("evaluation should succeed");
        assert_eq!(decision.kind, DecisionKind::Block);
    }

    #[test]
    fn argv_allows_bash_precommit_with_n_test() {
        let config = Config::default();
        let decision = evaluate_argv_command(
            "bash",
            &["-c".into(), "[ -n \"$CI\" ] && pre-commit run".into()],
            &config,
        )
        .expect("evaluation should succeed");
        assert_eq!(decision.kind, DecisionKind::Allow);
    }

    #[test]
    fn argv_blocks_git_push_force() {
        let config = Config::default();
        let decision = evaluate_argv_command(
            "git",
            &[
                "push".into(),
                "origin".into(),
                "main".into(),
                "--force".into(),
            ],
            &config,
        )
        .expect("evaluation should succeed");
        assert_eq!(decision.kind, DecisionKind::Block);
    }

    #[test]
    fn argv_allows_git_push_no_force() {
        let config = Config::default();
        let decision = evaluate_argv_command(
            "git",
            &["push".into(), "origin".into(), "main".into()],
            &config,
        )
        .expect("evaluation should succeed");
        assert_eq!(decision.kind, DecisionKind::Allow);
    }

    #[test]
    fn argv_custom_regex_rule_falls_back() {
        let config = config_with_native_rules(vec![NativeRule {
            id: "custom-block".to_string(),
            action: NativeAction::Block,
            pattern: r"dangerous-cmd".to_string(),
            rewrite: None,
            argv_match: None,
        }]);
        let decision = evaluate_argv_command("dangerous-cmd", &["--flag".into()], &config)
            .expect("evaluation should succeed");
        assert_eq!(decision.kind, DecisionKind::Block);
    }

    #[test]
    fn dcg_test_args_include_expected_defaults_and_config() {
        let args = build_dcg_test_args(
            "git push --force",
            &[],
            Some(Path::new("/tmp/dcg.toml")),
            &[
                String::from("containers.docker"),
                String::from("database.postgresql"),
            ],
            true,
        );

        assert_eq!(args[0], "test");
        assert!(args.contains(&"--format".to_string()));
        assert!(args.contains(&"json".to_string()));
        assert!(args.contains(&"--no-color".to_string()));
        assert!(args.contains(&"--config".to_string()));
        assert!(args.contains(&"/tmp/dcg.toml".to_string()));
        assert!(args.contains(&"--with-packs".to_string()));
        assert!(args.contains(&"containers.docker".to_string()));
        assert!(args.contains(&"database.postgresql".to_string()));
        assert!(args.contains(&"--explain".to_string()));
        assert_eq!(
            args.last().expect("command argument should be present"),
            "git push --force"
        );
    }
}
