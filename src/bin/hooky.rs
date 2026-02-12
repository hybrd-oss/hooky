use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use hooky::hooky::audit::{append_event, AuditEvent};
use hooky::hooky::config::Config;
use hooky::hooky::decision::{Decision, DecisionKind};
use hooky::hooky::{doctor, evaluator};
use hooky::types::response::CliResponse;
use regex::Regex;
use std::env;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const DEFAULT_CONFIG_PATH: &str = ".hooky.yml";
const DEFAULT_SHIMS_DIR: &str = ".hooky/shims";
const SHIM_COMMANDS: [&str; 6] = ["git", "rm", "mv", "curl", "bash", "sh"];

#[derive(Parser)]
#[command(name = "hooky")]
#[command(about = "Configurable command firewall for shells, agents, and automation")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a target program with a guarded shell and command shims
    Run {
        /// Path to .hooky.yml
        #[arg(long)]
        config: Option<PathBuf>,

        /// Directory where shims are installed
        #[arg(long)]
        shims_dir: Option<PathBuf>,

        /// Target program followed by its arguments
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        target_and_args: Vec<String>,
    },

    /// Install shell and command shims
    InstallShims {
        /// Destination directory
        #[arg(long)]
        dir: Option<PathBuf>,

        /// Overwrite existing shim files
        #[arg(long)]
        force: bool,
    },

    /// Validate hooky configuration and engine prerequisites
    Doctor {
        /// Path to .hooky.yml
        #[arg(long)]
        config: Option<PathBuf>,
    },

    /// Evaluate a full shell command string
    CheckShell {
        /// Shell command to evaluate
        #[arg(long)]
        cmd: String,

        /// Path to .hooky.yml
        #[arg(long)]
        config: Option<PathBuf>,

        /// Suppress JSON output and use exit code only
        #[arg(long)]
        quiet: bool,
    },

    /// Evaluate argv-style command input
    CheckArgv {
        /// Binary name (for example: git)
        #[arg(long)]
        bin: String,

        /// Path to .hooky.yml
        #[arg(long)]
        config: Option<PathBuf>,

        /// Suppress JSON output and use exit code only
        #[arg(long)]
        quiet: bool,

        /// Remaining argv items to evaluate
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

fn main() {
    if let Err(err) = run() {
        let response = CliResponse::<()>::error(err.to_string());
        match serde_json::to_string_pretty(&response) {
            Ok(json) => {
                println!("{json}");
            }
            Err(_) => {
                println!("{{\"error\":\"{}\"}}", err.to_string().replace('"', "\\\""));
            }
        }
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            config,
            shims_dir,
            target_and_args,
        } => run_program(config.as_deref(), shims_dir.as_deref(), &target_and_args),
        Commands::InstallShims { dir, force } => install_shims_command(dir.as_deref(), force),
        Commands::Doctor { config } => run_doctor(config.as_deref()),
        Commands::CheckShell { cmd, config, quiet } => {
            run_check_shell(config.as_deref(), &cmd, quiet)
        }
        Commands::CheckArgv {
            bin,
            args,
            config,
            quiet,
        } => run_check_argv(config.as_deref(), &bin, &args, quiet),
    }
}

fn run_program(
    config_path: Option<&Path>,
    shims_dir: Option<&Path>,
    target_and_args: &[String],
) -> Result<()> {
    let (program, program_args) = target_and_args
        .split_first()
        .ok_or_else(|| anyhow!("no target program provided"))?;
    let program = program.as_str();
    if !program_exists(program) {
        bail!("target program not found in PATH: {program}");
    }

    let resolved_config = resolve_config_path(config_path);
    let config = Config::load(Some(&resolved_config))?;
    let doctor_report = doctor::run(&config)?;
    if !doctor_report.ok {
        bail!("doctor checks failed; run `hooky doctor` for details");
    }

    let current_exe = std::env::current_exe().context("failed to resolve current executable")?;
    let shims_path = shims_dir.map_or_else(|| PathBuf::from(DEFAULT_SHIMS_DIR), Path::to_path_buf);

    // `run` should be idempotent: refresh generated shims instead of failing
    // when they already exist from a prior `install-shims` or `run`.
    install_shims(&shims_path, true, &current_exe)?;

    let existing_path = std::env::var("PATH").unwrap_or_default();
    let combined_path = if existing_path.is_empty() {
        shims_path.display().to_string()
    } else {
        format!("{}:{existing_path}", shims_path.display())
    };

    let safe_shell = shims_path.join("hooky-shell");
    let mut cmd = Command::new(program);
    cmd.args(program_args)
        .env("PATH", combined_path)
        .env("SHELL", &safe_shell)
        .env("HOOKY_BIN", &current_exe)
        .env("HOOKY_CONFIG", &resolved_config)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let status = cmd
        .status()
        .with_context(|| format!("failed to start target program: {program}"))?;
    match status.code() {
        Some(code) => std::process::exit(code),
        None => std::process::exit(1),
    }
}

fn program_exists(program: &str) -> bool {
    if program.contains('/') {
        return Path::new(program).exists();
    }

    evaluator::command_exists(program)
}

fn install_shims_command(dir: Option<&Path>, force: bool) -> Result<()> {
    let current_exe = std::env::current_exe().context("failed to resolve current executable")?;
    let target_dir = dir.map_or_else(|| PathBuf::from(DEFAULT_SHIMS_DIR), Path::to_path_buf);

    let installed = install_shims(&target_dir, force, &current_exe)?;
    let response = CliResponse::success(InstallShimsResponse {
        dir: target_dir,
        files_installed: installed,
    });

    let json =
        serde_json::to_string_pretty(&response).context("failed to serialize install-shims")?;
    println!("{json}");
    Ok(())
}

fn install_shims(dir: &Path, force: bool, hooky_bin: &Path) -> Result<usize> {
    fs::create_dir_all(dir)
        .with_context(|| format!("failed to create shims directory {}", dir.display()))?;

    let safe_shell_path = dir.join("hooky-shell");
    let safe_shell_script = build_safe_shell_script(hooky_bin)?;
    write_executable_script(&safe_shell_path, &safe_shell_script, force)?;

    let mut installed = 1usize;
    for command_name in SHIM_COMMANDS {
        let real_path = resolve_binary_path(command_name, dir)
            .with_context(|| format!("failed to resolve binary path for {command_name}"))?;
        let shim_script = build_command_shim_script(command_name, &real_path, hooky_bin)?;
        let shim_path = dir.join(command_name);
        write_executable_script(&shim_path, &shim_script, force)?;
        installed += 1;
    }

    Ok(installed)
}

fn build_safe_shell_script(hooky_bin: &Path) -> Result<String> {
    let bin = hooky_bin
        .to_str()
        .ok_or_else(|| anyhow!("hooky binary path is not valid UTF-8"))?;

    Ok(format!(
        "#!/bin/bash
set -euo pipefail

HOOKY_BIN=\"${{HOOKY_BIN:-{bin}}}\"
HOOKY_CONFIG=\"${{HOOKY_CONFIG:-{DEFAULT_CONFIG_PATH}}}\"

if [[ \"${{1:-}}\" == \"-c\" && -n \"${{2:-}}\" ]]; then
  \"$HOOKY_BIN\" check-shell --quiet --config \"$HOOKY_CONFIG\" --cmd \"$2\"
elif [[ \"${{1:-}}\" == \"-lc\" && -n \"${{2:-}}\" ]]; then
  \"$HOOKY_BIN\" check-shell --quiet --config \"$HOOKY_CONFIG\" --cmd \"$2\"
elif [[ \"${{1:-}}\" == \"-l\" && \"${{2:-}}\" == \"-c\" && -n \"${{3:-}}\" ]]; then
  \"$HOOKY_BIN\" check-shell --quiet --config \"$HOOKY_CONFIG\" --cmd \"$3\"
fi

exec /bin/bash \"$@\"
"
    ))
}

fn build_command_shim_script(
    command_name: &str,
    real_path: &Path,
    hooky_bin: &Path,
) -> Result<String> {
    let real = real_path
        .to_str()
        .ok_or_else(|| anyhow!("real binary path for {command_name} is not valid UTF-8"))?;
    let bin = hooky_bin
        .to_str()
        .ok_or_else(|| anyhow!("hooky binary path is not valid UTF-8"))?;

    Ok(format!(
        "#!/bin/bash
set -euo pipefail

HOOKY_BIN=\"${{HOOKY_BIN:-{bin}}}\"
HOOKY_CONFIG=\"${{HOOKY_CONFIG:-{DEFAULT_CONFIG_PATH}}}\"

\"$HOOKY_BIN\" check-argv --quiet --config \"$HOOKY_CONFIG\" --bin \"{command_name}\" -- \"$@\"
exec \"{real}\" \"$@\"
"
    ))
}

fn write_executable_script(path: &Path, contents: &str, force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!(
            "shim {} already exists (use --force to overwrite)",
            path.display()
        );
    }

    fs::write(path, contents)
        .with_context(|| format!("failed to write shim script {}", path.display()))?;

    let mut perms = fs::metadata(path)
        .with_context(|| format!("failed to read metadata for {}", path.display()))?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).with_context(|| {
        format!(
            "failed to set executable permissions for {}",
            path.display()
        )
    })?;

    Ok(())
}

fn resolve_binary_path(command_name: &str, shims_dir: &Path) -> Result<PathBuf> {
    resolve_binary_path_with_path(command_name, env::var_os("PATH").as_deref(), shims_dir)
}

fn resolve_binary_path_with_path(
    command_name: &str,
    path_env: Option<&OsStr>,
    shims_dir: &Path,
) -> Result<PathBuf> {
    let path_env = path_env.ok_or_else(|| anyhow!("PATH is not set"))?;
    let shims_canonical = fs::canonicalize(shims_dir).unwrap_or_else(|_| shims_dir.to_path_buf());

    let mut trusted_candidates = Vec::new();
    let mut fallback_candidates = Vec::new();

    for entry in env::split_paths(path_env) {
        if !entry.is_absolute() {
            continue;
        }

        let entry_canonical = fs::canonicalize(&entry).unwrap_or(entry.clone());
        if entry_canonical.starts_with(&shims_canonical) {
            continue;
        }

        let candidate = entry.join(command_name);
        if !is_executable_file(&candidate) {
            continue;
        }

        let candidate_canonical = fs::canonicalize(&candidate).unwrap_or(candidate.clone());
        if candidate_canonical.starts_with(&shims_canonical) {
            continue;
        }

        if is_trusted_bin_path(&candidate_canonical) {
            trusted_candidates.push(candidate_canonical);
        } else {
            fallback_candidates.push(candidate_canonical);
        }
    }

    if let Some(first) = trusted_candidates.into_iter().next() {
        return Ok(first);
    }
    if let Some(first) = fallback_candidates.into_iter().next() {
        return Ok(first);
    }

    bail!("binary not found in PATH: {command_name}")
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };

    if !metadata.is_file() {
        return false;
    }

    metadata.permissions().mode() & 0o111 != 0
}

fn is_trusted_bin_path(path: &Path) -> bool {
    const TRUSTED_DIRS: [&str; 4] = ["/usr/bin", "/bin", "/usr/local/bin", "/opt/homebrew/bin"];
    TRUSTED_DIRS.iter().any(|trusted| path.starts_with(trusted))
}

fn resolve_config_path(config_path: Option<&Path>) -> PathBuf {
    config_path.map_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH), Path::to_path_buf)
}

fn run_doctor(config_path: Option<&Path>) -> Result<()> {
    let config = Config::load(config_path)?;
    let report = doctor::run(&config)?;
    let response = CliResponse::success(report);
    let json =
        serde_json::to_string_pretty(&response).context("failed to serialize doctor response")?;
    println!("{json}");

    if !response
        .data
        .as_ref()
        .is_some_and(|doctor_report| doctor_report.ok)
    {
        std::process::exit(1);
    }

    Ok(())
}

fn run_check_shell(config_path: Option<&Path>, command: &str, quiet: bool) -> Result<()> {
    let config = Config::load(config_path)?;
    let decision = match evaluator::evaluate_shell_command(command, &config) {
        Ok(decision) => decision,
        Err(err) => fail_closed_decision(&err.to_string()),
    };

    write_audit(&config, command, &decision)?;

    if quiet {
        emit_quiet_failure_details(&decision);
    } else {
        let response = CliResponse::success(CheckResponse {
            command: command.to_string(),
            decision: decision.clone(),
        });
        let json =
            serde_json::to_string_pretty(&response).context("failed to serialize check-shell")?;
        println!("{json}");
    }

    set_exit_code_from_decision(&decision);
    Ok(())
}

fn run_check_argv(
    config_path: Option<&Path>,
    bin: &str,
    args: &[String],
    quiet: bool,
) -> Result<()> {
    let config = Config::load(config_path)?;
    let decision = match evaluator::evaluate_argv_command(bin, args, &config) {
        Ok(decision) => decision,
        Err(err) => fail_closed_decision(&err.to_string()),
    };

    let command = std::iter::once(bin.to_string())
        .chain(args.iter().map(std::clone::Clone::clone))
        .collect::<Vec<String>>()
        .join(" ");

    write_audit(&config, &command, &decision)?;

    if quiet {
        emit_quiet_failure_details(&decision);
    } else {
        let response = CliResponse::success(CheckResponse {
            command,
            decision: decision.clone(),
        });
        let json =
            serde_json::to_string_pretty(&response).context("failed to serialize check-argv")?;
        println!("{json}");
    }

    set_exit_code_from_decision(&decision);
    Ok(())
}

fn emit_quiet_failure_details(decision: &Decision) {
    if matches!(decision.kind, DecisionKind::Allow) {
        return;
    }

    let mut details = format!("hooky {:?}: {}", decision.kind, decision.reason);
    if let Some(rule_id) = &decision.rule_id {
        let _ = write!(&mut details, " [rule: {rule_id}]");
    }
    let _ = write!(&mut details, " [engine: {}]", decision.engine);

    eprintln!("{details}");
}

fn write_audit(config: &Config, command: &str, decision: &Decision) -> Result<()> {
    let event = AuditEvent {
        timestamp: chrono::Utc::now(),
        event: "command_check".to_string(),
        command: redact_command_for_audit(command),
        decision: decision.clone(),
    };

    append_event(&config.audit.log_path, &event)
}

fn redact_command_for_audit(command: &str) -> String {
    let mut redacted = command.to_string();

    let patterns: [(&str, &str); 5] = [
        (
            r#"(?i)(--?(?:token|password|passwd|secret|api[-_]?key|access[-_]?key|auth[-_]?token))(=|\s+)("[^"]*"|'[^']*'|\S+)"#,
            "$1$2[REDACTED]",
        ),
        (
            r#"(?i)\b(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|TOKEN|PASSWORD|PASSWD|API_KEY|SECRET)=("[^"]*"|'[^']*'|\S+)"#,
            "$1=[REDACTED]",
        ),
        (r"(?i)(authorization:\s*bearer\s+)\S+", "$1[REDACTED]"),
        (
            r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]+):([^@/\s]+)@",
            "$1:[REDACTED]@",
        ),
        (
            r#"(?i)("(?:token|password|secret|api[_-]?key)"\s*:\s*")[^"]*(")"#,
            "$1[REDACTED]$2",
        ),
    ];

    for (pattern, replacement) in patterns {
        if let Ok(regex) = Regex::new(pattern) {
            redacted = regex.replace_all(&redacted, replacement).to_string();
        }
    }

    redacted
}

fn fail_closed_decision(error: &str) -> Decision {
    Decision::block(
        format!("fail-closed: {error}"),
        "hooky",
        Some("engine-error".to_string()),
    )
}

fn set_exit_code_from_decision(decision: &Decision) {
    match decision.kind {
        DecisionKind::Allow | DecisionKind::Rewrite => {}
        DecisionKind::Confirm => std::process::exit(10),
        DecisionKind::Block => std::process::exit(1),
    }
}

#[derive(serde::Serialize)]
struct CheckResponse {
    command: String,
    decision: Decision,
}

#[derive(serde::Serialize)]
struct InstallShimsResponse {
    dir: PathBuf,
    files_installed: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn redacts_common_secret_patterns() {
        let command = "curl -H 'Authorization: Bearer abc123' --token abc --password=def https://user:pass@example.com";
        let redacted = redact_command_for_audit(command);

        assert!(redacted.contains("Bearer [REDACTED]"));
        assert!(redacted.contains("--token [REDACTED]"));
        assert!(redacted.contains("--password=[REDACTED]"));
        assert!(redacted.contains("https://user:[REDACTED]@example.com"));
        assert!(!redacted.contains("abc123"));
        assert!(!redacted.contains("pass@example.com"));
    }

    #[test]
    fn resolve_binary_path_skips_shims_dir() {
        let temp = tempfile::tempdir().expect("tempdir should be created");
        let shims_dir = temp.path().join("shims");
        let safe_bin_dir = temp.path().join("safe-bin");
        fs::create_dir_all(&shims_dir).expect("shims dir");
        fs::create_dir_all(&safe_bin_dir).expect("safe bin dir");

        let shim_git = shims_dir.join("git");
        let safe_git = safe_bin_dir.join("git");
        fs::write(&shim_git, "#!/bin/sh\n").expect("shim write");
        fs::write(&safe_git, "#!/bin/sh\n").expect("safe write");
        fs::set_permissions(&shim_git, fs::Permissions::from_mode(0o755)).expect("shim perms");
        fs::set_permissions(&safe_git, fs::Permissions::from_mode(0o755)).expect("safe perms");

        let path = OsString::from(format!(
            "{}:{}",
            shims_dir.display(),
            safe_bin_dir.display()
        ));
        let resolved =
            resolve_binary_path_with_path("git", Some(path.as_os_str()), &shims_dir).unwrap();

        let resolved_canonical = fs::canonicalize(resolved).expect("resolved canonical path");
        let safe_canonical = fs::canonicalize(safe_git).expect("safe canonical path");
        assert_eq!(resolved_canonical, safe_canonical);
    }

    #[test]
    fn safe_shell_script_checks_dash_c_and_dash_lc() {
        let script = build_safe_shell_script(Path::new("/tmp/hooky")).expect("script generation");

        assert!(script.starts_with("#!/bin/bash\n"));
        assert!(script.contains("\"${1:-}\" == \"-c\""));
        assert!(script.contains("\"${1:-}\" == \"-lc\""));
        assert!(script.contains("\"${1:-}\" == \"-l\" && \"${2:-}\" == \"-c\""));
    }

    #[test]
    fn command_shim_uses_absolute_bash_shebang() {
        let script =
            build_command_shim_script("git", Path::new("/usr/bin/git"), Path::new("/tmp/hooky"))
                .expect("script generation");

        assert!(script.starts_with("#!/bin/bash\n"));
    }
}
