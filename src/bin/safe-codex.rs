use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use safe_codex::safe_codex::audit::{append_event, AuditEvent};
use safe_codex::safe_codex::config::Config;
use safe_codex::safe_codex::decision::{Decision, DecisionKind};
use safe_codex::safe_codex::{doctor, evaluator};
use safe_codex::types::response::CliResponse;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const DEFAULT_CONFIG_PATH: &str = ".safe-codex.yml";
const DEFAULT_SHIMS_DIR: &str = ".safe-codex/shims";
const SHIM_COMMANDS: [&str; 6] = ["git", "rm", "mv", "curl", "bash", "sh"];

#[derive(Parser)]
#[command(name = "safe-codex")]
#[command(about = "Command safety wrapper and policy evaluator for Codex")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run codex with a guarded shell and command shims
    Run {
        /// Path to .safe-codex.yml
        #[arg(long)]
        config: Option<PathBuf>,

        /// Directory where shims are installed
        #[arg(long)]
        shims_dir: Option<PathBuf>,

        /// Arguments forwarded to codex
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        codex_args: Vec<String>,
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

    /// Validate safe-codex configuration and engine prerequisites
    Doctor {
        /// Path to .safe-codex.yml
        #[arg(long)]
        config: Option<PathBuf>,
    },

    /// Evaluate a full shell command string
    CheckShell {
        /// Shell command to evaluate
        #[arg(long)]
        cmd: String,

        /// Path to .safe-codex.yml
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

        /// Path to .safe-codex.yml
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
                println!(
                    "{{\"success\":false,\"error\":\"{}\"}}",
                    err.to_string().replace('"', "\\\"")
                );
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
            codex_args,
        } => run_codex(config.as_deref(), shims_dir.as_deref(), &codex_args),
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

fn run_codex(
    config_path: Option<&Path>,
    shims_dir: Option<&Path>,
    codex_args: &[String],
) -> Result<()> {
    if !evaluator::command_exists("codex") {
        bail!("codex command not found in PATH");
    }

    let resolved_config = resolve_config_path(config_path);
    let config = Config::load(Some(&resolved_config))?;
    let doctor_report = doctor::run(&config)?;
    if !doctor_report.ok {
        bail!("doctor checks failed; run `safe-codex doctor` for details");
    }

    let current_exe = std::env::current_exe().context("failed to resolve current executable")?;
    let shims_path = shims_dir.map_or_else(|| PathBuf::from(DEFAULT_SHIMS_DIR), Path::to_path_buf);

    install_shims(&shims_path, false, &current_exe)?;

    let existing_path = std::env::var("PATH").unwrap_or_default();
    let combined_path = if existing_path.is_empty() {
        shims_path.display().to_string()
    } else {
        format!("{}:{existing_path}", shims_path.display())
    };

    let safe_shell = shims_path.join("safe-shell");
    let mut cmd = Command::new("codex");
    cmd.args(codex_args)
        .env("PATH", combined_path)
        .env("SHELL", &safe_shell)
        .env("SAFE_CODEX_BIN", &current_exe)
        .env("SAFE_CODEX_CONFIG", &resolved_config)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let status = cmd.status().context("failed to start codex")?;
    match status.code() {
        Some(code) => std::process::exit(code),
        None => std::process::exit(1),
    }
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

fn install_shims(dir: &Path, force: bool, safe_codex_bin: &Path) -> Result<usize> {
    fs::create_dir_all(dir)
        .with_context(|| format!("failed to create shims directory {}", dir.display()))?;

    let safe_shell_path = dir.join("safe-shell");
    let safe_shell_script = build_safe_shell_script(safe_codex_bin)?;
    write_executable_script(&safe_shell_path, &safe_shell_script, force)?;

    let mut installed = 1usize;
    for command_name in SHIM_COMMANDS {
        let real_path = resolve_binary_path(command_name)
            .with_context(|| format!("failed to resolve binary path for {command_name}"))?;
        let shim_script = build_command_shim_script(command_name, &real_path, safe_codex_bin)?;
        let shim_path = dir.join(command_name);
        write_executable_script(&shim_path, &shim_script, force)?;
        installed += 1;
    }

    Ok(installed)
}

fn build_safe_shell_script(safe_codex_bin: &Path) -> Result<String> {
    let bin = safe_codex_bin
        .to_str()
        .ok_or_else(|| anyhow!("safe-codex binary path is not valid UTF-8"))?;

    Ok(format!(
        "#!/usr/bin/env bash
set -euo pipefail

SAFE_CODEX_BIN=\"${{SAFE_CODEX_BIN:-{bin}}}\"
SAFE_CODEX_CONFIG=\"${{SAFE_CODEX_CONFIG:-{DEFAULT_CONFIG_PATH}}}\"

if [[ \"${{1:-}}\" == \"-lc\" && -n \"${{2:-}}\" ]]; then
  \"$SAFE_CODEX_BIN\" check-shell --quiet --config \"$SAFE_CODEX_CONFIG\" --cmd \"$2\"
fi

exec /bin/bash \"$@\"
"
    ))
}

fn build_command_shim_script(
    command_name: &str,
    real_path: &Path,
    safe_codex_bin: &Path,
) -> Result<String> {
    let real = real_path
        .to_str()
        .ok_or_else(|| anyhow!("real binary path for {command_name} is not valid UTF-8"))?;
    let bin = safe_codex_bin
        .to_str()
        .ok_or_else(|| anyhow!("safe-codex binary path is not valid UTF-8"))?;

    Ok(format!(
        "#!/usr/bin/env bash
set -euo pipefail

SAFE_CODEX_BIN=\"${{SAFE_CODEX_BIN:-{bin}}}\"
SAFE_CODEX_CONFIG=\"${{SAFE_CODEX_CONFIG:-{DEFAULT_CONFIG_PATH}}}\"

\"$SAFE_CODEX_BIN\" check-argv --quiet --config \"$SAFE_CODEX_CONFIG\" --bin \"{command_name}\" -- \"$@\"
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

fn resolve_binary_path(command_name: &str) -> Result<PathBuf> {
    let output = Command::new("which")
        .arg(command_name)
        .output()
        .with_context(|| format!("failed to run which for {command_name}"))?;

    if !output.status.success() {
        bail!("binary not found: {command_name}");
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        bail!("which returned empty path for {command_name}");
    }

    Ok(PathBuf::from(path))
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

    if !quiet {
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

    if !quiet {
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

fn write_audit(config: &Config, command: &str, decision: &Decision) -> Result<()> {
    let event = AuditEvent {
        timestamp: chrono::Utc::now(),
        event: "command_check".to_string(),
        command: command.to_string(),
        decision: decision.clone(),
    };

    append_event(&config.audit.log_path, &event)
}

fn fail_closed_decision(error: &str) -> Decision {
    Decision::block(
        format!("fail-closed: {error}"),
        "safe-codex",
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
