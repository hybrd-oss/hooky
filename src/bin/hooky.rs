use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use hooky::hooky::audit::{append_event, clean_before_today, AuditEvent};
use hooky::hooky::config::{Config, EngineConfig};
use hooky::hooky::decision::{Decision, DecisionKind};
use hooky::hooky::{doctor, evaluator};
use hooky::types::response::CliResponse;
use regex::Regex;
use std::collections::BTreeSet;
use std::env;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const DEFAULT_SHIMS_DIR: &str = ".hooky/shims";
const REQUIRED_GITIGNORE_PATTERNS: [&str; 1] = [".hooky/"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeScope {
    Global,
    Project,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimePaths {
    scope: RuntimeScope,
    config_path: PathBuf,
    runtime_dir: PathBuf,
    audit_log_path: PathBuf,
    shims_dir: PathBuf,
}

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
    /// Initialize hooky config and runtime directory
    Init {
        /// Initialize global config at ~/.hooky/config.yml
        #[arg(long)]
        global: bool,

        /// Path to config file (project mode only)
        #[arg(long)]
        config: Option<PathBuf>,

        /// DCG executable command
        #[arg(long)]
        cmd: Option<String>,

        /// Path to DCG config file
        #[arg(long)]
        dcg_config: Option<PathBuf>,

        /// DCG pack to enable (can be provided multiple times)
        #[arg(long = "with-pack")]
        with_packs: Vec<String>,

        /// Enable DCG explain output
        #[arg(long)]
        explain: bool,
    },

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

    /// Delete audit log entries older than today
    Clean {
        /// Path to .hooky.yml
        #[arg(long)]
        config: Option<PathBuf>,
    },

    /// Guided setup helpers
    Setup {
        #[command(subcommand)]
        setup: SetupCommands,
    },

    /// Import settings from external tools
    Import {
        #[command(subcommand)]
        import: ImportCommands,
    },
}

#[derive(Subcommand)]
enum SetupCommands {
    /// Enable and configure the DCG engine in hooky config
    Dcg {
        /// Path to .hooky.yml
        #[arg(long)]
        config: Option<PathBuf>,

        /// DCG executable command
        #[arg(long)]
        cmd: Option<String>,

        /// Path to DCG config file
        #[arg(long)]
        dcg_config: Option<PathBuf>,

        /// DCG pack to enable (can be provided multiple times)
        #[arg(long = "with-pack")]
        with_packs: Vec<String>,

        /// Enable DCG explain output
        #[arg(long)]
        explain: bool,
    },
}

#[derive(Subcommand)]
enum ImportCommands {
    /// Import an existing DCG configuration into hooky
    Dcg {
        /// Path to DCG config file (for example: .dcg.toml)
        #[arg(long)]
        from: PathBuf,

        /// Path to .hooky.yml
        #[arg(long)]
        config: Option<PathBuf>,

        /// DCG executable command
        #[arg(long)]
        cmd: Option<String>,
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
        Commands::Init {
            global,
            config,
            cmd,
            dcg_config,
            with_packs,
            explain,
        } => run_init(
            global,
            config.as_deref(),
            cmd.as_deref(),
            dcg_config.as_deref(),
            &with_packs,
            explain,
        ),
        Commands::Run {
            config,
            shims_dir,
            target_and_args,
        } => run_program(config.as_deref(), shims_dir.as_deref(), &target_and_args),
        Commands::InstallShims { dir, force } => install_shims_command(dir.as_deref(), force),
        Commands::Doctor { config } => run_doctor(config.as_deref()),
        Commands::Clean { config } => run_clean(config.as_deref()),
        Commands::CheckShell { cmd, config, quiet } => {
            run_check_shell(config.as_deref(), &cmd, quiet)
        }
        Commands::CheckArgv {
            bin,
            args,
            config,
            quiet,
        } => run_check_argv(config.as_deref(), &bin, &args, quiet),
        Commands::Setup { setup } => match setup {
            SetupCommands::Dcg {
                config,
                cmd,
                dcg_config,
                with_packs,
                explain,
            } => run_setup_dcg(
                config.as_deref(),
                cmd.as_deref(),
                dcg_config.as_deref(),
                &with_packs,
                explain,
            ),
        },
        Commands::Import { import } => match import {
            ImportCommands::Dcg { from, config, cmd } => {
                run_import_dcg(&from, config.as_deref(), cmd.as_deref())
            }
        },
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

    let config = load_effective_config(config_path)?;
    let doctor_report = doctor::run(&config)?;
    if !doctor_report.ok {
        bail!("doctor checks failed; run `hooky doctor` for details");
    }

    let current_exe = std::env::current_exe().context("failed to resolve current executable")?;
    let runtime_paths = resolve_runtime_paths(config_path)?;
    let shims_path = shims_dir.map_or_else(|| runtime_paths.shims_dir.clone(), Path::to_path_buf);
    let shim_config_path = config_path.map(|path| {
        fs::canonicalize(path)
            .unwrap_or_else(|_| path.to_path_buf())
            .display()
            .to_string()
    });

    // `run` should be idempotent: refresh generated shims instead of failing
    // when they already exist from a prior `install-shims` or `run`.
    install_shims(
        &shims_path,
        true,
        &current_exe,
        shim_config_path.as_deref(),
        &config.shims.commands,
    )?;

    let shims_path = canonical_or_absolute_path(&shims_path)
        .with_context(|| format!("failed to resolve shims path {}", shims_path.display()))?;

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

fn run_init(
    global: bool,
    config_path: Option<&Path>,
    dcg_cmd: Option<&str>,
    dcg_config: Option<&Path>,
    with_packs: &[String],
    explain: bool,
) -> Result<()> {
    if global && config_path.is_some() {
        bail!("--config cannot be combined with --global");
    }

    let runtime_paths = if global {
        global_runtime_paths()?
    } else {
        project_runtime_paths(config_path)
    };
    let scope = match runtime_paths.scope {
        RuntimeScope::Global => "global".to_string(),
        RuntimeScope::Project => "project".to_string(),
    };

    if let Some(parent) = runtime_paths.config_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }
    fs::create_dir_all(&runtime_paths.runtime_dir)
        .with_context(|| format!("failed to create {}", runtime_paths.runtime_dir.display()))?;

    let mut config = Config::load(Some(&runtime_paths.config_path))?;

    // For global init, ensure the ClaudeHooks engine points to the absolute
    // ~/.claude/hooks path so it resolves correctly from any working directory.
    if global {
        let home = dirs::home_dir().ok_or_else(|| anyhow!("failed to determine home directory"))?;
        let global_hooks = home.join(".claude").join("hooks");
        for engine in &mut config.engines {
            if let EngineConfig::ClaudeHooks { hooks_dirs, .. } = engine {
                *hooks_dirs = vec![global_hooks.clone()];
            }
        }
    }

    upsert_dcg_engine(
        &mut config,
        true,
        dcg_cmd.unwrap_or("dcg"),
        dcg_config,
        with_packs,
        explain,
    );
    config
        .audit
        .log_path
        .clone_from(&runtime_paths.audit_log_path);
    write_config_file(&runtime_paths.config_path, &config)?;

    let resolved_dcg_cmd = dcg_cmd.unwrap_or("dcg");
    let dcg_found = program_exists(resolved_dcg_cmd);

    let response = CliResponse::success(InitResponse {
        scope,
        config_path: runtime_paths.config_path,
        runtime_dir: runtime_paths.runtime_dir,
        dcg_enabled: true,
        dcg_cmd: resolved_dcg_cmd.to_string(),
        dcg_config: dcg_config.map(Path::to_path_buf),
        with_packs: with_packs.to_vec(),
        explain,
        dcg_found,
    });
    let json =
        serde_json::to_string_pretty(&response).context("failed to serialize init response")?;
    println!("{json}");

    if !dcg_found {
        eprintln!(
            "\nhooky: DCG engine is enabled but '{resolved_dcg_cmd}' was not found.\n\
             Install DCG to activate the full rule set:\n\n  \
             curl -fsSL \"https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/install.sh?$(date +%s)\" | bash -s -- --easy-mode\n"
        );
    }

    Ok(())
}

fn program_exists(program: &str) -> bool {
    if program.contains('/') {
        return Path::new(program).exists();
    }

    evaluator::command_exists(program)
}

fn canonical_or_absolute_path(path: &Path) -> Result<PathBuf> {
    if let Ok(canonical) = fs::canonicalize(path) {
        return Ok(canonical);
    }

    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }

    let cwd = env::current_dir().context("failed to determine current directory")?;
    Ok(cwd.join(path))
}

fn install_shims_command(dir: Option<&Path>, force: bool) -> Result<()> {
    maybe_sync_gitignore_patterns();
    let config = load_effective_config(None)?;

    let current_exe = std::env::current_exe().context("failed to resolve current executable")?;
    let runtime_paths = resolve_runtime_paths(None)?;
    let target_dir = dir.map_or_else(|| runtime_paths.shims_dir, Path::to_path_buf);

    let installed = install_shims(
        &target_dir,
        force,
        &current_exe,
        None,
        &config.shims.commands,
    )?;
    let response = CliResponse::success(InstallShimsResponse {
        dir: target_dir,
        files_installed: installed,
    });

    let json =
        serde_json::to_string_pretty(&response).context("failed to serialize install-shims")?;
    println!("{json}");
    Ok(())
}

fn install_shims(
    dir: &Path,
    force: bool,
    hooky_bin: &Path,
    config_path: Option<&str>,
    shim_commands: &[String],
) -> Result<usize> {
    fs::create_dir_all(dir)
        .with_context(|| format!("failed to create shims directory {}", dir.display()))?;

    let safe_shell_path = dir.join("hooky-shell");
    let safe_shell_script = build_safe_shell_script(hooky_bin, config_path)?;
    write_executable_script(&safe_shell_path, &safe_shell_script, force)?;

    let mut installed = 1usize;
    for command_name in shim_commands {
        let real_path = resolve_binary_path(command_name, dir)
            .with_context(|| format!("failed to resolve binary path for {command_name}"))?;
        let shim_script =
            build_command_shim_script(command_name, &real_path, hooky_bin, config_path)?;
        let shim_path = dir.join(command_name);
        write_executable_script(&shim_path, &shim_script, force)?;
        installed += 1;
    }

    Ok(installed)
}

fn build_safe_shell_script(hooky_bin: &Path, config_path: Option<&str>) -> Result<String> {
    let bin = hooky_bin
        .to_str()
        .ok_or_else(|| anyhow!("hooky binary path is not valid UTF-8"))?;
    let config_setup = build_config_args_setup(config_path);

    Ok(format!(
        "#!/bin/bash
set -euo pipefail

HOOKY_BIN=\"{bin}\"
{config_setup}

if [[ \"${{1:-}}\" == \"-c\" && -n \"${{2:-}}\" ]]; then
  \"$HOOKY_BIN\" check-shell --quiet \"${{HOOKY_CONFIG_ARGS[@]}}\" --cmd \"$2\"
elif [[ \"${{1:-}}\" == \"-lc\" && -n \"${{2:-}}\" ]]; then
  \"$HOOKY_BIN\" check-shell --quiet \"${{HOOKY_CONFIG_ARGS[@]}}\" --cmd \"$2\"
elif [[ \"${{1:-}}\" == \"-l\" && \"${{2:-}}\" == \"-c\" && -n \"${{3:-}}\" ]]; then
  \"$HOOKY_BIN\" check-shell --quiet \"${{HOOKY_CONFIG_ARGS[@]}}\" --cmd \"$3\"
fi

exec /bin/bash \"$@\"
"
    ))
}

fn build_command_shim_script(
    command_name: &str,
    real_path: &Path,
    hooky_bin: &Path,
    config_path: Option<&str>,
) -> Result<String> {
    let real = real_path
        .to_str()
        .ok_or_else(|| anyhow!("real binary path for {command_name} is not valid UTF-8"))?;
    let bin = hooky_bin
        .to_str()
        .ok_or_else(|| anyhow!("hooky binary path is not valid UTF-8"))?;
    let config_setup = build_config_args_setup(config_path);

    Ok(format!(
        "#!/bin/bash
set -euo pipefail

HOOKY_BIN=\"{bin}\"
{config_setup}

\"$HOOKY_BIN\" check-argv --quiet \"${{HOOKY_CONFIG_ARGS[@]}}\" --bin \"{command_name}\" -- \"$@\"
exec \"{real}\" \"$@\"
"
    ))
}

fn build_config_args_setup(config_path: Option<&str>) -> String {
    match config_path {
        Some(path) => format!("HOOKY_CONFIG_ARGS=(--config \"{path}\")\n"),
        None => "HOOKY_CONFIG_ARGS=()
if [[ -f \".hooky.yml\" ]]; then
  HOOKY_CONFIG_ARGS=(--config \".hooky.yml\")
elif [[ -f \"$HOME/.hooky/config.yml\" ]]; then
  HOOKY_CONFIG_ARGS=(--config \"$HOME/.hooky/config.yml\")
fi
"
        .to_string(),
    }
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

fn load_effective_config(config_path: Option<&Path>) -> Result<Config> {
    let mut config = match config_path {
        Some(path) => Config::load(Some(path)),
        None => Config::load_merged(None),
    }?;

    config.audit.log_path = resolve_audit_log_path(&config.audit.log_path)?;
    Ok(config)
}

fn resolve_runtime_paths(config_path: Option<&Path>) -> Result<RuntimePaths> {
    match config_path {
        Some(path) => runtime_paths_for_config(path),
        None => detect_default_runtime_paths(),
    }
}

fn detect_default_runtime_paths() -> Result<RuntimePaths> {
    let local_config = Path::new(".hooky.yml");
    if local_config.exists() {
        return Ok(project_runtime_paths(Some(local_config)));
    }

    let global = global_runtime_paths()?;
    if global.config_path.exists() {
        return Ok(global);
    }

    Ok(project_runtime_paths(None))
}

fn runtime_paths_for_config(config_path: &Path) -> Result<RuntimePaths> {
    let candidate = config_path.to_path_buf();
    let global = global_runtime_paths()?;
    if paths_refer_to_same_location(&candidate, &global.config_path) {
        return Ok(global);
    }

    Ok(project_runtime_paths(Some(config_path)))
}

fn global_runtime_paths() -> Result<RuntimePaths> {
    let hooky_dir = home_hooky_dir()?;
    Ok(RuntimePaths {
        scope: RuntimeScope::Global,
        config_path: hooky_dir.join("config.yml"),
        runtime_dir: hooky_dir.clone(),
        audit_log_path: PathBuf::from(".hooky-log.jsonl"),
        shims_dir: hooky_dir.join("shims"),
    })
}

fn project_runtime_paths(config_path: Option<&Path>) -> RuntimePaths {
    let config_path = config_path.map_or_else(|| PathBuf::from(".hooky.yml"), Path::to_path_buf);
    let base_dir = config_parent_dir(&config_path);
    RuntimePaths {
        scope: RuntimeScope::Project,
        config_path,
        runtime_dir: base_dir.join(".hooky"),
        audit_log_path: PathBuf::from(".hooky/.hooky-log.jsonl"),
        shims_dir: base_dir.join(DEFAULT_SHIMS_DIR),
    }
}

fn config_parent_dir(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

fn home_hooky_dir() -> Result<PathBuf> {
    Ok(dirs::home_dir()
        .ok_or_else(|| anyhow!("failed to determine home directory"))?
        .join(".hooky"))
}

fn paths_refer_to_same_location(left: &Path, right: &Path) -> bool {
    let left = fs::canonicalize(left).unwrap_or_else(|_| left.to_path_buf());
    let right = fs::canonicalize(right).unwrap_or_else(|_| right.to_path_buf());
    left == right
}

fn resolve_audit_log_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }

    let cwd = env::current_dir().context("failed to determine current directory")?;
    Ok(resolve_audit_log_path_from_start(path, &cwd))
}

fn resolve_audit_log_path_from_start(path: &Path, start: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }

    if let Some(hooky_dir) = find_nearest_hooky_dir(start) {
        if let Ok(suffix) = path.strip_prefix(".hooky") {
            return hooky_dir.join(suffix);
        }

        let hooky_root = hooky_dir.parent().unwrap_or(hooky_dir.as_path());
        return hooky_root.join(path);
    }

    path.to_path_buf()
}

fn find_nearest_hooky_dir(start: &Path) -> Option<PathBuf> {
    let mut current = start.to_path_buf();
    loop {
        let hooky_dir = current.join(".hooky");
        if hooky_dir.is_dir() {
            return Some(hooky_dir);
        }

        if !current.pop() {
            return None;
        }
    }
}

fn run_doctor(config_path: Option<&Path>) -> Result<()> {
    maybe_sync_gitignore_patterns();

    let config = load_effective_config(config_path)?;
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

fn run_clean(config_path: Option<&Path>) -> Result<()> {
    let config = load_effective_config(config_path)?;
    let removed = clean_before_today(&config.audit.log_path)?;
    let response = CliResponse::success(serde_json::json!({
        "removed": removed,
        "log_path": config.audit.log_path.display().to_string(),
    }));
    let json =
        serde_json::to_string_pretty(&response).context("failed to serialize clean response")?;
    println!("{json}");
    Ok(())
}

fn run_check_shell(config_path: Option<&Path>, command: &str, quiet: bool) -> Result<()> {
    let config = load_effective_config(config_path)?;
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
    let config = load_effective_config(config_path)?;
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

fn maybe_sync_gitignore_patterns() {
    match ensure_gitignore_entries(Path::new(".gitignore"), &REQUIRED_GITIGNORE_PATTERNS) {
        Ok(true) => {
            eprintln!("hooky: updated .gitignore with runtime artifacts (.hooky/)");
        }
        Ok(false) => {}
        Err(err) => {
            eprintln!("hooky warning: failed to update .gitignore: {err}");
        }
    }
}

fn ensure_gitignore_entries(path: &Path, entries: &[&str]) -> Result<bool> {
    let existing = if path.exists() {
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?
    } else {
        String::new()
    };

    let existing_patterns = existing
        .lines()
        .map(normalize_gitignore_pattern)
        .filter(|pattern| !pattern.is_empty())
        .collect::<BTreeSet<String>>();

    let missing = entries
        .iter()
        .copied()
        .filter(|entry| !existing_patterns.contains(&normalize_gitignore_pattern(entry)))
        .collect::<Vec<&str>>();

    if missing.is_empty() {
        return Ok(false);
    }

    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    for entry in missing {
        updated.push_str(entry);
        updated.push('\n');
    }

    fs::write(path, updated).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(true)
}

fn normalize_gitignore_pattern(pattern: &str) -> String {
    pattern
        .trim()
        .trim_start_matches('/')
        .split('#')
        .next()
        .map_or_else(String::new, |value| value.trim().to_string())
}

fn run_setup_dcg(
    config_path: Option<&Path>,
    dcg_cmd: Option<&str>,
    dcg_config: Option<&Path>,
    with_packs: &[String],
    explain: bool,
) -> Result<()> {
    let config_path = config_path.map_or_else(|| PathBuf::from(".hooky.yml"), Path::to_path_buf);
    let mut config = Config::load(Some(&config_path))?;

    upsert_dcg_engine(
        &mut config,
        true,
        dcg_cmd.unwrap_or("dcg"),
        dcg_config,
        with_packs,
        explain,
    );
    write_config_file(&config_path, &config)?;

    let response = CliResponse::success(SetupDcgResponse {
        config_path,
        enabled: true,
        dcg_cmd: dcg_cmd.unwrap_or("dcg").to_string(),
        dcg_config: dcg_config.map(Path::to_path_buf),
        with_packs: with_packs.to_vec(),
        explain,
    });
    let json =
        serde_json::to_string_pretty(&response).context("failed to serialize setup response")?;
    println!("{json}");
    Ok(())
}

fn run_import_dcg(from: &Path, config_path: Option<&Path>, dcg_cmd: Option<&str>) -> Result<()> {
    if !from.exists() {
        bail!("dcg config file not found: {}", from.display());
    }

    let config_path = config_path.map_or_else(|| PathBuf::from(".hooky.yml"), Path::to_path_buf);
    let mut config = Config::load(Some(&config_path))?;
    upsert_dcg_engine(
        &mut config,
        true,
        dcg_cmd.unwrap_or("dcg"),
        Some(from),
        &[],
        false,
    );
    write_config_file(&config_path, &config)?;

    let response = CliResponse::success(ImportDcgResponse {
        config_path,
        imported_from: from.to_path_buf(),
        dcg_cmd: dcg_cmd.unwrap_or("dcg").to_string(),
    });
    let json =
        serde_json::to_string_pretty(&response).context("failed to serialize import response")?;
    println!("{json}");
    Ok(())
}

fn upsert_dcg_engine(
    config: &mut Config,
    enabled: bool,
    cmd: &str,
    dcg_config: Option<&Path>,
    with_packs: &[String],
    explain: bool,
) {
    let mut replaced = false;
    for engine in &mut config.engines {
        if matches!(engine, EngineConfig::Dcg { .. }) {
            *engine = EngineConfig::Dcg {
                enabled,
                cmd: cmd.to_string(),
                args: Vec::new(),
                config: dcg_config.map(Path::to_path_buf),
                with_packs: with_packs.to_vec(),
                explain,
            };
            replaced = true;
            break;
        }
    }

    if !replaced {
        config.engines.push(EngineConfig::Dcg {
            enabled,
            cmd: cmd.to_string(),
            args: Vec::new(),
            config: dcg_config.map(Path::to_path_buf),
            with_packs: with_packs.to_vec(),
            explain,
        });
    }
}

fn write_config_file(path: &Path, config: &Config) -> Result<()> {
    let yaml = serde_yaml::to_string(config).context("failed to serialize hooky config to yaml")?;
    fs::write(path, yaml).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
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

#[derive(serde::Serialize)]
struct SetupDcgResponse {
    config_path: PathBuf,
    enabled: bool,
    dcg_cmd: String,
    dcg_config: Option<PathBuf>,
    with_packs: Vec<String>,
    explain: bool,
}

#[derive(serde::Serialize)]
struct ImportDcgResponse {
    config_path: PathBuf,
    imported_from: PathBuf,
    dcg_cmd: String,
}

#[derive(serde::Serialize)]
struct InitResponse {
    scope: String,
    config_path: PathBuf,
    runtime_dir: PathBuf,
    dcg_enabled: bool,
    dcg_cmd: String,
    dcg_config: Option<PathBuf>,
    with_packs: Vec<String>,
    explain: bool,
    dcg_found: bool,
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
        let script =
            build_safe_shell_script(Path::new("/tmp/hooky"), None).expect("script generation");

        assert!(script.starts_with("#!/bin/bash\n"));
        assert!(script.contains("\"${1:-}\" == \"-c\""));
        assert!(script.contains("\"${1:-}\" == \"-lc\""));
        assert!(script.contains("\"${1:-}\" == \"-l\" && \"${2:-}\" == \"-c\""));
    }

    #[test]
    fn safe_shell_script_ignores_runtime_env_overrides() {
        let script = build_safe_shell_script(Path::new("/tmp/hooky"), Some("/tmp/hooky.yml"))
            .expect("script generation");

        assert!(script.contains("HOOKY_BIN=\"/tmp/hooky\""));
        assert!(script.contains("HOOKY_CONFIG_ARGS=(--config \"/tmp/hooky.yml\")"));
        assert!(script.contains("\"${HOOKY_CONFIG_ARGS[@]}\" --cmd"));
        assert!(!script.contains("${HOOKY_BIN:-"));
        assert!(!script.contains("${HOOKY_CONFIG:-"));
    }

    #[test]
    fn safe_shell_script_discovers_local_then_global_config() {
        let script =
            build_safe_shell_script(Path::new("/tmp/hooky"), None).expect("script generation");

        assert!(script.contains("HOOKY_CONFIG_ARGS=()"));
        assert!(script.contains("if [[ -f \".hooky.yml\" ]]; then"));
        assert!(script.contains("HOOKY_CONFIG_ARGS=(--config \".hooky.yml\")"));
        assert!(script.contains("elif [[ -f \"$HOME/.hooky/config.yml\" ]]; then"));
        assert!(script.contains("HOOKY_CONFIG_ARGS=(--config \"$HOME/.hooky/config.yml\")"));
        assert!(script.contains(
            "\"$HOOKY_BIN\" check-shell --quiet \"${HOOKY_CONFIG_ARGS[@]}\" --cmd \"$2\""
        ));
    }

    #[test]
    fn command_shim_uses_absolute_bash_shebang() {
        let script = build_command_shim_script(
            "git",
            Path::new("/usr/bin/git"),
            Path::new("/tmp/hooky"),
            None,
        )
        .expect("script generation");

        assert!(script.starts_with("#!/bin/bash\n"));
    }

    #[test]
    fn command_shim_ignores_runtime_env_overrides() {
        let script = build_command_shim_script(
            "git",
            Path::new("/usr/bin/git"),
            Path::new("/tmp/hooky"),
            Some("/tmp/hooky.yml"),
        )
        .expect("script generation");

        assert!(script.contains("HOOKY_BIN=\"/tmp/hooky\""));
        assert!(script.contains("HOOKY_CONFIG_ARGS=(--config \"/tmp/hooky.yml\")"));
        assert!(script.contains("check-argv --quiet \"${HOOKY_CONFIG_ARGS[@]}\" --bin \"git\""));
        assert!(!script.contains("${HOOKY_BIN:-"));
        assert!(!script.contains("${HOOKY_CONFIG:-"));
    }

    #[test]
    fn command_shim_discovers_local_then_global_config() {
        let script = build_command_shim_script(
            "git",
            Path::new("/usr/bin/git"),
            Path::new("/tmp/hooky"),
            None,
        )
        .expect("script generation");

        assert!(script.contains("HOOKY_CONFIG_ARGS=()"));
        assert!(script.contains("if [[ -f \".hooky.yml\" ]]; then"));
        assert!(script.contains("HOOKY_CONFIG_ARGS=(--config \".hooky.yml\")"));
        assert!(script.contains("elif [[ -f \"$HOME/.hooky/config.yml\" ]]; then"));
        assert!(script.contains("HOOKY_CONFIG_ARGS=(--config \"$HOME/.hooky/config.yml\")"));
        assert!(script.contains(
            "\"$HOOKY_BIN\" check-argv --quiet \"${HOOKY_CONFIG_ARGS[@]}\" --bin \"git\" -- \"$@\""
        ));
    }

    #[test]
    fn ensure_gitignore_entries_appends_missing_patterns() {
        let temp = tempfile::tempdir().expect("tempdir should be created");
        let gitignore_path = temp.path().join(".gitignore");
        fs::write(&gitignore_path, "/target\n").expect("gitignore should be created");

        let changed = ensure_gitignore_entries(&gitignore_path, &REQUIRED_GITIGNORE_PATTERNS)
            .expect("gitignore update should succeed");
        assert!(changed);

        let content = fs::read_to_string(gitignore_path).expect("gitignore should be readable");
        assert!(content.contains(".hooky/\n"));
    }

    #[test]
    fn ensure_gitignore_entries_is_idempotent_for_slash_prefixed_patterns() {
        let temp = tempfile::tempdir().expect("tempdir should be created");
        let gitignore_path = temp.path().join(".gitignore");
        fs::write(&gitignore_path, "/target\n/.hooky/\n").expect("gitignore should be created");

        let changed = ensure_gitignore_entries(&gitignore_path, &REQUIRED_GITIGNORE_PATTERNS)
            .expect("gitignore update should succeed");
        assert!(!changed);
    }

    #[test]
    fn resolve_audit_log_path_anchors_default_path_to_nearest_hooky_dir() {
        let temp = tempfile::tempdir().expect("tempdir should be created");
        let root = temp.path().join("repo");
        let nested = root.join("frontend/src");
        let hooky_dir = root.join(".hooky");
        fs::create_dir_all(&nested).expect("nested dir should exist");
        fs::create_dir_all(&hooky_dir).expect("hooky dir should exist");

        let resolved =
            resolve_audit_log_path_from_start(Path::new(".hooky/.hooky-log.jsonl"), &nested);

        assert_eq!(resolved, hooky_dir.join(".hooky-log.jsonl"));
    }
}
