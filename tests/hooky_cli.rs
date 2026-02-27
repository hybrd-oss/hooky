use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::Path;

fn write_native_config(config_path: &Path, audit_path: &Path) {
    let config = format!(
        "version: 1
mode: enforce
engines:
  - type: native
    enabled: true
    rules:
      - id: block-no-verify
        action: block
        pattern: \"--no-verify\"
        rewrite: ~
      - id: force-to-lease
        action: rewrite
        pattern: \"--force\"
        rewrite: \"git push --force-with-lease\"
audit:
  log_path: \"{}\"
",
        audit_path.display()
    );

    fs::write(config_path, config).expect("failed to write test config");
}

#[test]
fn check_shell_blocks_without_running_git() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let config_path = temp.path().join("hooky.yml");
    let audit_path = temp.path().join("audit.jsonl");
    write_native_config(&config_path, &audit_path);

    Command::new(env!("CARGO_BIN_EXE_hooky"))
        .args([
            "check-shell",
            "--config",
            config_path.to_str().expect("path should be valid utf-8"),
            "--cmd",
            "git commit --no-verify -m test",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("\"kind\": \"block\""));

    let audit = fs::read_to_string(audit_path).expect("audit file should exist");
    assert!(audit.contains("git commit --no-verify -m test"));
    assert!(audit.contains("\"kind\":\"block\""));
}

#[test]
fn check_argv_denies_force_push_in_deny_only_mode() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let config_path = temp.path().join("hooky.yml");
    let audit_path = temp.path().join("audit.jsonl");
    write_native_config(&config_path, &audit_path);

    Command::new(env!("CARGO_BIN_EXE_hooky"))
        .args([
            "check-argv",
            "--config",
            config_path.to_str().expect("path should be valid utf-8"),
            "--bin",
            "git",
            "--",
            "push",
            "origin",
            "main",
            "--force",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("\"kind\": \"block\""))
        .stdout(predicate::str::contains("deny-only mode"));
}

#[test]
fn check_argv_quiet_still_prints_failure_details() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let config_path = temp.path().join("hooky.yml");
    let audit_path = temp.path().join("audit.jsonl");
    write_native_config(&config_path, &audit_path);

    Command::new(env!("CARGO_BIN_EXE_hooky"))
        .args([
            "check-argv",
            "--quiet",
            "--config",
            config_path.to_str().expect("path should be valid utf-8"),
            "--bin",
            "git",
            "--",
            "commit",
            "--no-verify",
            "-m",
            "test",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("hooky Block:"))
        .stderr(predicate::str::contains("rule: block-no-verify"));
}

#[test]
fn install_shims_creates_expected_files() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let shims_dir = temp.path().join("shims");

    Command::new(env!("CARGO_BIN_EXE_hooky"))
        .args([
            "install-shims",
            "--dir",
            shims_dir.to_str().expect("path should be valid utf-8"),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"files_installed\""));

    let expected = ["hooky-shell", "git", "rm", "mv", "curl", "bash", "sh"];
    for file in expected {
        assert!(
            shims_dir.join(file).exists(),
            "expected shim {file} to exist"
        );
    }
}

#[test]
fn check_shell_audit_redacts_secrets() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let config_path = temp.path().join("hooky.yml");
    let audit_path = temp.path().join("audit.jsonl");
    write_native_config(&config_path, &audit_path);

    Command::new(env!("CARGO_BIN_EXE_hooky"))
        .args([
            "check-shell",
            "--config",
            config_path.to_str().expect("path should be valid utf-8"),
            "--cmd",
            "curl -H 'Authorization: Bearer topsecret' --token abc123 https://user:pass@example.com",
        ])
        .assert()
        .success();

    let audit = fs::read_to_string(audit_path).expect("audit file should exist");
    assert!(audit.contains("Bearer [REDACTED]"));
    assert!(audit.contains("--token [REDACTED]"));
    assert!(audit.contains("https://user:[REDACTED]@example.com"));
    assert!(!audit.contains("topsecret"));
    assert!(!audit.contains("abc123"));
    assert!(!audit.contains("pass@example.com"));
}

#[test]
fn run_requires_target_program() {
    Command::new(env!("CARGO_BIN_EXE_hooky"))
        .arg("run")
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "required arguments were not provided",
        ));
}

#[test]
fn run_executes_generic_target_program() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let config_path = temp.path().join("hooky.yml");
    let audit_path = temp.path().join("audit.jsonl");
    let shims_dir = temp.path().join("shims");
    write_native_config(&config_path, &audit_path);

    Command::new(env!("CARGO_BIN_EXE_hooky"))
        .args([
            "run",
            "--config",
            config_path.to_str().expect("path should be valid utf-8"),
            "--shims-dir",
            shims_dir.to_str().expect("path should be valid utf-8"),
            "--",
            "echo",
            "hooky-run-smoke",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("hooky-run-smoke"));
}

#[test]
fn run_is_idempotent_after_install_shims() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let config_path = temp.path().join("hooky.yml");
    let audit_path = temp.path().join("audit.jsonl");
    let shims_dir = temp.path().join("shims");
    write_native_config(&config_path, &audit_path);

    Command::new(env!("CARGO_BIN_EXE_hooky"))
        .args([
            "install-shims",
            "--dir",
            shims_dir.to_str().expect("path should be valid utf-8"),
        ])
        .assert()
        .success();

    Command::new(env!("CARGO_BIN_EXE_hooky"))
        .args([
            "run",
            "--config",
            config_path.to_str().expect("path should be valid utf-8"),
            "--shims-dir",
            shims_dir.to_str().expect("path should be valid utf-8"),
            "--",
            "echo",
            "hooky-idempotent",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("hooky-idempotent"));
}

#[test]
fn run_with_relative_shims_dir_exports_absolute_path_prefix() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let config_path = temp.path().join("hooky.yml");
    let audit_path = temp.path().join("audit.jsonl");
    write_native_config(&config_path, &audit_path);

    Command::new(env!("CARGO_BIN_EXE_hooky"))
        .current_dir(temp.path())
        .args([
            "run",
            "--config",
            config_path.to_str().expect("path should be valid utf-8"),
            "--shims-dir",
            "shims",
            "--",
            "bash",
            "-lc",
            "first=\"${PATH%%:*}\"; [[ \"$first\" = /* ]] && echo absolute-prefix",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("absolute-prefix"));
}

#[test]
fn setup_dcg_writes_enabled_dcg_engine_config() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let config_path = temp.path().join("hooky.yml");

    Command::new(env!("CARGO_BIN_EXE_hooky"))
        .current_dir(temp.path())
        .args([
            "setup",
            "dcg",
            "--config",
            config_path.to_str().expect("path should be valid utf-8"),
            "--dcg-config",
            "/tmp/dcg.toml",
            "--with-pack",
            "containers.docker",
            "--explain",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"enabled\": true"));

    let written = fs::read_to_string(&config_path).expect("config should be written");
    assert!(written.contains("type: dcg"));
    assert!(written.contains("enabled: true"));
    assert!(written.contains("config: /tmp/dcg.toml"));
    assert!(written.contains("with_packs:"));
    assert!(written.contains("containers.docker"));
    assert!(written.contains("explain: true"));
}

#[test]
fn init_project_bootstraps_config_and_runtime_dir() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let config_path = temp.path().join(".hooky.yml");
    let runtime_dir = temp.path().join(".hooky");

    Command::new(env!("CARGO_BIN_EXE_hooky"))
        .current_dir(temp.path())
        .arg("init")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"scope\": \"project\""))
        .stdout(predicate::str::contains("\"dcg_enabled\": true"));

    let written = fs::read_to_string(&config_path).expect("config should be written");
    assert!(written.contains("type: dcg"));
    assert!(written.contains("enabled: true"));
    assert!(written.contains("log_path: .hooky/.hooky-log.jsonl"));
    assert!(runtime_dir.exists(), "runtime dir should exist");
}

#[test]
fn init_global_writes_home_config_with_global_audit_path() {
    let temp_home = tempfile::tempdir().expect("tempdir should be created");
    let global_dir = temp_home.path().join(".hooky");
    let config_path = global_dir.join("config.yml");

    Command::new(env!("CARGO_BIN_EXE_hooky"))
        .env("HOME", temp_home.path())
        .arg("init")
        .arg("--global")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"scope\": \"global\""))
        .stdout(predicate::str::contains("\"dcg_enabled\": true"));

    let written = fs::read_to_string(&config_path).expect("global config should be written");
    assert!(written.contains("type: dcg"));
    assert!(written.contains("enabled: true"));
    assert!(written.contains("log_path: .hooky-log.jsonl"));
    assert!(global_dir.exists(), "global .hooky dir should exist");
}

#[test]
fn check_argv_allows_bash_precommit_with_n_test() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let config_path = temp.path().join("hooky.yml");
    let audit_path = temp.path().join("audit.jsonl");

    // Use default config (which includes the default native rules with argv_match)
    let config = format!(
        "version: 1
mode: enforce
audit:
  log_path: \"{}\"
",
        audit_path.display()
    );
    fs::write(&config_path, config).expect("failed to write test config");

    // This is the false-positive case: bash running a pre-commit hook
    // The -n in [ -n "$CI" ] should NOT trigger the block-no-verify rule
    Command::new(env!("CARGO_BIN_EXE_hooky"))
        .args([
            "check-argv",
            "--config",
            config_path.to_str().expect("path should be valid utf-8"),
            "--bin",
            "bash",
            "--",
            "-c",
            "[ -n \"$CI\" ] && pre-commit run",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"kind\": \"allow\""));
}

#[test]
fn import_dcg_points_hooky_to_existing_dcg_config() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let dcg_path = temp.path().join(".dcg.toml");
    let hooky_config_path = temp.path().join("hooky.yml");
    fs::write(&dcg_path, "# test config\n").expect("dcg config should be created");

    Command::new(env!("CARGO_BIN_EXE_hooky"))
        .current_dir(temp.path())
        .args([
            "import",
            "dcg",
            "--from",
            dcg_path.to_str().expect("path should be valid utf-8"),
            "--config",
            hooky_config_path
                .to_str()
                .expect("path should be valid utf-8"),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("imported_from"));

    let written = fs::read_to_string(&hooky_config_path).expect("config should be written");
    assert!(written.contains("type: dcg"));
    assert!(written.contains("enabled: true"));
    assert!(written.contains(&format!("config: {}", dcg_path.display())));
}

#[test]
fn check_argv_from_subdirectory_writes_audit_to_repo_hooky_dir() {
    let temp = tempfile::tempdir().expect("tempdir should be created");
    let temp_home = tempfile::tempdir().expect("tempdir should be created");
    let root = temp.path().join("repo");
    let frontend = root.join("frontend");
    let hooky_dir = root.join(".hooky");
    let audit_path = hooky_dir.join(".hooky-log.jsonl");

    fs::create_dir_all(&frontend).expect("frontend dir should exist");
    fs::create_dir_all(&hooky_dir).expect("hooky dir should exist");

    Command::new(env!("CARGO_BIN_EXE_hooky"))
        .env("HOME", temp_home.path())
        .current_dir(&frontend)
        .args([
            "check-argv",
            "--quiet",
            "--bin",
            "bash",
            "--",
            "-c",
            "echo test",
        ])
        .assert()
        .success();

    let audit = fs::read_to_string(audit_path).expect("audit file should exist");
    assert!(audit.contains("\"event\":\"command_check\""));
}
