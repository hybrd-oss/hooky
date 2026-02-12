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
