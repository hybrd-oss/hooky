<div align="center">
  <img src="assets/hooky.png" alt="hooky" width="400"/>

  # hooky

  **A command firewall for AI agents.**

  Brought to you by the [HYBRD](https://www.hybrd.com) engineering team.

  [![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
</div>

---

AI agents in yolo mode are fast — but they'll happily run `git commit --no-verify`, `git push --force`, or `rm -rf` without thinking twice. Hooky wraps any agent in a configurable policy layer that intercepts commands before they execute, enforces your rules, and logs every decision.

Works with **Codex**, **Claude Code**, or anything that runs shell commands.

---

## Setup

```bash
# 1. Install DCG (the core rule engine)
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/destructive_command_guard/main/install.sh?$(date +%s)" | bash -s -- --easy-mode

# 2. Install Hooky
cargo install --path . --force

# 3. Create config (global recommended — applies to all repos)
hooky init --global

# 4. Run your agent through Hooky — shims install automatically on first run
hooky run -- codex
hooky run -- claude
```

That's it. Hooky intercepts commands at the shell level and enforces rules before anything runs.

> **Verify your setup** — `hooky doctor` checks that DCG is installed, shims are active, and config is valid.

---

## What's blocked out of the box

Hooky ships with three default rules:

| Rule | What it blocks |
|------|----------------|
| `block-no-verify` | `git commit --no-verify`, `--no-gpg-sign`, `-n` — pre-commit hooks must always run |
| `block-force-push` | `git push --force` — use `--force-with-lease` instead |
| `block-skip-env` | `SKIP=...` env prefix — bypassing hook runners |

When a command is blocked, the agent sees a clear error:

```text
hooky Block: BLOCKED: Commands with --no-verify or --no-gpg-sign are not allowed.
Pre-commit hooks must always run. [rule: block-no-verify] [engine: native]
```

Every decision — allowed or blocked — is appended to `.hooky/.hooky-log.jsonl` with the command, rule, engine, and timestamp.

---

## Adding your own rules

Edit `.hooky.yml` (project) or `~/.hooky/config.yml` (global):

```yaml
engines:
  - type: native
    enabled: true
    merge_strategy: extend   # adds to built-in rules
    rules:
      - id: block-kubectl-delete-all
        action: block
        pattern: '\bkubectl\s+delete\b.*\s--all(\s|$)'

      - id: block-terraform-destroy
        action: block
        pattern: '\bterraform\s+destroy\b.*\s-auto-approve(\s|$)'
```

Test a rule immediately:

```bash
hooky check-shell --cmd "kubectl delete pods --all -n prod"
# hooky Block: BLOCKED ...
```

---

## Extending command coverage

By default, Hooky intercepts `git`, `rm`, `mv`, `curl`, `bash`, and `sh`. Add any binary:

```yaml
shims:
  commands:
    - git
    - rm
    - docker
    - kubectl
    - terraform
```

```bash
hooky install-shims --force
```

---

## Verify your setup

```bash
hooky doctor
```

Checks that shims are installed, config is valid, and `.hooky/` is in `.gitignore`.

---

## Global vs. project config

```bash
hooky init --global   # ~/.hooky/config.yml — defaults for all repos
hooky init            # .hooky.yml — overrides for this repo
```

When both exist, the project config overrides matching engine settings from global.

---

## Claude Code hook compatibility

If you have `.claude/hooks/` scripts (e.g. from [DCG](https://github.com/dicklesworthstone/destructive_command_guard)), Hooky picks them up automatically — no migration needed. The `claude_hooks` engine is enabled by default.

---

For deeper configuration options (DCG packs, local hooks, audit settings) see [docs/configuration.md](docs/configuration.md).
For how interception and policy evaluation work under the hood, see [docs/how-it-works.md](docs/how-it-works.md).
