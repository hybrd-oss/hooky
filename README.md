<div align="center">
  <img src="assets/hooky.png" alt="hooky" width="400"/>

  # hooky

  **A configurable command firewall for AI agents and shells.**

  Brought to you by the [HYBRD](https://www.hybrd.com) engineering team.

  [![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
</div>

---

Hooky intercepts shell commands before they run and enforces a configurable policy — across every tool in your stack, uniformly.

- Block dangerous flags (`--no-verify`, `--force`, `--auto-approve`, `rm -rf`)
- Apply rules to any tool: Codex, Claude Code, CI scripts, or bare shell
- Audit every decision in a JSONL log with automatic secret redaction
- Extend coverage to any command via lightweight PATH shims

Instead of waiting for every AI agent to implement its own safety checks, wrap it in `hooky run` and get consistent enforcement everywhere.

---

## Quickstart

```bash
cargo install --path . --force

# Bootstrap config + shims
hooky init --global

# Verify setup
hooky doctor

# Test a blocked command
hooky check-shell --cmd "rm -rf fake-dir"

# Run any agent under Hooky
hooky run -- codex --help
hooky run -- claude --help
```

`hooky doctor` and `hooky install-shims` will add `.hooky/` to `.gitignore` if missing.

---

## How It Works

`hooky run -- <program>` starts your program with `.hooky/shims` prepended to `PATH`. Every shimmed command (`git`, `rm`, `mv`, `curl`, `bash`, `sh` by default) runs through Hooky's policy pipeline before the real binary executes.

Policy is evaluated across multiple engines with **deny-first** semantics — any block wins:

| Decision | Behavior |
|----------|----------|
| `allow` | Command runs normally, no output |
| `block` | Execution stops, reason printed to stderr, non-zero exit |
| `confirm` | Exits with code `10` |
| `rewrite` | Currently treated as `block` (deny-only mode) |

Every decision is appended to `.hooky/.hooky-log.jsonl`.

**Example — blocked command:**

```text
hooky Block: BLOCKED: Commands with --no-verify or --no-gpg-sign are not allowed.
Pre-commit hooks must always run. [rule: block-no-verify] [engine: claude_hooks]
```

Audit log entry:

```json
{
  "data": {
    "command": "git commit --no-verify -m test",
    "decision": {
      "kind": "block",
      "reason": "blocked by native rule block-no-verify",
      "rule_id": "block-no-verify",
      "engine": "native"
    }
  },
  "timestamp": "2026-02-12T19:40:02.314475Z"
}
```

See [docs/how-it-works.md](docs/how-it-works.md) for a detailed breakdown of the interception and evaluation pipeline.

---

## Configuration

Config lives in `.hooky.yml` (project-local) or `~/.hooky/config.yml` (global). When both exist, the project config overrides matching engine settings from global.

### Shims — which commands get intercepted

Add any binary to the shim list and regenerate:

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

### Native rules — custom block patterns

```yaml
engines:
  - type: native
    enabled: true
    merge_strategy: extend
    rules:
      - id: block-kubectl-delete-all
        action: block
        pattern: '\bkubectl\s+delete\b.*\s--all(\s|$)'

      - id: block-terraform-destroy-auto-approve
        action: block
        pattern: '\bterraform\s+destroy\b.*\s-auto-approve(\s|$)'
```

### DCG integration

[DCG](https://github.com/dicklesworthstone/destructive_command_guard) packs add an additional rule layer:

```bash
hooky setup dcg
hooky setup dcg --with-pack core.filesystem --with-pack containers.docker
hooky import dcg --from .dcg.toml
```

### Claude Code hook compatibility

Existing `.claude/hooks/` scripts (e.g. `block-no-verify.sh`) are picked up automatically — no migration needed.

See [docs/configuration.md](docs/configuration.md) for the full configuration reference.

---

## Global vs. Project Config

```bash
# Set global defaults for all repos
hooky init --global

# Add or override settings for one repo
cd /path/to/repo
hooky init
```

Global config applies everywhere. Project `.hooky.yml` takes precedence for that repo.
