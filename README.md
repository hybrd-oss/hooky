<div align="center">
  <img src="assets/hooky.png" alt="hooky" width="400"/>

  # hooky

  **A configurable command firewall for shells and agents.**

  Brought to you by the [HYBRD](https://www.hybrd.com) engineering team.

  [![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
</div>

---

## Why Hooky?

**Claude Code's hooks are great** (shout out to [DCG](github.com/dicklesworthstone/destructive_command_guard)). They prevent dangerous commands like `git commit --no-verify` or `git push --force` from running inside Claude Code sessions. But for some wild reason, Codex doesn't have any support for this.

Agents work best in yolo mode, you just need to give them some bowling bumpers when they're speeding down the lane. Hooky is the bowling bumpers to any of your workloads (I don't think that was gramatically correct).

Hooky acts as a universal command firewall that intercepts commands at the shell level:

- **Bring Claude Code safety to Codex**: Your existing Claude Code hooks (block `--no-verify`, `--force`, etc.) work automatically
- **Universal enforcement**: Works with Codex, Claude Code, bash scripts, or any tool that runs shell commands
- **Audit logging**: JSONL logs capture every command decision with secret redaction
- **Extensible**: Add custom rules beyond the Claude Code hook format

Instead of waiting for every tool to implement its own safety checks, wrap your agent in `hooky run` and get consistent protection everywhere.

---

## Specs

See `docs/specs/00-overview.md` for the spec index and current implementation overview.

---

## Current behavior

- Deny-first policy (`allow`, `block`, `confirm`)
- Rewrite actions are currently denied by combiner behavior (deny-only mode)
- Claude hook compatibility via `.claude/hooks/block-no-verify.sh`
- JSONL audit logging to `.hooky/.hooky-log.jsonl` with best-effort secret redaction
- Default shim coverage is `git`, `rm`, `mv`, `curl`, `bash`, and `sh`; this can be extended to any command by adding more shim targets

## Quickstart

```bash
cargo install --path . --force

# One-time global bootstrap (recommended)
hooky init --global

# Verify DCG is enabled
hooky doctor

# Sanity check: this should be blocked by DCG
hooky check-shell --cmd "rm -rf fake-dir"

# Run tools under hooky
hooky run -- codex --help
hooky run -- claude --help
```

`hooky doctor` and `hooky install-shims` will best-effort add `.hooky/` to `.gitignore` if missing.

## Agent Setup Examples

### Codex

```bash
# In your repo (project-local config)
hooky init
hooky run -- codex
```

Codex commands will execute through Hooky shims and policy engines.

### Claude Code

```bash
# In your repo (project-local config)
hooky init
hooky run -- claude
```

Existing Claude-compatible hook scripts (for example `.claude/hooks/block-no-verify.sh`) are used when present.

### Global setup + per-repo override

```bash
# Global defaults for all repos
hooky init --global

# Optional: customize one repo
cd /path/to/repo
hooky init
```

When both exist, repo `.hooky.yml` overrides matching engine settings from `~/.hooky/config.yml`.

## Sample rejected command output

Example: blocked by a native rule (`--no-verify`).

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

## Golden Example (Codex Under `hooky run`)

This is the expected end-to-end behavior when Codex is launched through Hooky and asked to run a blocked command.

```bash
hooky run -- codex exec "please try to run commit no-verify. don't worry about staged files, I just want to see if our tooling rejects it" --yolo
```

Expected blocked command line (from the `exec` step):

```text
hooky Block: BLOCKED: Commands with --no-verify or --no-gpg-sign are not allowed.
Pre-commit hooks must always run. [rule: block-no-verify] [engine: claude_hooks]
```

Expected Codex summary (example):

```text
Tooling rejected it.

`git commit --no-verify -m "test no-verify behavior"` exited with code `1` and returned:

`hooky Block: BLOCKED: Commands with --no-verify or --no-gpg-sign are not allowed. Pre-commit hooks must always run. [rule: block-no-verify] [engine: claude_hooks]`
```

Example: rewrite rule rejected in deny-only mode (`--force`).

```json
{
  "data": {
    "command": "git push origin main --force",
    "decision": {
      "kind": "block",
      "reason": "rewrite decisions are disabled; deny-only mode",
      "rule_id": "force-to-lease",
      "engine": "combiner"
    }
  },
  "timestamp": "2026-02-12T19:40:02.333342Z"
}
```

## How interception works

1. `hooky run -- <program> [args...]` starts the target program with a guarded environment:
   - Prepends `.hooky/shims` to `PATH`
   - Sets `SHELL` to the generated `hooky-shell` shim
2. `hooky install-shims` creates wrapper scripts for `git`, `rm`, `mv`, `curl`, `bash`, and `sh` by default.
   - This mechanism is generic: you can add additional shim targets to cover other commands.
3. Each command shim runs `hooky check-argv ...` before executing the real binary.
   - If decision is `allow`, it `exec`s the real command
   - If decision is `block` (or `confirm`), execution stops with a non-zero exit
   - Shims use `--quiet`, but failed decisions still print concise stderr details (reason, rule, engine)
4. `hooky-shell` checks shell-string invocations (for example `bash -c "..."` and `bash -lc "..."`) via `hooky check-shell ...`.
5. Decisions are combined across engines (`claude_hooks`, `dcg`, `native`, `local_hooks`) with deny-first behavior:
   - Any `block` stops the command
   - `confirm` returns exit code `10`
   - `rewrite` is currently treated as `block` (deny-only mode)
6. Every command check is appended to `.hooky/.hooky-log.jsonl`.

`--quiet` behavior:
- `allow`: no decision output
- `block`/`confirm`/`rewrite`: emits concise failure details to stderr and returns a non-zero exit code

This is command-level interception via shell and PATH shims (not kernel/syscall sandboxing). In practice, commands are intercepted when they enter through shimmed command entrypoints. The current default set is `git`, `rm`, `mv`, `curl`, `bash`, and `sh`, but the approach can be extended to other commands.

## Configuration

Default config file: `.hooky.yml` (optional).

### Add your own tools and checks

Hooky is extensible in two layers:

1. Command coverage via shims (which binaries get intercepted)
2. Policy engines (what gets allowed/blocked)

Add more tool shims in `.hooky.yml`:

```yaml
shims:
  commands:
    - git
    - rm
    - docker
    - kubectl
    - terraform
```

After updating shim targets, regenerate shims:

```bash
hooky install-shims --force
```

Add custom native checks:

```yaml
engines:
  - type: native
    enabled: true
    merge_strategy: extend
    rules:
      - id: block-kubectl-delete-all
        action: block
        pattern: '\bkubectl\s+delete\b.*\s--all(\s|$)'
        rewrite: null

      - id: block-terraform-destroy-auto-approve
        action: block
        pattern: '\bterraform\s+destroy\b.*\s-auto-approve(\s|$)'
        rewrite: null
```

Use DCG packs for additional checks:

```bash
hooky setup dcg --with-pack core.filesystem --with-pack containers.docker
```

Or import an existing DCG config:

```bash
hooky import dcg --from .dcg.toml
```

Validate your custom checks:

```bash
hooky doctor
hooky check-shell --cmd "kubectl delete pods --all -n prod"
hooky check-shell --cmd "terraform destroy -auto-approve"
```

Then run your agent under Hooky so those checks apply during real execution:

```bash
hooky run -- codex
# or
hooky run -- claude
```

### DCG setup (easy path)

Enable DCG integration in one command:

```bash
hooky setup dcg
```

Bootstrap a complete Hooky config (including DCG + runtime directory):

```bash
# Project-local (.hooky.yml + ./.hooky/)
hooky init

# Global (~/.hooky/config.yml + ~/.hooky/)
hooky init --global
```

If you already have a config and only want to enable/update DCG settings in it:

```bash
hooky setup dcg
```

Import an existing DCG config file:

```bash
hooky import dcg --from .dcg.toml
```

Optional setup flags:

- `--dcg-config <path>`: set `dcg test --config <path>`
- `--with-pack <pack>`: add one or more `--with-packs` entries
- `--explain`: enable DCG explain mode

When enabled, hooky invokes DCG using `dcg test --format json --no-color ...` and parses the JSON decision.

See `plan.md` for implementation roadmap.
