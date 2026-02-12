# Hooky Implementation Plan (Rust)

## Overview

Build a standalone `hooky` command that enforces command safety for Codex sessions via command interception, policy engines, and audit logging.

Primary goals:
1. Intercept commands before execution
2. Evaluate with one or more policy engines (`native`, `dcg`, `claude_hooks`, `local_hooks`)
3. Enforce deterministic decisions (`allow`, `block`, `rewrite`, `confirm`)
4. Remain fully independent from the `tv` CLI

## Current State Analysis

- The repo currently ships one Rust package and one binary (`tv`).
- No generalized command interception layer exists.
- `.claude/hooks/` exists and can be used as a compatibility target.
- There is no built-in support for DCG delegation today.

## Desired End State

A user can run:

```bash
hooky [codex args...]
```

And get:
- Guarded command execution via shell interception and `PATH` shims
- Multi-engine policy evaluation pipeline
- Optional DCG delegation
- Claude hooks compatibility mode
- JSONL audit trail with rule provenance

## Non-Goals (MVP)

- No sandbox/kernel-level hardening (container/seccomp/AppArmor)
- No UI/TUI for policy editing
- No `tv` subcommand integration
- No remote policy service

## High-Level Architecture

```text
hooky (launcher)
  -> hooky-shell (intercepts shell command strings)
  -> PATH shims (intercept direct binary calls)
  -> safe-policy daemon/cli (Rust)
       -> engine pipeline
          -> native rules engine
          -> dcg adapter
          -> claude hooks adapter
          -> local hooks adapter
       -> decision combiner
       -> audit logger (jsonl)
```

## Repository Layout Proposal

Use a workspace layout while keeping existing `tv` code intact:

```text
Cargo.toml (workspace root)
crates/
  tv/                  # existing code moved or referenced
  hooky/          # launcher + shim management
  safe-policy/         # policy models, parser, evaluator, combiner
  safe-engines/        # engine trait + dcg/claude/hooks/native impls
  safe-audit/          # structured logging and replay helpers
```

Alternative if deferring workspace migration:
- Keep current package layout and add additional `[[bin]]` entries + `src/safe_*` modules.
- Migrate to workspace in Phase 3.

## Decision Model

Normalized decision returned by each engine:

```rust
pub enum DecisionKind {
    Allow,
    Block,
    Rewrite,
    Confirm,
}

pub struct Decision {
    pub kind: DecisionKind,
    pub reason: String,
    pub rule_id: Option<String>,
    pub rewritten_command: Option<String>,
    pub engine: String,
}
```

Combiner policy defaults:
1. Any `Block` wins
2. Apply `Rewrite` using configured strategy (`first` or `chain`)
3. If no block and at least one `Confirm`, return `Confirm`
4. Otherwise `Allow`

## Config Schema (`.hooky.yml`)

```yaml
version: 1
mode: enforce # enforce|audit

engines:
  - type: dcg
    enabled: true
    cmd: dcg
    args: ["check"]
    timeout_ms: 1200

  - type: claude_hooks
    enabled: true
    hooks_dir: .claude/hooks
    compatibility_mode: strict
    timeout_ms: 1500

  - type: local_hooks
    enabled: true
    pre_command: .hooky/hooks/pre-command.sh
    post_command: .hooky/hooks/post-command.sh

  - type: native
    enabled: true
    rules:
      - id: block-no-verify
        match: "git commit --no-verify"
        action: block
      - id: force-to-lease
        match: "git push --force"
        action: rewrite
        rewrite: "git push --force-with-lease"

combine:
  on_conflict: deny_wins
  rewrite_mode: first

bypass:
  env_var: HOOKY_BYPASS
  allow: false
```

## Interception Design

### Layer 1: Shell command interception

`hooky-shell` intercepts `-lc "..."` commands before forwarding to the real shell.

Catches:
- shell builtins
- pipes and chained commands
- one-liners with `&&`/`;`

### Layer 2: Binary shim interception

Generated shims for selected commands (`git`, `rm`, `mv`, `curl`, `bash`, `sh`, etc.) call `safe-policy check-argv` before executing real binaries.

Catches:
- direct `execve` style invocations using `PATH`

### Known bypasses (documented)
- Absolute binary paths (`/usr/bin/git`) bypass `PATH` shims
- External processes outside wrapped environment bypass both layers

## Claude Hook Compatibility

Provide adapter behavior to run existing `.claude/hooks/*` scripts with compatible env/input shape.

Compatibility requirements:
- Hook phase mapping (`pre-command`, `post-command`)
- stdin JSON payload shape
- expected env vars
- exit code semantics (non-zero blocks by default in enforce mode)
- timeout and stderr capture

## DCG Integration

Support two modes:
1. `dcg_only`: decision delegated to DCG
2. `hybrid`: DCG runs in pipeline with other engines

Failure policy:
- `fail_closed` (default enforce): engine failure blocks
- `fail_open` (optional audit mode): engine failure logs warning and continues

## CLI Surface

Standalone commands:

```bash
hooky run [--] <codex args...>
hooky check-shell --cmd "git push --force"
hooky check-argv --bin git -- push --force
hooky install-shims
hooky doctor
hooky replay-log <file>
```

All machine-readable outputs should use the repo's JSON response conventions where practical.

## Phased Build Plan

## Phase 0: Scaffolding

- [ ] Add standalone `hooky` binary target
- [ ] Add config loader for `.hooky.yml`
- [ ] Add baseline decision enums + serde models
- [ ] Add JSONL audit writer

Success criteria:
- `hooky doctor` validates config and filesystem prerequisites

## Phase 1: Native engine + interception MVP

- [ ] Implement `native` rule matcher (block/rewrite/confirm/allow)
- [ ] Implement `check-shell` and `check-argv`
- [ ] Implement `hooky-shell` wrapper script template
- [ ] Implement shim generation/install (`install-shims`)

Success criteria:
- Local demo blocks `git commit --no-verify`
- Local demo rewrites `git push --force` to `--force-with-lease`
- Every decision appended to JSONL audit log

## Phase 2: Multi-engine pipeline

- [ ] Add engine trait and ordered pipeline executor
- [ ] Add combiner with deterministic precedence
- [ ] Add `local_hooks` engine
- [ ] Add failure policy controls (`fail_closed`, `fail_open`)

Success criteria:
- Mixed engine outcomes resolve predictably and are test-covered

## Phase 3: Claude hooks compatibility adapter

- [ ] Implement `.claude/hooks` discovery
- [ ] Implement compatible event payload + env vars
- [ ] Implement strict/lenient compatibility modes

Success criteria:
- Existing hook script like `block-no-verify.sh` works without modification

## Phase 4: DCG adapter

- [ ] Add external process adapter for DCG
- [ ] Map DCG output to normalized `Decision`
- [ ] Add `dcg_only` and `hybrid` execution modes
- [ ] Add `hooky doctor` checks for DCG availability

Success criteria:
- Same command decision path works with native-only, dcg-only, and hybrid modes

## Phase 5: Hardening and release

- [ ] Add integration tests with `assert_cmd` + temp dirs
- [ ] Add timeout/retry/cancellation handling
- [ ] Add replay tool for audit debugging
- [ ] Package install docs and migration guide (from Claude hooks)

Success criteria:
- `cargo test` passes
- `cargo clippy -- -D warnings` passes
- documented quickstart from zero to enforced policies

## Testing Strategy

Unit tests:
- rule matching and parse edge cases
- combiner precedence and rewrite strategy
- config compatibility checks

Integration tests:
- shim interception in temp `PATH`
- shell interception with chained commands
- hook timeout/failure semantics
- DCG adapter behavior (mocked binary)

Compatibility tests:
- fixture `.claude/hooks/block-no-verify.sh` expected to block

## Risks and Mitigations

1. Bypass via absolute binary paths
- Mitigation: document limits, optionally add stricter shell parsing and path policies

2. Hook script nondeterminism
- Mitigation: strict timeout + normalized output + deterministic ordering

3. Engine latency stacking
- Mitigation: per-engine timeouts and optional short-circuit on hard block

4. Config complexity
- Mitigation: ship opinionated defaults and `hooky init`

## Rollout Plan

1. Dogfood in this repo with `mode: audit`
2. Enable `enforce` for critical rules after one week of clean logs
3. Add DCG hybrid mode in second rollout window
4. Publish standalone binary and migration docs

## Deliverables

- `hooky` standalone binary
- `.hooky.yml` schema + example config
- shim installer and shell wrapper
- claude hook compatibility adapter
- optional DCG adapter
- test suite + docs + audit replay tool
