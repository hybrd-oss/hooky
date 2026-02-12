# safe-codex

`safe-codex` is a standalone command safety wrapper and policy evaluator for Codex.

## Current behavior

- Deny-first policy (`allow`, `block`, `confirm`)
- Rewrite actions are currently denied by combiner behavior (deny-only mode)
- Claude hook compatibility via `.claude/hooks/block-no-verify.sh`
- JSONL audit logging to `.safe-codex-log.jsonl`

## Quickstart

```bash
cargo install --path . --force

safe-codex doctor
safe-codex check-shell --cmd "git commit --no-verify -m test"
safe-codex install-shims
safe-codex run -- --help
```

## How interception works

1. `safe-codex run` starts Codex with a guarded environment:
   - Prepends `.safe-codex/shims` to `PATH`
   - Sets `SHELL` to the generated `safe-shell` shim
2. `safe-codex install-shims` creates wrapper scripts for `git`, `rm`, `mv`, `curl`, `bash`, and `sh`.
3. Each command shim runs `safe-codex check-argv ...` before executing the real binary.
   - If decision is `allow`, it `exec`s the real command
   - If decision is `block` (or `confirm`), execution stops with a non-zero exit
4. `safe-shell` checks shell-string invocations (for example `bash -lc "..."`) via `safe-codex check-shell ...`.
5. Decisions are combined across engines (`claude_hooks`, `dcg`, `native`, `local_hooks`) with deny-first behavior:
   - Any `block` stops the command
   - `confirm` returns exit code `10`
   - `rewrite` is currently treated as `block` (deny-only mode)
6. Every command check is appended to `.safe-codex-log.jsonl`.

This is command-level interception via shell and PATH shims (not kernel/syscall sandboxing). In practice, `git ...` and `rm -rf ...` are intercepted because `git` and `rm` are shimmed command entrypoints.

## Configuration

Default config file: `.safe-codex.yml` (optional).

See `plan.md` for implementation roadmap.
