<div align="center">
  <img src="assets/hooky.png" alt="hooky" width="400"/>

  # hooky

  **A standalone command safety wrapper and policy evaluator for Codex**

  [![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
</div>

---

## Current behavior

- Deny-first policy (`allow`, `block`, `confirm`)
- Rewrite actions are currently denied by combiner behavior (deny-only mode)
- Claude hook compatibility via `.claude/hooks/block-no-verify.sh`
- JSONL audit logging to `.hooky-log.jsonl` with best-effort secret redaction

## Quickstart

```bash
cargo install --path . --force

hooky doctor
hooky check-shell --cmd "git commit --no-verify -m test"
hooky install-shims
hooky run -- --help
```

## How interception works

1. `hooky run` starts Codex with a guarded environment:
   - Prepends `.hooky/shims` to `PATH`
   - Sets `SHELL` to the generated `hooky-shell` shim
2. `hooky install-shims` creates wrapper scripts for `git`, `rm`, `mv`, `curl`, `bash`, and `sh`.
3. Each command shim runs `hooky check-argv ...` before executing the real binary.
   - If decision is `allow`, it `exec`s the real command
   - If decision is `block` (or `confirm`), execution stops with a non-zero exit
4. `hooky-shell` checks shell-string invocations (for example `bash -c "..."` and `bash -lc "..."`) via `hooky check-shell ...`.
5. Decisions are combined across engines (`claude_hooks`, `dcg`, `native`, `local_hooks`) with deny-first behavior:
   - Any `block` stops the command
   - `confirm` returns exit code `10`
   - `rewrite` is currently treated as `block` (deny-only mode)
6. Every command check is appended to `.hooky-log.jsonl`.

This is command-level interception via shell and PATH shims (not kernel/syscall sandboxing). In practice, `git ...` and `rm -rf ...` are intercepted because `git` and `rm` are shimmed command entrypoints.

## Configuration

Default config file: `.hooky.yml` (optional).

See `plan.md` for implementation roadmap.
