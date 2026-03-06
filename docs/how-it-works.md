# How Hooky Works

This document describes the command interception pipeline and decision model in detail.

---

## Interception Architecture

Hooky uses **PATH shims** and a **shell wrapper** — not syscall sandboxing. Commands are intercepted when they pass through shimmed entrypoints.

```
hooky run -- <program>
      │
      ├── prepends the active shims dir to PATH
      └── sets SHELL to hooky-shell wrapper

When the program runs a shimmed command (e.g. git):

  git commit ...
      │
      ▼
  active-shims/git          ← shim script
      │
      ├── resolve config: ./.hooky.yml -> ~/.hooky/config.yml
      ├── hooky check-argv git commit ...
      │         │
      │         ▼
      │   Policy Pipeline
      │         │
      │    ┌────┴────┐
      │    │ allow?  │──── exec real git
      │    └────┬────┘
      │         │ block/confirm
      └── print reason to stderr, exit non-zero
```

For shell-string invocations (`bash -c "..."`, `bash -lc "..."`), the `hooky-shell` wrapper resolves config using the same local-then-global order before calling `hooky check-shell`.

---

## Policy Engines

Commands are evaluated across four engine types in parallel. Results are combined with **deny-first** semantics.

| Engine | Source |
|--------|--------|
| `native` | Regex rules in `.hooky.yml` |
| `claude_hooks` | Shell scripts in `.claude/hooks/` |
| `dcg` | [DCG](https://github.com/dicklesworthstone/destructive_command_guard) test packs |
| `local_hooks` | Project-local hook scripts |

**Combining rules:**
- Any `block` → command is blocked, regardless of other engine results
- All `allow` → command runs
- `confirm` → exits with code `10` (caller can prompt the user)
- `rewrite` → currently treated as `block` (deny-only mode)

---

## Decision Model

Each `hooky check-argv` or `hooky check-shell` call returns a decision:

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

**`--quiet` behavior (default for shims):**
- `allow` → no output
- `block` / `confirm` / `rewrite` → concise reason printed to stderr

---

## Audit Logging

Every decision is appended to `.hooky/.hooky-log.jsonl`. Entries include:

- Full command string
- Decision kind, reason, rule ID, and engine
- Timestamp (ISO 8601)
- Best-effort secret redaction (tokens, passwords, keys in env vars and command args)

Log location resolves upward from the current working directory to the nearest `.hooky/` directory, so nested repo work still lands in the right place.

Shim location follows the active config scope:
- global-only config uses `~/.hooky/shims`
- local config uses `./.hooky/shims`

---

## Shim Coverage

Default shimmed commands: `git`, `rm`, `mv`, `curl`, `bash`, `sh`.

This is extensible — any binary can be shimmed. See [configuration.md](configuration.md#shims) for details.

---

## What Hooky Does NOT Do

- Kernel or syscall sandboxing
- Network-level filtering
- Multi-user authentication or remote policy servers
- Daemon mode or persistent background process

Hooky is a lightweight, local enforcement layer — fast to set up, easy to extend, and composable with existing tooling.
