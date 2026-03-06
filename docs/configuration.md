# Configuration Reference

Hooky's configuration lives in:

- **Project-local**: `.hooky.yml` (in your repo root)
- **Global**: `~/.hooky/config.yml`

When both exist, project settings override matching engine settings from global. The local `shims.commands` list replaces the global shim list.

Bootstrap either with:

```bash
hooky init              # project-local
hooky init --global     # global
```

---

## Shims

Shims determine which commands get intercepted. Hooky replaces each listed binary with a wrapper script in the active runtime directory:

- `~/.hooky/shims/` when only global config is active
- `./.hooky/shims/` when a local `.hooky.yml` is active
- `--dir <path>` overrides both for `hooky install-shims`

Each wrapper discovers config at execution time in this order:

1. `./.hooky.yml`
2. `~/.hooky/config.yml`
3. No explicit config flag, which falls back to Hooky's defaults

**Default shims:** `git`, `rm`, `mv`, `curl`, `bash`, `sh`

To add more:

```yaml
shims:
  commands:
    - git
    - rm
    - mv
    - curl
    - bash
    - sh
    - docker
    - kubectl
    - terraform
    - npm
    - pip
```

After changing shim targets, regenerate:

```bash
hooky install-shims --force
```

`hooky run` uses the same scope-aware default when it auto-installs shims.

---

## Policy Engines

Engines are listed under the `engines` key. Multiple engines can be active simultaneously — all are evaluated and results are combined deny-first.

### Native Rules

Regex-based rules evaluated entirely within Hooky, no external dependency.

```yaml
engines:
  - type: native
    enabled: true
    merge_strategy: extend   # "extend" adds to built-ins; "replace" overrides them
    rules:
      - id: block-kubectl-delete-all
        action: block
        pattern: '\bkubectl\s+delete\b.*\s--all(\s|$)'
        rewrite: null

      - id: block-terraform-destroy-auto-approve
        action: block
        pattern: '\bterraform\s+destroy\b.*\s-auto-approve(\s|$)'
        rewrite: null

      - id: block-docker-run-privileged
        action: block
        pattern: '\bdocker\s+run\b.*\s--privileged(\s|$)'
        rewrite: null
```

**`merge_strategy` values:**
- `extend` — rules are added on top of the built-in native rules
- `replace` — only the rules you define are active (built-ins disabled)

Test a rule before relying on it:

```bash
hooky check-shell --cmd "kubectl delete pods --all -n prod"
hooky check-shell --cmd "terraform destroy -auto-approve"
```

### DCG (Destructive Command Guard)

[DCG](https://github.com/dicklesworthstone/destructive_command_guard) provides curated rule packs for common dangerous patterns.

**Enable with default settings:**

```bash
hooky setup dcg
```

**Enable with specific packs:**

```bash
hooky setup dcg --with-pack core.filesystem --with-pack containers.docker
```

**Import an existing DCG config file:**

```bash
hooky import dcg --from .dcg.toml
```

**Manual config:**

```yaml
engines:
  - type: dcg
    enabled: true
    config_path: .dcg.toml
    explain: false
    packs:
      - core.filesystem
      - containers.docker
```

**`hooky setup dcg` flags:**
- `--dcg-config <path>` — path to DCG config file
- `--with-pack <pack>` — add a pack (repeatable)
- `--explain` — enable DCG explain mode in output

When enabled, Hooky invokes `dcg test --format json --no-color` and merges its decision with other engines.

### Claude Code Hook Compatibility

Hooky automatically picks up shell scripts in `.claude/hooks/`. No config required — if the directory exists, the engine is active.

Scripts follow the same interface as Claude Code hooks: they receive the command via stdin or arguments and exit non-zero to block.

```yaml
engines:
  - type: claude_hooks
    enabled: true
    hooks_dir: .claude/hooks   # default; can be overridden
```

### Local Hooks

Project-specific hook scripts outside the `.claude/` convention:

```yaml
engines:
  - type: local_hooks
    enabled: true
    hooks_dir: .hooky/hooks
```

---

## Audit Logging

Logs are written to `.hooky/.hooky-log.jsonl`, resolved upward from the current working directory.

```yaml
audit:
  enabled: true
  redact_secrets: true   # strip tokens, passwords, keys from log entries
```

Secret redaction is best-effort: it targets common patterns in environment variables and command arguments (API keys, tokens, passwords, private key material).

---

## Full Example Config

```yaml
shims:
  commands:
    - git
    - rm
    - mv
    - curl
    - bash
    - sh
    - docker
    - kubectl

engines:
  - type: native
    enabled: true
    merge_strategy: extend
    rules:
      - id: block-kubectl-delete-all
        action: block
        pattern: '\bkubectl\s+delete\b.*\s--all(\s|$)'
      - id: block-docker-privileged
        action: block
        pattern: '\bdocker\s+run\b.*\s--privileged(\s|$)'

  - type: dcg
    enabled: true
    packs:
      - core.filesystem
      - containers.docker

  - type: claude_hooks
    enabled: true

audit:
  enabled: true
  redact_secrets: true
```

---

## Validating Your Config

```bash
hooky doctor
```

Checks for:
- Valid config syntax
- Shims installed and on PATH
- DCG binary available (if DCG engine enabled)
- `.hooky/` in `.gitignore`
