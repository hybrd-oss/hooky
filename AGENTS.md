# Agent Instructions

## Project Overview

**hooky** is a configurable command firewall for shells and AI agents, written in Rust. It acts as a universal command safety layer that intercepts shell commands before execution and evaluates them against multiple policy engines.

**Key capabilities:**
- **Command interception**: PATH shims and shell wrappers catch commands at execution time
- **Multi-engine evaluation**: Native rules, Claude Code hooks compatibility, DCG integration, local hooks
- **Deny-first policy**: Any block decision wins; supports allow/block/rewrite/confirm actions
- **Audit logging**: JSONL audit trail with rule provenance and secret redaction
- **Agent safety**: Brings Claude Code safety mechanisms to Codex and other automation tools

**Primary use case**: Wrap AI agents (Codex, Claude Code) or automation scripts in `hooky run` to enforce safety policies without modifying the agent/tool itself.

## Repository Table of Contents

### Core Source Code
- `src/bin/hooky.rs` - Main CLI binary and command router
- `src/lib.rs` - Library entry point
- `src/hooky/` - Core hooky modules
  - `config.rs` - Configuration loading, merging, and validation (`.hooky.yml`)
  - `evaluator.rs` - Multi-engine policy evaluation pipeline
  - `decision.rs` - Decision model (allow/block/rewrite/confirm)
  - `audit.rs` - JSONL audit logging with secret redaction
  - `doctor.rs` - Health checks and installation validation
  - `mod.rs` - Module exports
- `src/types/` - Shared type definitions
  - `response.rs` - API response types
  - `mod.rs` - Type module exports

### Configuration & Policies
- `.hooky.yml` - Main configuration file (optional, with defaults)
- `.claude/hooks/` - Claude Code hook compatibility scripts
  - `block-no-verify.sh` - Example block hook for `--no-verify` flag
- `.hooky/shims/` - Generated command wrapper shims (created by `hooky install-shims`)

### Documentation
- `README.md` - User-facing documentation with quickstart and examples
- `AGENTS.md` - This file: agent instructions and workflow guidelines
- `plan.md` - Implementation roadmap and architecture design
- `SECURITY.md` - Security considerations and known limitations
- `design-global-config.md` - Global configuration design notes

### Build & Testing
- `Cargo.toml` - Rust package manifest
- `tests/hooky_cli.rs` - Integration tests
- `.pre-commit-config.yaml` - Pre-commit hook configuration

### Issue Tracking
- `.beads/` - Beads issue tracking system
  - `config.yaml` - Beads configuration
  - `interactions.jsonl` - Issue interaction log
  - `metadata.json` - Issue metadata
  - `README.md` - Beads documentation

### Assets
- `assets/hooky.png` - Project logo

---

This project uses **bd** (beads) for issue tracking. Run `bd onboard` to get started.

## Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --status in_progress  # Claim work
bd close <id>         # Complete work
bd sync               # Sync with git
```

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
