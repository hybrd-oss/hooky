# Hooky Specifications

## Project Overview

Hooky is a configurable command firewall for shells and AI agents. It provides a CLI (`hooky`) that intercepts commands at execution time (via PATH shims or shell wrappers) and evaluates them against multiple policy engines before allowing, blocking, rewriting, or confirming execution.

### Core Principles

- **Deny-first policy**: Any block decision wins
- **Universal enforcement**: Works with agents, shells, and automation scripts
- **Multi-engine evaluation**: Native rules, Claude hooks compatibility, DCG integration, local hooks
- **Auditability**: JSONL audit trail with rule provenance and secret redaction

## Spec Index

| Spec | Status | Description |
|------|--------|-------------|
| 01-command-interception | `complete` (spec file missing) | PATH shims and shell wrappers intercept commands at execution time |
| 02-policy-evaluation | `complete` (spec file missing) | Multi-engine evaluation pipeline with deny-first semantics |
| 03-decision-model | `complete` (spec file missing) | Decision types: allow, block, rewrite, confirm |
| 04-audit-logging | `complete` (spec file missing) | JSONL audit logging with redaction and provenance |
| 05-config-loading | `complete` (spec file missing) | Configuration loading, merging, and validation |
| 06-doctor-install | `complete` (spec file missing) | Installation validation and health checks |
| 07-claude-hooks-compat | `complete` (spec file missing) | Claude Code hook compatibility engine |

## Development Approach

### Tracer Bullet Methodology

Each spec is self-contained and describes working behavior in the current implementation.

## Spec Status Values

- `not_started` - Work has not begun
- `in_progress` - Currently being implemented
- `blocked` - Waiting on external dependency
- `complete` - All success criteria met

## Spec Maintenance

**Specs are living documents.** Update them as you implement.

### When Starting a Spec

1. Update the spec's `**Status**:` to `in_progress`
2. Update the status table in this file
3. Review the spec for any outdated assumptions

### During Implementation

1. Check off progress items as you complete them
2. Add discoveries/notes if implementation differs from plan
3. Update code examples if the actual implementation differs

### When Completing a Spec

1. Verify all success criteria are checked
2. Update the spec's `**Status**:` to `complete`
3. Update the status table in this file
4. Add follow-up work as notes or new specs

### Handling Scope Changes

If you discover work that doesn't fit the current spec:

- Small additions: Add to current spec's Progress section
- Large additions: Create a new spec file (e.g., `08-new-feature.md`)
- Blockers: Update status to `blocked` and note the dependency

## Architecture Summary

```
┌──────────────────────────────────────────────────────────┐
│                          Hooky                           │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  ┌────────────────────────────────────────────────────┐  │
│  │                COMMAND INTERCEPTION                │  │
│  │   shims / wrappers capture commands at execution   │  │
│  └────────────────────────────────────────────────────┘  │
│         │                                    │           │
│         │ build context                      │ audit     │
│         ▼                                    ▼           │
│  ┌────────────────────────────────────────────────────┐  │
│  │                 POLICY EVALUATION                  │  │
│  │  engines: native rules, Claude hooks, DCG, local    │  │
│  └────────────────────────────────────────────────────┘  │
│         │                                    │           │
│         │ decision                           │ log       │
│         ▼                                    ▼           │
│  ┌────────────────────────────────────────────────────┐  │
│  │               DECISION & ENFORCEMENT               │  │
│  │  allow / block / rewrite / confirm                 │  │
│  └────────────────────────────────────────────────────┘  │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

## Flow

1. Command is invoked through a shim or wrapper
2. Hooky builds a request context
3. Policy engines evaluate the command
4. A decision is computed and enforced
5. An audit event is written (with redaction)

## What We're NOT Building (v1)

- Remote policy servers
- Multi-user authentication
- UI or daemon mode
- Distributed enforcement

## References

- `README.md`
- `plan.md`
- `SECURITY.md`
- `design-global-config.md`
