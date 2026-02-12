#!/bin/bash
# Block git commands with --no-verify flag or SKIP= environment variable
# Used as a Claude Code PreToolUse hook

input=$(cat)
command=$(echo "$input" | jq -r '.tool_input.command // empty')

# Check for --no-verify, --no-gpg-sign, or -n flags
if echo "$command" | grep -qE '(--no-verify|--no-gpg-sign|-n\b.*commit)'; then
  echo "BLOCKED: Commands with --no-verify or --no-gpg-sign are not allowed."
  echo "Pre-commit hooks must always run."
  exit 1
fi

# Check for SKIP= environment variable at the start of commands
# This matches patterns like: SKIP=hook, SKIP=hook1,hook2, SKIP=
if echo "$command" | grep -qE '^\s*SKIP='; then
  echo "BLOCKED: Commands with SKIP= environment variable are not allowed."
  echo "Pre-commit hooks must always run."
  exit 1
fi

exit 0
