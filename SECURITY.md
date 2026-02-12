# Security Policy

## Supported Versions

This project is currently pre-1.0. Security fixes are applied on the latest `main` branch.

If you find a security issue, please report it even if you are on an older commit.

## Reporting a Vulnerability

Please do **not** open a public GitHub issue for undisclosed vulnerabilities.

Report privately by emailing: `security@hybrd.com`

Include:

- A clear description of the issue and impact
- Steps to reproduce (or proof-of-concept)
- Affected commit/version
- Any suggested remediation

## Disclosure Process

- We will acknowledge receipt as quickly as possible.
- We will validate and assess severity.
- We will prepare and ship a fix.
- We will coordinate disclosure timing with the reporter when practical.

## Security Model and Scope

`hooky` is command-entrypoint interception via generated shell/PATH shims.

In scope:

- Commands executed through shimmed binaries (`git`, `rm`, `mv`, `curl`, `bash`, `sh`)
- Shell command strings checked by `hooky-shell` for `bash -c`, `bash -lc`, and `bash -l -c`
- Policy engine decisions and deny-first behavior

Out of scope / known limits:

- Kernel/syscall sandboxing
- Full process containment
- Non-shimmed executables
- Direct absolute path execution that bypasses shimmed entrypoints

## Hardening Checklist Before Public Releases

- Run `cargo test`
- Run `cargo audit`
- Run `cargo deny check advisories`
- Run `pre-commit run --all-files`
- Review `.hooky-log.jsonl` handling and ensure sensitive data redaction remains enabled
