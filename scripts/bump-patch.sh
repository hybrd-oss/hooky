#!/usr/bin/env bash
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is required" >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo is required" >&2
  exit 1
fi

echo "Running pre-bump quality gates..."
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features

current_version="$(sed -nE 's/^version = "([0-9]+)\.([0-9]+)\.([0-9]+)"/\1.\2.\3/p' Cargo.toml | head -n1)"
if [[ -z "${current_version}" ]]; then
  echo "error: could not parse package version from Cargo.toml" >&2
  exit 1
fi

IFS='.' read -r major minor patch <<< "${current_version}"
next_version="${major}.${minor}.$((patch + 1))"

sed -i.bak -E '0,/^version = "[0-9]+\.[0-9]+\.[0-9]+"/s//version = "'"${next_version}"'"/' Cargo.toml
rm -f Cargo.toml.bak

# Refresh lockfile entry for the root package version.
cargo check -q

git add Cargo.toml Cargo.lock
git commit -m "chore: bump version to v${next_version}" -- Cargo.toml Cargo.lock

echo "Bumped version: ${current_version} -> ${next_version}"
