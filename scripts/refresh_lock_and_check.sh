#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# Requires network / a populated uv cache. Never rewrites CI state itself.
uv lock
uv lock --check
uv sync --locked --extra test
uv run --no-sync pytest -q
printf '%s\n' 'Lockfile regenerated, checked and tested. Commit uv.lock before enforcing --locked in CI.'
