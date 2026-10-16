#!/usr/bin/env bash
# Reproduction gate: run on each independently provisioned and audited machine.
set -euo pipefail
if [[ $# -lt 1 ]]; then echo 'Usage: scripts/replicate.sh <experiment-campaign-directory>' >&2; exit 2; fi
if ! command -v uv >/dev/null; then echo 'not_run: uv unavailable' >&2; exit 2; fi
if [[ ! -f uv.lock ]]; then echo 'not_run: uv.lock missing; regenerate and review under networked toolchain' >&2; exit 2; fi
uv sync --locked --extra test
uv run python -m pytest -q
if ! command -v forge >/dev/null; then echo 'not_run: Foundry is required for signed EVM evidence' >&2; exit 2; fi
(cd contracts && forge test -vv)
if [[ ! -d "$1" ]]; then echo 'not_run: campaign input not found' >&2; exit 2; fi
uv run python -m experiments.runners.campaign --plan experiments/plan_smoke.json --output "$1"
