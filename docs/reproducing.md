# Local reproducibility for the v2 reference

This repository distinguishes actual local execution from the proposed
full-fledged X1–X12 multi-machine research campaign.

Run from repository root in an isolated Python 3.12+ environment:

```sh
uv sync --extra test
uv run pytest -q
uv run python Main.py --v2 --events 16
uv run python -m experiments.runners.campaign --plan experiments/plan_smoke.json --allow-dirty
```

`--allow-dirty` is intended **only** for a working copy; full evidence must be
produced from a clean Git tree. The runner records this choice in `env.json`.
Cells write `config.json`, `status.json`, `env.json`, stdout and stderr.
External-dependent experiments remain explicitly `not_run` unless real tools
and input artifacts are available. The memory ledger is **not** a gas/finality
model. Reference microbenchmarks are not EVM measurements.

Property tests (requires Hypothesis, not available in every environment):

```sh
HYPOTHESIS_PROFILE=ci uv run --extra test pytest tests/v2/property
HYPOTHESIS_PROFILE=nightly uv run --extra test pytest tests/v2/property
```

Crypto backend requirements:

```sh
PABLA_CRYPTO_BACKEND=reference uv run pytest -q tests/v2
PABLA_CRYPTO_BACKEND=native uv run --extra native pytest -q tests/v2
```

The native backend requires runtime differential testing. Using the reference
backend does not establish constant-time behavior or secure erasure.

For real workload replay, acquire data lawfully from its owner, record the
original URL and license, generate a SHA-256 manifest, then load via
`experiments.workloads.loghub.verified_trace`. No synthetic file is silently
converted into a 'real trace'. See [Loghub](https://github.com/logpai/loghub).
For LANL data, obtain the authorized dataset separately; it is not bundled.

The complete campaign and two-machine reproduction are not yet available.
Formal claims T1–T8 require independently reviewed proofs; current unit and
property tests cannot substitute for that review.
