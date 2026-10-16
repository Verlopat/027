# PABLA: Provenance-Aware Batched Log Anchoring

**Research software** for independently verifiable provenance and continuity indicators in synthetic host/cloud security telemetry. The protocol binds an event's canonical bytes, collector ID, epoch, sequence and preceding digest into a signed Merkle-batched commitment, then optionally anchors that commitment on an Ethereum-compatible local chain.

Cryptographic provenance does **not** prove that an event really happened, that the collector observed everything, or that a collector with a stolen active key is honest.

## Requirements and version checks

```sh
python3 --version
uv --version
git --version
anvil --version
forge --version
```

Recommended: Python 3.12/3.13, `uv`, Foundry/Anvil for genuine blockchain experiments. Use a dedicated venv, never `sudo pip`. No real Ethereum private keys or public networks are required.

## Quick start (local cryptographic smoke test + E1–E8 experiment suite)

```sh
git clone https://github.com/Verlopat/027.git
cd 027
uv sync --extra test --extra parquet
uv run python Main.py
uv run pytest -q
```

If an Anvil deployment is not configured, `Main.py` uses a conspicuously labeled in-memory **test double**. It runs actual cryptography, attack mutations, verification, measurements and statistics. The in-memory backend is *not a blockchain*; its recorded calls cannot be used as gas, finality, public-network performance or Ethereum latency evidence.

Every `Main.py` invocation creates a fresh immutable `output/test1`, `output/test2`, … containing archived batch evidence, an SQLite index, Merkle inclusion proof, environment manifest, real raw CSV/JSONL (and Parquet if installed), derived deterministic detection summary, graphics and logs. A failed run creates `failure.json` without overwriting earlier runs.

## Genuine local Anvil execution

```sh
# In a separate terminal; development keys ONLY.
anvil --chain-id 31337
# In the project root:
cd contracts && forge build && cd ..
uv sync --extra chain --extra test --extra parquet
uv run python scripts/deploy_contract.py
# Read the address from contract-deployment.json, then:
PABLA_CONTRACT=<deployed-contract-address> uv run python Main.py --backend anvil --require-chain --trials 1 --events 20
```

`--require-chain` fails instead of falling back to the in-memory test double. RPC is restricted to loopback and chain ID 31337. Keep test-chain traffic isolated and reset the Anvil state between independent experimental campaigns. Export transaction receipts before reset. **Contract compilation and live EVM interaction must be validated on a machine where Foundry and Anvil are installed.**

## Select experimental workload

```sh
uv run python Main.py --backend memory --trials 10 --events 1000 --batch-size 100 --seed 739391
uv run python Main.py --profile full --trials 30 --events 10000 --batch-size 1000
```

Default is intentionally laptop-safe (pilot profile). The `full` profile increases repetitions and volume; it does not magically turn a pilot into the entire pre-registered study matrix. For journal analysis, freeze and disclose exact configuration ranges, collect multiple independent full runs, complete the hardware/chain setup and audit the comparison conditions. For B1, the framework caps expensive per-event anchoring at 10,000 events per trial, and reports that cap rather than presenting a million transactions as measured.

## Architecture

- `pabla/protocol.py`: canonical JSON, versioned length-framed hashes, hash-chain commitments, odd-leaf-duplication Merkle proofs, Ed25519 manifest signing, verifier and verdict codes.
- `pabla/ledger.py`: persistent-on-chain EVM registry adapter and independently labeled in-memory test ledger.
- `contracts/`: Solidity registry, epoch revocation, monotonic anchor sequencing and contract tests.
- `pabla/workloads.py`: deterministic synthetic telemetry and post-commitment attack injection.
- `pabla/experiments.py`: experimental profiles, paired trial framework, E1–E8 raw observation generation.
- `pabla/analysis.py`: exact binomial confidence intervals, paired McNemar and Holm-adjusted comparisons, bootstrap CIs, plots.
- `pabla/storage.py`: per-run directories, atomic artifact writes and SQLite indexing.
- `Main.py`: single-entrypoint workflow; no manuscript files are created.

## Methodology and output interpretation

- P1: signed sequence-aware hash chain + Merkle batching + anchor.
- B1: direct single-event anchoring; B2: signed off-chain batches; B3: hash chain only; B4: signed Merkle batch with anchoring but no event chain.
- A1–A5: disable respectively event chain, cross-manifest links, anchor, revocation check, or timestamp plausibility. Baselines make different trust assumptions and cannot be compared as security-equivalent protocols.
- AT1–AT10: alteration, deletion, reorder, replay, clock skew, unauthorized signature, post-revocation submission, root substitution, active-key fraud and missing archive.
- E1/E2 test integrity/continuity, E3 overhead, E4 physically paced batching/rate sensitivity, E5 revocation and rotation, E6 stolen-key residual risk, E7 measurement stability.

The reference verifier checks commitment integrity for archives already received and some observable sequence gaps. No system that relies only on a compromised collector can establish completeness of never-emitted events. Pre-revocation, already-anchored records remain valid following a later revocation; only later attempts are blocked. Missing archives receive `UNDETERMINED_ARCHIVE_MISSING`, not an invented proof of content modification. Time warnings are warnings, not cryptographic integrity failures.

See `docs/protocol.md`, `docs/threat-model.md`, `docs/evaluation.md`, `docs/limitations.md` for byte-level construction and experimental boundaries.

## Security and operational constraints

Never use default Anvil test accounts with live funds. Keep registry ownership separate from collector ingestion credentials in a deployed system. Ed25519 private keys are generated in process for synthetic evaluations and not persisted to Git. A real service needs an externally reviewed key-management solution, protected collector runtime, secure archival redundancy, recovery/idempotent outbox and independent time attestation. No claim of formally verified smart contracts or journal acceptance is made.

## Test suite

```sh
uv run pytest -q
cd contracts && forge test -vv
```

Results generated by experimental execution, not included as fabricated static figures.

## License

MIT (see `LICENSE`).

## Security review improvements and unresolved work

The verifier now requires an explicit, registry-bound trusted policy. Manifest-provided `method` is treated as untrusted input; warning classifications never bypass cryptographic or anchor checks. `verify_complete_history` compares the verified archive against the on-chain latest batch and sequence; simple `verify_history` validates the supplied prefix only. EVM transaction reverts are converted into traceable `ProtocolError` outcomes. Collector identities bind the policy digest on the contract, so the modified contract requires redeployment (its ABI is not compatible with the earlier contract).

Security trial summaries distinguish adaptive attacks and do not attach pseudoreplicated significance tests to deterministic detection. Construction and anchor timings are separated. E7 uses isolated subprocesses for RSS/CPU measurements. GitHub Actions includes a pinned Foundry v1.5.0 job, Foundry contract tests and a minimal real-Anvil integration run. **Local development did not include a live Foundry/Anvil toolchain or an online dependency resolution**. GitHub Actions validates the live-EVM integration and includes an online job to generate and commit a `uv.lock` dependency graph when needed.

The implementation remains research software, not a production deployment or proof of scientific novelty. Unresolved journal requirements include independently reset EVM runs for unbiased comparison, a truly external evaluated baseline, stronger formal provenance claims, a frozen full experiment matrix, and independent audit. Internal ablations that fail to demonstrate unique detection capability must be reported as negative findings, not discarded.

An E8 comparison evaluates signed Certificate Transparency-style binary history trees with independently verified inclusion and append-only consistency proofs. The code is a reference implementation for evidence semantics, not an optimized CT service; performance superiority over mature CT deployments is not claimed.
