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

## Quick start (local cryptographic smoke test + E1–E7 experiment suite)

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
- `pabla/experiments.py`: experimental profiles, paired trial framework, E1–E7 raw observation generation.
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

Security trial summaries distinguish adaptive attacks and do not attach pseudoreplicated significance tests to deterministic detection. Construction and anchor timings are separated. E7 uses isolated subprocesses for RSS/CPU measurements. GitHub Actions includes a pinned Foundry v1.5.0 job, Foundry contract tests and a minimal real-Anvil integration run. **Local development did not include a live Foundry/Anvil toolchain or an online dependency resolution**, so live-EVM results and a `uv.lock` file must be generated/validated in a networked environment.

The implementation remains research software, not a production deployment or proof of scientific novelty. Unresolved journal requirements include independently reset EVM runs for unbiased comparison, a truly external evaluated baseline, stronger formal provenance claims, a frozen full experiment matrix, and independent audit. Internal ablations that fail to demonstrate unique detection capability must be reported as negative findings, not discarded.

## PABLA-FI research extension (E9–E12)

The `FI` policy registers a period-public-key Merkle schedule, ratchets Ed25519
signing seeds per batch, enforces monotonic period anchoring and performs
period-to-root inclusion verification. `FI-noerase` and `FI-nochain` are explicit
ablations. `pabla/anchoring.py` implements deadline/size rules, while E9–E11
record key-compromise classifications, synthetic exposure counts and executed
anchor-call cost tradeoffs. E12 streams externally supplied LANL relative-time
records and stores the source SHA-256 digest.

```bash
uv sync --extra test --extra parquet
uv run pytest -q
uv run python Main.py --trials 2 --events 24 --batch-size 12
# With independently obtained LANL auth.txt.gz or proc.txt.gz:
uv run python Main.py --dataset-path /path/to/auth.txt.gz
# Live EVM run requires installed Anvil, compiled Foundry contract and PABLA_CONTRACT:
uv run python Main.py --backend anvil --require-chain --trials 1 --events 24
```

See `docs/forward-integrity.md` and `docs/experiment-interpretation.md` for
explicit compromise limitations, proof assumptions, measurement provenance,
models versus observations, the distinction between CT checkpoints and anchored
CT roots, and known incomplete validations. Neither journal novelty nor
production key erasure is established by a passing test suite.

## Anchor-race, relay and dual exposure evaluation

The `pabla/relay.py` witness retains signed batch copies only after a declared
transfer delay. E9 adds `ANCHOR_RACE_FORGED_PENDING` for P1/B4/FI/FI-noerase,
verifying both forged and honest-relay histories after the forged on-chain
commitment. An FI forged signature is rejected, but the contract can still
anchor invalid signed evidence from an authorized submitter, so the honest
copy can be denied anchoring. See `docs/forward-integrity.md`.

E10 now reports independently **modification** and **suppression** exposure,
with fields comparing executed attacks/verifier outcomes to a separate custody
model. E11 is a cost characterization, not an optimization claim. The hash
chain is not a distinguishing novelty claim. Experiment code lives under
`pabla/experiments/{common,e1_e8,e9_fi,e10_e12}.py`.

To acquire an *official* LANL trace and run E12 when Internet access is
available (small red-team file is for functional validation, not volume):

```bash
python scripts/download_lanl.py --subset redteam --output data/lanl-redteam.txt.gz
uv run python Main.py --dataset-path data/lanl-redteam.txt.gz
```

A full-scale Anvil evaluation must be conducted separately with ten or more
independently reset trials, its output directories and SHA-256 dataset manifest
archived. The full grid and before/after FI gas savings have **not** been
measured in the offline environment. Never infer gas savings from changed
Solidity storage layout alone.

## Witness-gated anchor race protection

A separate `FI+WITNESS` E9 model registers an independently controlled witness
address and a relay key. The compromised collector's normal EVM submitter
cannot anchor unverified FI evidence. The relay must receive and verify the
honest signed batch before its separately controlled witness account submits
`anchorFIWitness`. A delayed or noncooperating witness still delays anchoring;
this is *not* a trustless solution. The legacy FI path remains available for
explicit comparison and is susceptible to anchor-slot denial.

The relay is implemented in `pabla/relay.py`, and the protected E9 simulation
and tests use real verifier outcomes. Anvil test accounts are local and unlocked;
no production-grade key isolation or on-chain Ed25519 verification is implied.

The FI contract no longer allocates a per-batch `fiAnchors` schedule-root slot;
period equals batch number and the schedule root is reconstructed from the
registered schedule. EVM gas savings require independent before/after receipts
and are not claimed without execution.

## PABLA-v2 reference implementation (research branch)

The opt-in v2 code lives in `pabla/v2/`; the existing PABLA-FI entry point
is retained unchanged for backwards-compatible comparison.

```bash
python3 Main.py --v2 --events 32
python3 -m pytest -q tests/v2
```

Each execution creates `output/v2testN/` containing a report, environment
manifest, a persisted collector store, an independent witness store, and
`x03_windows.csv`. The X3 probes actually forge evidence, call the independent
full verifier, and compare outcomes with a separate analytic window model.
All v2 runs identify the **in-memory test double**; the example uses synthetic
data and does not report EVM gas, public-chain finality, published-baseline
performance, or verified novelty. The offline scheduler accepts an optional
`--gas-csv <path>` with a `price` column; external data receive a SHA-256 digest.

See `docs/protocol-v2.md`, `docs/windows-v2.md`, and `docs/v2-validation.md`.
`contracts/src/AnchorLogV2.sol` implements a distinct secp256k1-signed checkpoint
and equivocation-proof contract, rather than adding Ed25519 assertions to the
legacy contract. The existing v1 and FI baseline implementations remain.

**Security limitation:** SQLite and the CPython reference backend do not provide
forensic-grade key erasure. They must not be represented as satisfying A-ERASE
under an attacker who obtains disk images, page caches or process-memory copies.
The pure-Python secp256k1 implementation is neither constant-time nor side-channel
hardened. Do not deploy it for production key custody.


## Additional v2 research infrastructure (local completion copy)

The following modules extend the reference implementation and require
independent review before use in security-sensitive production deployments.

- `pabla/v2/envcapture.py`: provenance including source revision, dirty-tree
  status, lockfile digest, CPU details and installed tool versions.
- `pabla/v2/backends.py`: selectable reference/native signer API. The native
  libsecp256k1 path is optional and was **not** tested when its dependencies
  were unavailable. Python ECC is not constant time.
- `pabla/v2/keystore.py`: SQLite and atomic file seed-store interfaces. These
  do **not** guarantee secure erasure.
- `pabla/v2/faults.py`: deterministic SQL durability-boundary injection. A
  critical SQLite autocommit bug in `wal.py` was fixed by adding explicit
  `BEGIN IMMEDIATE` / `COMMIT` / rollback transactions.
- `pabla/v2/witness_set.py` and `reporting.py`: independent cosignature quorum,
  gossip-in-process and trusted time-policy reporting. Byzantine quorum
  intersection needs `2*quorum > witness_count + max_corrupt`.
- `pabla/v2/streaming.py`: single-pass event verification with logarithmic
  Merkle state, exercised with real timed synthetic million-event workloads.
- `pabla/v2/adversary.py`: bounded verifier-oracle search over archive and
  signed-pending attacks. It is **not** a general optimal-adversary proof.
- `experiments/runners/campaign.py`: isolated subprocess smoke campaign,
  complete logs and `not_run` statuses for unavailable experiments.

Quick validation from an installed project environment:

```sh
uv run --extra test pytest -q
uv run python Main.py --v2 --events 16
uv run python -m experiments.runners.campaign --plan experiments/plan_smoke.json
uv run python scripts/bench_stream.py --events 1000000
```

Full replication, Tamarin verification, external secure-logging baseline
comparisons, dataset permissions, native crypto/erasure validation, formal
proof checking, and a complete X1–X12 campaign remain external validation
obligations. See `docs/reproducing.md`, `docs/crash-safety.md` and
`docs/baselines.md` for precise assumptions and limitations.
