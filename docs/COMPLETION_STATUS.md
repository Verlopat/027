# Completion state of the 14-item v2 research prompt pack

**This is an implementation/validation record, not a research manuscript or a Q1 acceptance claim.**

Source used: PABLA main commit `215660b13598ee8045781a2d777c240c0aa2082f`
(as previously verified via GitHub). The source package was pushed to GitHub as commit `1f040c6952efd1644b72534a25ae6667d304caf6` on `main`.
This newer working copy includes additional unpushed changes; refer to the checked Git commit when attributing evidence.

| Item | State | Evidence | Unfinished requirement |
|---|---|---|---|
| 1 Testing foundation | Partial | `tests/v2/property`, `test_foundations`, coverage config, nightly workflow, envcapture, mutation command | Hypothesis/mutmut unavailable locally; 90% branch coverage not achieved; updated `uv.lock` unavailable offline |
| 2 Native crypto/key custody | Partial | `backends.py`, `keystore.py`, crypto timing script | Optional native packages unavailable; no side-channel evaluation or TPM/HSM custody; full differential test outstanding |
| 3 Crash safety | Partly validated | SQLite autocommit defect fixed; boundary injection test passes | SIGKILL/power-loss matrix not run, disk-level erasure not established |
| 4 Witness set | Partial | Quorum certificates, sound quorum-intersection guard, in-process evidence gossip | No authenticated network transport, crash-safe cosignature re-issuance or Byzantine deployment |
| 5 Verifier properties/fuzz | Partial | Trusted time `PropertyReport`; full/streaming verifiers; tamper regressions | Full property taxonomy, Hypothesis mutation grammar, 15 golden cases outstanding |
| 6 Optimal adversary | Partial | `adversary.py` verifier-based bounded attack catalogue | No proof of optimality, 10k-time multi-scheme X3 campaign, or full ablation grid |
| 7 Contract checks | Not extended | Existing Solidity/CI code retained | Foundry/Anvil/Slither unavailable; new invariants and differential vectors not executed |
| 8a Journald FSS | Not run | Honest capability gate | Isolated production-equivalent systemd journal driver not deployed |
| 8b Tessera | Not run | Honest integration gate | Pinned Tessera and external witness not deployed |
| 8c Literature baselines | Not done | Legacy v1 and internal CT preserved | Peer-reviewed algorithms not reimplemented or independently reviewed |
| 9 Real workloads | Partial | Streaming checksum-enforced source loader; fixture test | Official Loghub/LANL data not downloaded; no real benchmark rows |
| 10 Real gas scheduling | Partial | BigQuery export code and offline comparator | No authenticated query or measured gas receipt input; X7 campaign not run |
| 11 Campaign/release | Partial | Subprocess smoke, statuses, manifests, checksum tarball | Full X1–X12 matrix, preregistered analysis and published figures not executed |
| 12 Tamarin | Not done | — | Tool unavailable and checked model absent |
| 13 Proofs | Not done | — | T1–T8 need complete reductions and independent cryptographic reviewer |
| 14 Replication | Partial | Reproduction gate script and archive comparator | No second machine or human replicator evidence |

Local verification records must not be treated as claims about production
security, correctness of proposed mathematical theorems, real Ethereum gas,
realistic datasets, or journal publication readiness.

## Important fault-injection finding

The SQLite-backed collector used `isolation_level=None` with `with self.db:`
which does not start a multi-statement transaction in autocommit mode.
Boundary injection found a partial seal update and duplicate period insert at
restart. Replaced this with explicit `BEGIN IMMEDIATE` and `COMMIT`, with
`ROLLBACK` on failure. The enumerated test now passes for every instrumented
SQLite execution/transaction boundary. This does **not** establish physical
power-loss resistance or secure deletion of old cryptographic secrets.

## Follow-up after independent audit of commit `1f040c6`

- **Fixed locally:** the bounded adversary now requires a trusted freshness
  policy by default and offers an explicit no-freshness ablation. Dropping
  a final sealed period and its events can succeed without freshness;
  `tests/v2/test_adversary.py` proves both outcomes with the real verifier.
- **Multi-seal crash validation:** all 256 instrumented boundaries passed in
  three shards; this is not physical power-loss or SIGKILL validation.
- **Added:** 300-vector native differential test (runs only with optional
  `coincurve` and `pycryptodome`), Foundry negative fuzz tests (not executed),
  real-environment gated journald/Tessera adapters (not run), two baseline
  *adaptations* (tests passed), and unreviewed proof/Tamarin draft files.
- **Still blocked:** `uv lock` cannot access the package registry in this
  environment. `scripts/refresh_lock_and_check.sh` contains the exact next
  steps; **CI has intentionally not been switched to `--locked` without a
  valid updated lockfile**. The Tamarin parser/solvers and Foundry toolchain
  were also unavailable locally. T1–T8 are not proved.
- **Not yet demonstrated:** complete X1–X12 campaign, external baseline
  equivalence, live certified journald/Tessera runs, multi-machine replication,
  reviewer sign-off, real dataset experiments, and a Q1 novel contribution.


## Locked dependency update on fix branch

A GitHub Actions job with package-registry access ran `uv lock` and
`uv lock --check` successfully, producing the lockfile candidate for
`fix/v2-adversary-freshness`. The downloaded `uv.lock` passed
`uv lock --check --offline` and includes the optional Hypothesis/native
packages. CI test and nightly workflows now use `uv sync --locked` and
`uv run --no-sync`. This removes the earlier dependency-resolution blocker;
other experimental and formal verification blockers remain.
