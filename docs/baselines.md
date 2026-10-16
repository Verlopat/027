# Baseline trust models and validation status

Research results must compare authenticated parties, corruption capabilities,
independent commitments, audit semantics, and event bytes on matched terms.

| System | Trust root | Present implementation | Can be cited as measured? |
|---|---|---|---|
| PABLA-v1 / FI | registered keys, ledger | Existing legacy pipeline | Only from actual corresponding runs |
| PABLA-v2 | public schedule, independent witness/ledger | Python reference + Solidity integration source | Reference smoke, not production performance |
| CT-style tree | signed checkpoint | `pabla/ct_baseline.py` | Only as a labelled reference reimplementation |
| systemd-journald FSS | evolving symmetric key, trusted verification secret | Capability gate (`baselines/journald_fss`) | **No**: full isolated driver and tests outstanding |
| Tessera with witness | log operator + external witness | Capability gate (`baselines/transparency_log`) | **No**: independent software integration outstanding |
| Schneier–Kelsey, Logcrypt, BAF, SLiC | varies by paper | Not integrated | **No**: requires original full-text analysis and faithful adapter |

Do not substitute the internal CT tree for deployed Tessera, or describe
unavailable baselines as having passed tests. For journald, use a separate VM
or container with isolated journals and verification keys, never production host
journals. All measurements require raw verification stdout/stderr, versions,
exact event bytes and documented differences in assumptions.

## Opt-in external integrations (added 2026-10-16)

`baselines/journald_fss/driver.py` now calls real `systemd-cat` for input and
`journalctl --verify --verify-key` for verification **only** if the operator
provides a separate systemd VM/container, an externally saved FSS verification
key, a dedicated journal directory, and both `PABLA_ISOLATED_SYSTEMD=1` and
`PABLA_ALLOW_SYSTEMD_FSS=1`. It does not create FSS keys or modify the host's
journal by default. Arbitrary event bytes are transported as base64 messages
so newlines cannot split one event into multiple entries. Actual integrity
outcomes depend on the configured journald sealing intervals and hardware.
No external execution has been performed here.

`baselines/transparency_log/driver.py` now exposes an opt-in adapter for a
running Tessera POSIX personality with `PABLA_TESSERA_ADD_URL`,
`PABLA_TESSERA_CHECKPOINT_URL`, and an explicitly audited
`PABLA_TESSERA_VERIFY_CMD` (containing `{checkpoint}`). It appends actual leaf
bytes and delegates checkpoint/witness-signature validation to the supplied
verifier. **No meaningful Tessera security verdict is emitted unless the
verifier executes.** This is not a substitute for the protocol's required
inclusion/consistency tests and independent witness-policy assessment. Version
pinning, external witness setup and live experiments are still pending.

The SK99-inspired HMAC chain (`baselines/schneier_kelsey/sk99.py`) and the
static-key anchored Merkle adapter (`baselines/anchored_static/anchored.py`)
are **research adaptations, not exact reproductions of published systems**.
They have unit tests for tampering and truncation, but historical/comparative
claims still need independent paper-fidelity review. Logcrypt and SLiC have
not been integrated; no rows are fabricated for them.

Relevant upstream instructions: systemd `journalctl` FSS manual; the Tessera
Go library's documented POSIX personality and checkpoint/witness policy.
