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
