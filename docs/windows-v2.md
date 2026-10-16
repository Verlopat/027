# Three compromise windows and measured X3 fixture

For an event delivered at `arrival_ms`, a checkpoint seals it at `seal_ms`;
independent witness receipt is `witness_ms` and ledger confirmation is `anchor_ms`.
At compromise `t*`, count **arrived events** under:

- **Modification window**: `seal_ms > t*`, assuming the last period's key has been
  erased at seal time. This is the opportunity to sign a rewritten event history.
- **Silent suppression window**: same condition under this controlled full-verifier
  experiment, with the caveat that freshness depends on a configured heartbeat.
- **Unprovable suppression window**: neither witness nor ledger has received
  a commitment at `t*`. This is not a statement about what the collector saw.

`pabla/v2/windows.py` predicts counts independently from signed verification.
`pabla/v2/attacks.py` reconstructs a competing signed checkpoint with the seed
actually available at each compromise time and invokes `verify_full` on the
modified archive. Its third-party-evidence test uses witness/anchor receipt
availability. The sample reports the result *only for this deliberately simple
single-period model*. The full heterogeneous X3 adversary campaign and
matching theoretical lower bounds are unproven.

`output/v2testN/x03_windows.csv` includes sampled times, measured attack
verdicts, and distinct analytic predictions; the report retains any violations.
The run deliberately does not calculate p-values over deterministic outcomes.
