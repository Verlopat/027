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

## Freshness is a necessary trust assumption for silent-suppression bounds

A verifier with only a historical archive cannot distinguish the legitimately
terminated log from a suffix whose final sealed periods and associated events
were deleted. In particular, removing the last sealed checkpoint **together
with all events unique to it** may leave a gap-free, signature-valid prefix.
Thus W_silent bounds are conditional on a trusted current clock, seal interval,
clock tolerance, and a heartbeat/freshness check. Without this policy the
`DROP_LAST_SEALED_PERIOD` attack can be accepted even when all removed events
were sealed with erased keys. It is not evidence of a broken signature or ratchet.

`adversary.maximize()` requires trusted `now_ms`/`seal_interval_ms` in the
normal mode. `allow_no_freshness=True` is an explicitly named *insecure
ablation* used to demonstrate the necessity of freshness, never a default
experiment configuration. Both scenarios run through the actual verifier.
