# Crash safety of the reference collector

## Critical defect fixed in the completion copy

`PersistentLog` previously opened SQLite with `isolation_level=None` but used
`with connection:` as if it opened a multi-statement transaction. In SQLite
**autocommit** mode this did not group the `sealed` insert, state ratchet and
intent deletion. Fault injection produced a persisted seal alongside an old
intent; restart attempted a duplicate period insert. The fix introduces
`BEGIN IMMEDIATE`, `COMMIT` and `ROLLBACK` around each append, intent and seal
state transition.

`pabla/v2/faults.py` intercepts SQL execution and transaction boundaries. The
test enumerates each instrumented boundary and checks:

- Every acknowledged append remains in the recovered archive.
- The same period is never emitted with two different checkpoint digests.
- The recovered archive verifies under the real `verify_full` implementation.
- The recovered seal is accepted by a fresh independent witness.

## Assumptions and limits

SQLite synchronous=FULL and a filesystem respecting atomic SQLite commits are
assumed. Tests inject Python exceptions, not power-loss failures at arbitrary
filesystem block writes, forced process termination, corrupted disks, or
adversarial key-store rollbacks. In-process Python and SQLite cannot ensure
old-secret erasure from process memory, swapped pages, write-ahead remnants or
flash-storage wear leveling. These remain open security requirements.

Run: `python -m pytest -q tests/v2/crash/test_fault_injection.py`.


## Multi-period injection campaign (2026-10-16)

A second regression suite exercises append(5) → seal(100) → append(3) →
seal(200) → empty heartbeat seal(300) → append(2) → seal(400), with
fault injection at all **256** observed SQLite execution boundaries. For each
fault index, restart is checked against acknowledged events, the four
canonical period checkpoints, the real full verifier and witness consistency
proof checks. The 256 cases were executed in three shards (1–80, 81–160,
161–256), all passing in this environment. This remains deterministic
exception/fault injection, not SIGKILL, power-loss or key-erasure validation.
The `PABLA_CRASH_START` and `PABLA_CRASH_END` environment variables enable
CI to run disjoint shards without hiding faults.
