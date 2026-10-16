# v2 validation ledger — execution evidence and remaining gates

**Executed here:** local Python tests (ECDSA and Keccak vectors; compact-tree
comparison; schedule membership; crash-intent faults; witness equivocation;
trusted-policy verification; scheduling DP compared against a brute-force
oracle), v2 smoke execution on a labeled in-memory ledger, and X3 constrained
adaptive attack probes. The runner stores elapsed nanoseconds from actual code.

**Not executed here:** Solidity compilation/Foundry fuzz/invariants, signed EVM
checkpoint deployment, EVM gas comparison, LANL/Loghub ingestion, 30-run
full-profile campaign, two-machine replication, Rust key custody, native
journald FSS and Tessera baselines, independent computational or Tamarin
proof checks, and a second-reader full-text novelty review. Their absence is
not a positive result; do not infer Q1-readiness or formal forward secrecy.

The v2 Solidity regression includes two valid signing examples generated from
the Python reference codec, a conflict, and a signature/replay rejection case.
Run the tests in a Foundry environment before citing any on-chain results.

No manuscript, paper, fabricated experimental result, or unverified journal
acceptance claim is part of the repository. The older v1/FI code stays present
and continues to run as a comparison baseline.
