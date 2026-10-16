# Security scope and assumptions

## Trusted

- Collision-resistant SHA-256 and Ed25519 unforgeability while the active collector key is secret.
- Authenticated collector-to-key enrollment, uncompromised registry owner, accepted local Ethereum ledger history for live-Anvil trials.
- Complete archived evidence for the events being verified, unless declaring archive availability failure.
- Explicit uniqueness and sequence enforcement by the contract for authorized anchor submitters.

## In-scope adversary

- Modifies, removes, reorders or replays **archived** logs or batches, submits mismatched roots, impersonates unregistered sources, and attempts to anchor with a revoked epoch.
- Can steal the active collector private key during an AT9 evaluation, showing what cryptography cannot detect in the absence of independent witnesses.
- Can alter local collector wall time, producing warnings when compared to batch receipt time.

## Not established

- Truth or completeness of underlying real-world telemetry, unobserved omissions, forward security once a key is stolen, off-chain availability, irrevocable public-chain finality, exact timing, or privacy of on-chain metadata.
- Retrospective invalidation of an anchor posted before a revocation; historical signed material is preserved as forensic evidence, not deleted.
- Compromise-resistant key storage. Benchmarks create test-only Ed25519 keys in memory.

## Recovery

The registry owner revokes epoch `e`, records revocation block, registers epoch `e+1` only after revocation and binds it to the previous last manifest via a recovery commitment. Any anchor from old epoch submitted after revocation is rejected by the contract. Higher-level incident response must independently choose the last known-good record and review the compromised interval; PABLA itself cannot reconstruct lost truth.
