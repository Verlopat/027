# PABLA-FI: forward-integrity evidence and limits

## Trusted parties and compromise timeline

The registration owner controls collector registrations and schedule renewals. A ledger makes commitments append-only after finality. The collector holds a changing Ed25519 seed, its current event-chain head, and the signing schedule's **public** keys and Merkle proofs. The attacker may steal current collector memory, the current seed and archives, but does not take over the registry owner or rewrite finalized ledger history. Best-effort zeroing of Python `bytearray`s is not a formal erasure guarantee: the interpreter and cryptographic backend can retain copies. For real deployments a hardened keystore and externally corroborated event collection would be required.

The initial seed generates the ordered period public keys. Only public keys remain in the schedule. `s[i+1] = SHA256(Framed("PABLA-FI-RATCHET-v1",s[i]))`; Ed25519 signing keys derive from each period seed. A leaf commits `(period,pk)` and a Merkle root pins the entire schedule; the owner's registry transaction binds schedule root and period range. Each signed manifest includes its exact period and proof. After a signature, the mutable current seed buffer is overwritten and the derived next seed becomes current. A compromised current seed **can derive future seeds**, but cannot efficiently recover erased earlier seeds under the assumed one-way ratchet.

## Two different integrity properties

1. **Ledger-anchored history** is protected by immutability of the anchor, regardless of whether the collector used a static signing key. Do not claim FI improves that already-protected property.
2. **A previously signed but not anchored period** can be verified with an authenticated registered period key. If that key has been erased, theft of a *later* seed cannot re-sign that past period. A static-key collector or the FI-noerase ablation *can* re-sign it. However, if the only remaining copy of an unanchored archive is controlled by the adversary, the adversary can remove it. This does not establish event completeness or event truth.

`verify_pending_batch` returns `ACCEPT_WITH_WARNING` + `IN_WINDOW_UNVERIFIABLE`, never a `PROTECTED` verdict. It requires the trusted identity and policy, a fully verified signature, Merkle root, event chain, and placement immediately after the current ledger tip. It is a conditional cryptographic statement about an artifact, not evidence that every real-world event was captured.

## Formal game (conditional statement)

Let `Setup` register a Merkle commitment to a period-key schedule on an append-only trusted ledger. The honest collector emits signed period manifests and destroys period seeds when advancing. A polynomial-time adversary receives all archive bytes, the ledger view, and seed `s_t` for the current period `t`, then outputs a modified, purportedly valid **previously signed period** `i < t` and its verification evidence. A win requires (i) a verifier acceptance under a pinned FI policy, (ii) a record or manifest different from the archived signed artifact, and (iii) a period preceding the stolen seed.

Under collision resistance of the framed SHA-256 commitment and Merkle construction, Ed25519 EUF-CMA for erased period keys, trustworthy schedule registration, and genuinely irrecoverable erased seeds, a successful changed accepted period implies at least one of: (1) a digest/Merkle collision, (2) a valid signature under a past period public key that the attacker could not access, (3) substitution of the pinned public-key schedule, or (4) a verifier bug. A standard reduction can guess the attacked period and embed a signature challenge, with a loss depending on the number of candidate periods, plus collision probabilities. **This document is a proof outline, not a mechanically verified reduction or a novel theorem.**

The game explicitly does **not** promise prevention of complete archive suppression, never-emitted events, fabrication after theft under present/future keys, rollback of unanchored checkpoints, or secure erasure in Python. Any claimed *time* bound also requires an independent confirmation-time assumption and prompt revocation: key evolution alone does not bound attacks on future periods.

## Exposure-window reporting

For compromise timestamp `t` and last confirmed anchor `a(t)`, `W=t-a(t)` describes the **pre-compromise open window**. The count of exposed arrivals is computed from the trace's event-arrival timestamps and confirmed anchor times. It excludes the unbounded post-compromise interval until externally enforced revocation. E10 tests arithmetic of this model on seeded synthetic traces; E11 compares greedy deadline/size batching with fixed deadlines. The memory backend measures anchor **calls**, not Ethereum gas or finality latency.

FI-nochain intentionally removes the event hash chain but keeps Merkle leaves bound to the sequence and signed manifest. Current attacks need not distinguish FI and FI-nochain; absent a genuine differential, do **not** claim that the hash chain is independently novel or essential.
