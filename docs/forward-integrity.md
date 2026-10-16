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

## Anchor-race adversary and independent witness custody (E9)

`ANCHOR_RACE_FORGED_PENDING` instantiates an attacker that obtains the collector's
signing state after batch *k* is signed, and also controls the collector's
authorized **ledger submission credential**. The attacker submits a modified
batch *k* before the genuine relay copy is anchored. A witness receives and
retains a deep copy of the honest signed batch after a configurable transfer
delay. E9 verifies **both** artifacts against the same committed root and
records `relay_delivered_before_theft`, `witness_pending_preflight` and
`availability_failure` for the honest copy.

Static P1, B4, and FI-noerase can issue a valid replacement signature for the
old period; FI and FI-nochain cannot, *subject to past-seed erasure*. **Critical
limitation:** the current contract checks submitter identity and period/order,
not Ed25519. An attacker authorized to submit can anchor an FI commitment with
an **invalid** off-chain signature: its forged history is rejected by the
verifier, but the displaced honest relay history also fails the immutable
anchor check. This is a denial-of-service/availability failure, not an
integrity break and not solved by the FI signature scheme. The new protected registration mitigates this with an independently controlled
witness-only submission address, while the original legacy FI path remains as an
explicit attack/control condition. This changes the trust model: witness compromise
or refusal to serve is not solved by the cryptographic protocol.

Witness custody does not imply the collector captured every event, and no
protection exists for never-emitted events. The simulation uses discrete,
controlled delivery times, not a validated network-delay distribution.

## Independent witness-gated FI anchoring (protected variant)

The optional protected FI registration (`registerFIWitness`) commits an independent
EVM witness address *distinct from the compromised collector submitter*. Once
registered, `anchorFI` is disabled for that epoch; only `anchorFIWitness` sent
by the designated witness may claim the next slot. A Python relay verifies the
registered period proof, Ed25519 manifest signature, Merkle and chain evidence,
sequence continuity and byte-for-byte custody **before** submitting the original
copy. This is not Ed25519 verification by the EVM. Both the authorization gate
and the independent relay's key custody are necessary; compromise of the witness
remains a residual trust failure. A missing/delayed relay causes anchoring delay
rather than an irrevocable collector-forged anchor slot.

E9 compares `FI+WITNESS` with FI-legacy (the latter deliberately vulnerable to
anchor-slot denial). In the protected case the collector's forged submission
reverts; once the relay copy arrives it can anchor and pass verification.
The contract cannot prove the relay operator *actually* checked the batch; its
security is conditional on the honest witness and independent EVM key management.
A test deployment's unlocked Anvil accounts are NOT suitable operational custody.

The FI anchor period equals the batch number by the contract's invariant.
`getFIAnchor` now derives the schedule root from the retained registration
schedule and the immutable batch existence record; **no FI-specific per-batch
storage mapping** remains. This removes one potential 32-byte `SSTORE` per
anchor but gas savings are unmeasured until matched before/after EVM trials.

## Two operational exposure surfaces (E10)

E10 now runs collector sign operations, actual in-memory or EVM anchor calls,
witness delivery, an adaptive stolen-key mutation and the real verifier at
sampled compromise timestamps. **Modification exposure** counts unsigned
arrivals and un-witnessed signed pending records for which a real forged
manifest passes signature verification. **Suppression exposure** counts
unanchored and un-witnessed records for which the honest evidence can vanish
from the observer's accessible archive. A signed pending batch retained by an
independent witness need not be anchored to withstand complete local archive
deletion; it still lacks finality. The two windows differ from one another and
from the time between ledger confirmations.

The independent predictor uses ledger/relay receipt times and the expected
availability of the stolen period key, and is compared to the actual verifier
outcomes. This is a controlled simulation with synthetic operation clocks, **not**
empirically observed wall-clock compromise timing or network-delay variance.
The anchor-confirmation delay is a declared synthetic parameter even in an
Anvil run; measured transaction gas and timing remain separate.

## E11 interpretation and gas validation

E11 is a **cost/exposure characterization**, *not* a claim that the greedy
adaptive anchor policy minimizes gas. `anchor_calls_per_event` is observable
on the in-memory backend; `gas_per_event` is reported only if genuine Anvil
receipts exist. The redundant FI-anchor period storage word has been removed:
`period` is derived from `batchNumber` for the existing anchor, and the FI schedule root is now derived directly from the registered schedule
without any dedicated FI per-anchor mapping. This may lower gas,
but the improvement and its percentage are **unknown until both contract
revisions are measured with the same Foundry/Anvil configuration**. Never
present a source-code storage saving as a measured gas result.

## E12 and scale limitations

A small official LANL `redteam.txt.gz` (~4.8 KB) is suitable for functional
trace-loader validation only; it is not a representative high-volume enterprise
traffic benchmark. `dns.txt.gz` (~177 MB) is closer to a sizeable trace. Use
`scripts/download_lanl.py` to retrieve either directly from the official LANL
source, record a SHA-256 fingerprint, and invoke `Main.py --dataset-path ...`.
The LANL source was not downloadable in the offline local environment; **E12
has not been executed on a real dataset here**. `configs/full.json` defines
the intended experiment grid, but **the ten independently reset full Anvil
runs and pre/post contract gas comparison are not executed**. CI smoke tests
and pilot-scale synthetic traces cannot substitute for those observations.

The sequence-bound signed Merkle construction and on-chain ordering already
detect every tested hash-chain/manifest-link attack in P1 and B4. The per-event
hash chain is retained for backward compatibility and an explicit negative
ablation, **not** claimed as a new security contribution.
