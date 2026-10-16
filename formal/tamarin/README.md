# PABLA-v2 Tamarin research draft — NOT CHECKED

`pabla_v2.spthy` is a **first incomplete symbolic abstraction**, not a verified
security proof. The model has only a reachable-honest-seal sanity lemma. The
forward-integrity, fork-accountability and honest-nonrevocation lemmas L1–L3
from the prompt pack are deliberately **not marked as proven**, because the
current model lacks a complete key-schedule registration, consistent witness
state, and revocation/gossip delivery mechanism. Writing trivial tautological
lemmas would be worse than explicitly leaving these obligations open.

Requires Tamarin Prover and Maude; neither binary was available during this
implementation session. To start review, run:

```sh
tamarin-prover --parse-only formal/tamarin/pabla_v2.spthy
tamarin-prover --prove formal/tamarin/pabla_v2.spthy
```

A successful parse is only the first gate. A reviewer must add key-schedule
binding, contiguity, a corrupt-current-state rule, witness disagreement,
revocation and delayed ledger delivery, and check traces/lemmas for vacuity.
The model deliberately abstracts out ECDSA malleability, ledger consensus,
clock drift, secure erasure, and crash recovery.

References for syntax: [Tamarin official manual](https://tamarin-prover.com/manual/master/book/005_protocol-specification-rules.html).
