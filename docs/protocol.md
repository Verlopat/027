# PABLA protocol v1

PABLA-v1 defines a deterministic, Python-compatible signed binary commitment. This implementation is **not** RFC 8785 JCS: it uses `json.dumps(sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)` after explicit validation of JSON values, safe integer bounds, max nesting, event schema, timestamp format, byte limits and JSON duplicate-property rejection at decode time. Cross-language clients must implement the *identical* serialization and number formatting, or be rejected. RFC 8785/JCS is a separate standardized alternative requiring an incompatible protocol version. Unicode strings are preserved, not normalized.

## Framed digest

`H(domain,parts...) = SHA256( uint32be(len(domainASCII)) || domainASCII || concat(uint64be(len(part)) || part for part in parts) )`, where integers are unsigned 64-bit big-endian and strings UTF-8. This prevents ambiguity between `(ab,c)` and `(a,bc)` and domain-separates hashes.

For collector `c`, epoch `e`, sequence `s` and canonical event bytes `b`:

```
h = H('PABLA-EVENT-v1', c, e, s, b)
q0 = H('PABLA-GENESIS-v1', c, e)
q = H('PABLA-CHAIN-v1', c, e, s, hexdecode(q_previous), hexdecode(h))
leaf = H('PABLA-LEAF-v1', s, hexdecode(h), hexdecode(q))
```

For chain-disabled baselines, `q` is 32 bytes of zero. Merkle parents hash `H('PABLA-NODE-v1', left32, right32)`. An odd final node is copied once before hashing; inclusion proofs include one sibling for every level, with mandatory self-sibling checks for duplicated leaves. A single-leaf root equals the leaf hash. An empty tree is invalid.

The batch manifest includes identity/epoch, batch number, first/last sequence, event count, first predecessor chain hash, last chain, Merkle root, prior manifest digest, signed wall clock, monotonic stamp and method. Its digest is `H('PABLA-MANIFEST-v1', canonical(manifest))`, signed by Ed25519 over exactly the 32 hash bytes. Public keys are 32 raw bytes, signatures are 64 bytes. `collector_id` is hashed into a bytes32 contract identifier, not placed in an event payload on-chain.

A successful `ACCEPT` means that, given the supplied archived event series, current configured trust roots, and available anchor, hashes, signatures, sequences and anchor match. `ACCEPT_WITH_WARNING` indicates plausible cryptographic evidence but timing anomalies. `UNDETERMINED_ARCHIVE_MISSING` means the verifier cannot reconstruct the archive from an anchor.

P1's signature proves that a matching private key signed the manifest; it does not certify that source events were truthful. Event continuity is conditional on observed neighboring evidence, and time plausibility depends on local clocks and the chain's weak block timestamp. For any journal-scale claim, note that the legacy policy alternatives are deliberately weaker.
