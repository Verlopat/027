# PABLA-v2: implemented reference protocol

## Wire format

`Checkpoint` is SHA-256 of Solidity `abi.encode` of exactly nine 32-byte slots:
`domain, collector, epoch, period, size, root, prev, wallMs, scheduleRoot`.
`domain = SHA256("PABLA-CHECKPOINT-v2")`. All integers are unsigned 64-bit.
The log is an RFC 6962-style tree: `SHA256(0x00 || payload)` leaves and
`SHA256(0x01 || left || right)` nodes, with unequal subtree sizes split at the
largest power of two strictly smaller than the tree size. The empty root is
`SHA256("")`.

An independently computed schedule is a *perfect* binary Merkle tree over
`SHA256(abi.encode(KEY_TAG, period, signerAddress))`, where
`KEY_TAG=SHA256("PABLA-v2-PERIOD-KEY")`, and intermediate nodes use the same
`0x01` prefix. It has exactly `2^height` keys. Each signer address derives
from an ECDSA-secp256k1 public key via Ethereum Keccak-256, not SHA3-256.

For a current 32-byte state `s`, `NEXT(s)=framed_SHA256("PABLA-FSPRG-NEXT-v2",s)`
and `SK(s)=framed_SHA256("PABLA-FSPRG-SK-v2",s,counter)` interpreted as a
secp256k1 scalar with rejection sampling. This separates evolution from signing.
Each checkpoint is signed with RFC 6979 deterministic ECDSA and canonical low-s
signatures, encoded as 65 bytes `r || s || v` where `v=27/28`.

## Collector durability and witness custody

The reference SQLite collector first durably commits acknowledged events, then
persists `SealIntent` before computing a deterministic signature. A checkpoint,
its signature and the successor seed are committed in a *single SQLite transaction*.
After a crash prior to commit, recovery signs the unchanged persisted intent;
after commit, it re-emits the stored signature. Empty-period heartbeats are legal.

The witness stores checkpoints durably, checks epoch/period-key proofs and ECDSA
signatures, checks RFC 6962 consistency and period continuity, and returns an
Ed25519 cosignature or rejects. Same-period conflicting signatures produce a
public `EquivocationProof` containing two checkpoints, signatures and a Merkle
key proof. A v2 Solidity contract can validate such proof using `ecrecover` and
revoke an epoch. In the reference memory ledger, the same predicate is checked.

`verify_full` recomputes the prefix roots from the actual archived event bytes;
`verify_light` verifies signed checkpoints and independent witness/ledger evidence,
but explicitly does **not** assert that unseen event bytes are correct.

## Trust and limitations

The ratchet's old Python seed is overwritten on a best-effort basis, but the
SQLite journal and backups may expose historical key material. Real A-ERASE
requires a separate hardened storage design and review. A stolen current seed
still authorizes the current and future periods. A dishonest host may suppress
never-emitted events; the chain does not prove source truth. Witnesses may refuse
conflicts but cannot guarantee that a pre-compromise checkpoint was delivered.

This module is reference research software. Its Solidity contract and cross-
language vectors must be compiled and executed in Foundry/Anvil CI before EVM
correctness claims. Multi-party threshold witnesses, online deadline proofs,
Rust production key custody, and computational security proofs remain open.
