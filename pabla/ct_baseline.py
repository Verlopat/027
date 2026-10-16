"""RFC 6962-style Certificate Transparency history-tree *baseline*.

Domain-specific consistency and inclusion proofs use the exact SHA-256 leaf/node
prefix scheme described in RFC 6962 section 2.1. This is a comparative baseline
and not a copy of a live Certificate Transparency service. A signed checkpoint
proves that a log key endorsed one tree root; it cannot prove source truth.
"""
from __future__ import annotations

import hashlib
from typing import Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .protocol import canonical, digest, sign, valid_signature, public_hex, ProtocolError

EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node(left: bytes, right: bytes) -> bytes:
    if len(left) != 32 or len(right) != 32:
        raise ProtocolError("CT node must have 32-byte children")
    return hashlib.sha256(b"\x01" + left + right).digest()


def split_size(n: int) -> int:
    if n < 2:
        raise ProtocolError("CT split requires two or more leaves")
    return 1 << ((n - 1).bit_length() - 1)


def root(hashes: Sequence[bytes]) -> bytes:
    n = len(hashes)
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        if len(hashes[0]) != 32:
            raise ProtocolError("CT leaf must be 32 bytes")
        return hashes[0]
    k = split_size(n)
    return node(root(hashes[:k]), root(hashes[k:]))


def inclusion_proof(hashes: Sequence[bytes], index: int) -> list[bytes]:
    if not 0 <= index < len(hashes):
        raise ProtocolError("invalid CT inclusion index")
    if len(hashes) == 1:
        return []
    k = split_size(len(hashes))
    if index < k:
        return inclusion_proof(hashes[:k], index) + [root(hashes[k:])]
    return inclusion_proof(hashes[k:], index-k) + [root(hashes[:k])]


def verify_inclusion(h: bytes, index: int, size: int, proof: list[bytes], expected: bytes) -> bool:
    if not 0 <= index < size or len(h) != 32 or len(expected) != 32:
        return False
    # An RFC6962 path is not a duplicate-last-node Merkle proof. For a
    # non-power-of-two right subtree, walk from the leaf through RFC splits.
    def reconstruct(i: int, n: int, offset: int) -> bytes:
        if n == 1:
            return h
        k = split_size(n)
        if i < k:
            child = reconstruct(i, k, offset)
            if offset_ref[0] >= len(proof):
                raise ProtocolError("short CT inclusion proof")
            sib = proof[offset_ref[0]]
            offset_ref[0] += 1
            return node(child, sib)
        child = reconstruct(i-k, n-k, offset)
        if offset_ref[0] >= len(proof):
            raise ProtocolError("short CT inclusion proof")
        sib = proof[offset_ref[0]]
        offset_ref[0] += 1
        return node(sib, child)
    offset_ref = [0]
    try:
        actual = reconstruct(index, size, 0)
        return offset_ref[0] == len(proof) and actual == expected
    except (ProtocolError, IndexError, ValueError):
        return False


def consistency_proof(hashes: Sequence[bytes], old_size: int) -> list[bytes]:
    if old_size < 0 or old_size > len(hashes):
        raise ProtocolError("invalid CT consistency size")
    if old_size == 0:
        return []
    def subproof(m: int, xs: Sequence[bytes], complete: bool) -> list[bytes]:
        if m == len(xs):
            return [] if complete else [root(xs)]
        k = split_size(len(xs))
        if m <= k:
            return subproof(m, xs[:k], complete) + [root(xs[k:])]
        return subproof(m-k, xs[k:], False) + [root(xs[:k])]
    return subproof(old_size, hashes, True)


def verify_consistency(old_size: int, new_size: int, old: bytes, new: bytes, proof: list[bytes]) -> bool:
    if old_size < 0 or new_size < old_size or len(old) != 32 or len(new) != 32:
        return False
    if old_size == 0:
        return old == EMPTY_ROOT and not proof
    if old_size == new_size:
        return old == new and not proof
    if any(len(p) != 32 for p in proof):
        return False
    fn, sn = old_size-1, new_size-1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    if fn == 0:
        first, second = old, old
        path = proof
    else:
        if not proof:
            return False
        first = second = proof[0]
        path = proof[1:]
    for sibling in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            first = node(sibling, first)
            second = node(sibling, second)
            while fn and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            second = node(second, sibling)
        fn >>= 1
        sn >>= 1
    return sn == 0 and first == old and second == new


class CTBaseline:
    """Reference CT-like signed history tree for paired generated workloads."""
    def __init__(self, signing_key: Ed25519PrivateKey):
        self.signing_key = signing_key
        self.public_key = public_hex(signing_key)
        self.hashes: list[bytes] = []

    def append(self, event: dict) -> int:
        self.hashes.append(leaf(canonical(event)))
        return len(self.hashes)-1

    def checkpoint(self) -> dict:
        size = len(self.hashes)
        h = root(self.hashes).hex()
        commitment = digest("PABLA-CT-CHECKPOINT-v1", size, bytes.fromhex(h))
        return {"size": size, "root": h, "signature": sign(self.signing_key, commitment)}

    @staticmethod
    def verify_checkpoint(checkpoint: dict, public_key: str) -> bool:
        try:
            size = checkpoint["size"]
            if type(size) is not int or size < 0:
                return False
            r = bytes.fromhex(checkpoint["root"])
            return len(r) == 32 and valid_signature(public_key,
                digest("PABLA-CT-CHECKPOINT-v1", size, r),checkpoint["signature"])
        except (KeyError,ValueError,ProtocolError,TypeError):
            return False
