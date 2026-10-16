"""PABLA-FI public, hash-ratcheted Ed25519 period-key commitments.

Erasure is best-effort in CPython: bytearrays are overwritten but backend and
runtime copies cannot be guaranteed zeroized. Hardware-enforced erasure is NOT
claimed. A compromised current seed derives FUTURE, never PRIOR, seeds.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .protocol import ProtocolError, digest, merkle_root, merkle_proof, verify_proof, public_hex, sign


def ratchet(seed: bytes | bytearray) -> bytes:
    if len(seed) != 32:
        raise ProtocolError('FI ratchet seed must be 32 bytes')
    return bytes.fromhex(digest('PABLA-FI-RATCHET-v1', bytes(seed)))


def private_from_seed(seed: bytes | bytearray) -> Ed25519PrivateKey:
    if len(seed) != 32:
        raise ProtocolError('FI seed must be 32 bytes')
    return Ed25519PrivateKey.from_private_bytes(bytes(seed))


def period_leaf(period: int, public_key: str) -> str:
    if not isinstance(period, int) or period < 1 or len(public_key) != 64:
        raise ProtocolError('invalid FI period/key')
    return digest('PABLA-FI-KEY-v1', period, bytes.fromhex(public_key))


def validate_period_proof(period: int, public_key: str, proof: list[str], root: str,
                          start: int, count: int) -> bool:
    if not start <= period < start + count or count > 10000:
        return False
    try:
        leaf = period_leaf(period, public_key)
        return verify_proof(leaf, proof, period-start, count, root)
    except (ProtocolError, ValueError, TypeError):
        return False


@dataclass
class EvolvingSigner:
    """Keeps just current secret seed, schedule public keys and Merkle leaves.

    After each sign, the old mutable seed buffer is overwritten. Holding the
    current seed compromises the current period and all FUTURE periods.
    """
    _seed: bytearray = field(repr=False)
    start_period: int = 1
    count: int = 128
    current_period: int = 1
    public_keys: tuple[str, ...] = field(default_factory=tuple)
    leaves: tuple[str, ...] = field(default_factory=tuple)
    root: str = ''
    retain_old_for_ablation: bool = False
    historical_seeds: dict[int,bytes] = field(default_factory=dict,repr=False)

    @classmethod
    def create(cls, *, seed: bytes | None = None, count: int = 128, start_period: int = 1) -> 'EvolvingSigner':
        if not 1 <= count <= 10000 or start_period < 1:
            raise ProtocolError('invalid FI schedule bounds')
        first = bytearray(seed if seed is not None else os.urandom(32))
        if len(first) != 32:
            raise ProtocolError('invalid FI seed')
        temp = bytearray(first)
        public = []
        for _ in range(count):
            public.append(public_hex(private_from_seed(temp)))
            nxt = ratchet(temp)
            temp[:] = b'\x00' * len(temp)
            temp = bytearray(nxt)
        temp[:] = b'\x00' * len(temp)
        leaves = tuple(period_leaf(start_period+i, pk) for i,pk in enumerate(public))
        return cls(first, start_period, count, start_period, tuple(public), leaves, merkle_root(list(leaves)))

    def proof(self, period: int) -> list[str]:
        if not self.start_period <= period < self.start_period+self.count:
            raise ProtocolError('period outside FI schedule')
        return merkle_proof(list(self.leaves),period-self.start_period)

    def current_public(self) -> str:
        if not self.start_period <= self.current_period < self.start_period+self.count:
            raise ProtocolError('FI schedule exhausted; renew before next signature')
        return self.public_keys[self.current_period-self.start_period]

    def compromised_current_seed_for_test(self) -> bytes:
        """Explicit attack harness operation, never use in production logging."""
        return bytes(self._seed)

    def sign_and_evolve(self, message_hash: str) -> tuple[int,str,list[str],str]:
        period = self.current_period
        pk = self.current_public()
        signature = sign(private_from_seed(self._seed),message_hash)
        proof = self.proof(period)
        if self.retain_old_for_ablation:
            self.historical_seeds[period]=bytes(self._seed)
        new_seed = ratchet(self._seed)
        self._seed[:] = b'\x00'*len(self._seed)
        self._seed = bytearray(new_seed)
        self.current_period += 1
        return period,pk,proof,signature

    def renew(self, next_signer: 'EvolvingSigner') -> None:
        if next_signer.start_period != self.current_period:
            raise ProtocolError('schedule renewal must start at next unused period')
        self._seed[:] = b'\x00'*len(self._seed)
        self._seed = next_signer._seed
        self.start_period = next_signer.start_period
        self.current_period = next_signer.current_period
        self.count = next_signer.count
        self.public_keys = next_signer.public_keys
        self.leaves = next_signer.leaves
        self.root = next_signer.root
