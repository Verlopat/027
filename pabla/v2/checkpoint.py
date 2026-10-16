"""Fixed-width Solidity ABI-compatible checkpoint wire format."""
from __future__ import annotations
from dataclasses import dataclass,asdict
from .crypto import sha,word,b32

DOMAIN=sha(b'PABLA-CHECKPOINT-v2')

@dataclass(frozen=True)
class Checkpoint:
    collector:bytes
    epoch:int
    period:int
    size:int
    root:bytes
    prev:bytes
    wall_ms:int
    schedule_root:bytes
    domain:bytes=DOMAIN
    def encode(self)->bytes:
        # Each field is a full EVM abi.encode 32-byte word.
        return b''.join((b32(self.domain),b32(self.collector),word(self.epoch),word(self.period),
                        word(self.size),b32(self.root),b32(self.prev),word(self.wall_ms),b32(self.schedule_root)))
    def digest(self)->bytes:return sha(self.encode())
    def to_dict(self)->dict:
        return {k:(v.hex() if isinstance(v,bytes) else v) for k,v in asdict(self).items()}
    @classmethod
    def from_dict(cls,d:dict)->'Checkpoint':
        keys=('collector','root','prev','schedule_root','domain')
        return cls(**{k:(bytes.fromhex(v) if k in keys else v) for k,v in d.items()})

@dataclass(frozen=True)
class Sealed:
    checkpoint:Checkpoint
    signature:bytes
    key_proof:tuple[bytes,...]
    def to_dict(self)->dict:return {'checkpoint':self.checkpoint.to_dict(),'signature':self.signature.hex(),'key_proof':[v.hex() for v in self.key_proof]}
    @classmethod
    def from_dict(cls,d:dict)->'Sealed':
        return cls(Checkpoint.from_dict(d['checkpoint']),bytes.fromhex(d['signature']),tuple(bytes.fromhex(v) for v in d['key_proof']))
