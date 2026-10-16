"""Forward-secure ratchet with perfect Merkle commitment to EVM signer addresses.

IMPORTANT: pure Python can overwrite bytearrays but cannot guarantee erasure of
secret copies in native integer temporaries, allocator pages, or crash dumps.
"""
from __future__ import annotations
from dataclasses import dataclass
from .crypto import sha, word, abi_address, address, FSState, secret_for_state, next_state, b32
from .tree import perfect_root, perfect_proof, verify_perfect
KEY_TAG=sha(b'PABLA-v2-PERIOD-KEY')

def period_leaf(period:int, signer:bytes)->bytes:
    return sha(KEY_TAG+word(period)+abi_address(signer))

@dataclass
class PublicSchedule:
    first:int
    height:int
    addresses:tuple[bytes,...]
    leaves:tuple[bytes,...]
    root:bytes
    def proof(self,period:int)->list[bytes]:
        idx=period-self.first
        if not 0<=idx<len(self.leaves):raise ValueError('period out of schedule')
        return perfect_proof(list(self.leaves),idx)
    def verify(self,period:int,signer:bytes,proof:list[bytes])->bool:
        idx=period-self.first
        return 0<=idx<len(self.leaves) and verify_perfect(period_leaf(period,signer),idx,self.height,proof,self.root)
    def public_for(self,period:int)->bytes:
        if not self.first<=period<self.first+len(self.addresses):raise ValueError('schedule exhausted')
        return self.addresses[period-self.first]

@dataclass
class Schedule:
    public:PublicSchedule
    state:FSState
    @classmethod
    def setup(cls,seed:bytes,height:int=4,first:int=1)->'Schedule':
        if not isinstance(seed,bytes) or len(seed)!=32 or not 1<=height<=16 or first<1:
            raise ValueError('bad seed/height/first period')
        temp=bytearray(seed)
        addrs=[]
        for _ in range(1<<height):
            addrs.append(address(secret_for_state(bytes(temp))))
            nxt=next_state(bytes(temp));temp[:]=b'\x00'*32;temp=bytearray(nxt)
        temp[:]=b'\x00'*32
        leaves=tuple(period_leaf(first+i,a) for i,a in enumerate(addrs))
        return cls(PublicSchedule(first,height,tuple(addrs),leaves,perfect_root(list(leaves))),FSState(bytearray(seed),first))
    def seal_signature(self,digest:bytes):
        from .crypto import sign_digest
        p=self.state.period
        if p>=self.public.first+(1<<self.public.height):raise ValueError('schedule exhausted')
        sig=sign_digest(self.state.secret(),b32(digest))
        proof=self.public.proof(p)
        self.state.advance()
        return sig,proof
