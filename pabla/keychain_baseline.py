"""Forward-linked public-key baseline without a registered Merkle schedule.

The initial pk is trusted; each signed transition binds the next pk. A lost
transition prevents standalone verification of a later key. Off-chain only.
"""
from dataclasses import dataclass
from .protocol import digest, sign, valid_signature, public_hex
from .keyschedule import private_from_seed, ratchet

@dataclass(frozen=True)
class Transition:
    period: int
    public_key: str
    next_public_key: str
    signature: str


def issue_chain(seed: bytes, count: int) -> tuple[str,list[Transition],bytes]:
    if not 1 <= count <= 10000: raise ValueError('invalid period count')
    initial=public_hex(private_from_seed(seed)); current=seed
    out=[]
    for period in range(1,count+1):
        next_seed=ratchet(current)
        nxt=public_hex(private_from_seed(next_seed))
        message=digest('PABLA-FI-KEYCHAIN-LINK-v1',period,bytes.fromhex(nxt))
        out.append(Transition(period,public_hex(private_from_seed(current)),nxt,sign(private_from_seed(current),message)))
        current=next_seed
    return initial,out,current


def verify_chain(initial: str, transitions: list[Transition]) -> bool:
    trusted=initial
    for period,link in enumerate(transitions,1):
        if link.period!=period or link.public_key!=trusted or not valid_signature(
            trusted,digest('PABLA-FI-KEYCHAIN-LINK-v1',period,bytes.fromhex(link.next_public_key)),link.signature):
            return False
        trusted=link.next_public_key
    return True
