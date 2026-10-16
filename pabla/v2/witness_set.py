"""Independent witness quorum receipts and sound quorum-intersection checks.

Two different quorums of size q intersect in >= 2q-k witnesses. With up
 to f Byzantine witnesses, honest intersection requires 2q > k+f.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Mapping
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .crypto import sha
from .checkpoint import Sealed
from .witness import Witness

@dataclass(frozen=True)
class QuorumCertificate:
    digest: str
    receipts: dict[str, dict]
    def to_dict(self) -> dict:
        return {'digest':self.digest,'receipts':self.receipts}

@dataclass(frozen=True)
class Submission:
    statuses: dict[str,str]
    certificate: QuorumCertificate|None
    evidence:tuple[object,...]


def receipt_valid(receipt:dict,public:Ed25519PublicKey,digest:bytes)->bool:
    try:
        if receipt['digest']!=digest.hex() or type(receipt['wall_ms']) is not int or not 0<=receipt['wall_ms']<2**64:
            return False
        message=sha(b'PABLA-v2-WITNESS'+digest+receipt['wall_ms'].to_bytes(8,'big'))
        public.verify(bytes.fromhex(receipt['signature']), message)
        return True
    except (InvalidSignature,ValueError,TypeError,KeyError,AttributeError):return False


def verify_certificate(cert:QuorumCertificate,tip:Sealed,keys:Mapping[str,Ed25519PublicKey],quorum:int)->bool:
    if quorum<1 or quorum>len(keys) or cert.digest!=tip.checkpoint.digest().hex():return False
    accepted=0
    for witness_id,rec in cert.receipts.items():
        if witness_id in keys and receipt_valid(rec,keys[witness_id],tip.checkpoint.digest()):accepted+=1
    return accepted>=quorum

class WitnessSet:
    def __init__(self,witnesses:Mapping[str,Witness],quorum:int,*,max_corrupt:int=0):
        if len(witnesses)!=len(set(witnesses)) or not witnesses:raise ValueError('witness IDs must be unique')
        if not 1<=quorum<=len(witnesses):raise ValueError('invalid quorum')
        if not 0<=max_corrupt<len(witnesses):raise ValueError('invalid corruption bound')
        if 2*quorum<=len(witnesses)+max_corrupt:
            raise ValueError('quorum intersection cannot guarantee an honest witness')
        self.witnesses=dict(witnesses);self.quorum=quorum;self.max_corrupt=max_corrupt
        self.evidence=[]
        self.publics={i:w.private.public_key() for i,w in witnesses.items()}
    def submit_all(self,sealed:Sealed,consistency:list[bytes]|None=None,wall_ms:int=0)->Submission:
        status={};receipts={};evidence=[]
        for i,w in self.witnesses.items():
            kind,result=w.submit(sealed,consistency,wall_ms)
            status[i]=kind
            if kind=='COSIGNED' and receipt_valid(result,self.publics[i],sealed.checkpoint.digest()):
                receipts[i]=result
            if kind=='EQUIVOCATION':evidence.append(result)
        self.evidence.extend(evidence)
        cert=QuorumCertificate(sealed.checkpoint.digest().hex(),receipts) if len(receipts)>=self.quorum else None
        return Submission(status,cert,tuple(evidence))
    def gossip(self)->tuple[object,...]:
        """Return validated conflict evidence for external ledger submission.

        This is an in-process deterministic gossip model; deployment requires
        authenticated network transport and independent witness machines.
        """
        for proof in self.evidence:
            for witness in self.witnesses.values():
                witness.receive_equivocation(proof)
        return tuple(self.evidence)
