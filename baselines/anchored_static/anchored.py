"""Putz-style static-signature + Merkle-root anchor *adaptation*.

Not a paper-faithful reimplementation, and the anchor is an in-memory
third-party test double (no EVM gas claim). Original design needs separate
independent comparison before publication.
"""
from __future__ import annotations
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature
from pabla.v2.tree import CompactRange
from pabla.v2.crypto import sha
from baselines.common.adapter import BaselineResult

@dataclass(frozen=True)
class Batch:
    events:tuple[bytes,...]
    digest:bytes
    signature:bytes

class AnchoredStaticAdaptation:
    name='static-ed25519-merkle-anchor-adaptation'
    def __init__(self,secret:Ed25519PrivateKey|None=None):
        self._secret=secret or Ed25519PrivateKey.generate()
        self._public=self._secret.public_key()
        self.archive:list[Batch]=[]
        self.anchors:dict[int,bytes]={}
    def ingest(self,events)->BaselineResult:
        events=tuple(events)
        if any(not isinstance(e,bytes) for e in events):raise ValueError('requires bytes')
        tree=CompactRange()
        for ev in events:tree.append(ev)
        period=len(self.archive)+1
        digest=sha(b'PABLA-STATIC-ANCHOR\x00'+period.to_bytes(8,'big')+len(events).to_bytes(8,'big')+tree.root())
        signature=self._secret.sign(digest)
        self.archive.append(Batch(events,digest,signature))
        # Deliberate in-memory external anchor: this state is NOT compromised.
        self.anchors[period]=digest
        return BaselineResult('ok',self.name,verified_events=len(events))
    def verify(self)->BaselineResult:
        total=0
        if len(self.archive)!=len(self.anchors):
            return BaselineResult('reject',self.name,reason='missing anchored batch')
        for period,batch in enumerate(self.archive,1):
            tree=CompactRange()
            for e in batch.events:tree.append(e)
            digest=sha(b'PABLA-STATIC-ANCHOR\x00'+period.to_bytes(8,'big')+
                       len(batch.events).to_bytes(8,'big')+tree.root())
            if digest!=batch.digest or self.anchors.get(period)!=digest:
                return BaselineResult('reject',self.name,reason=f'anchor mismatch period {period}')
            try:self._public.verify(batch.signature,digest)
            except InvalidSignature:
                return BaselineResult('reject',self.name,reason=f'bad signature period {period}')
            total+=len(batch.events)
        return BaselineResult('accept',self.name,verified_events=total)
    def compromise(self,at_ms:int)->BaselineResult:
        return BaselineResult('ok',self.name,reason='static key stolen; already anchored digests remain independently protected')
    def cost(self)->dict:
        return {'status':'not_measured','gas':None,'batches':len(self.archive)}
