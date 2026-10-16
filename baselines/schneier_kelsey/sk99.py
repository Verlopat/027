"""Forward-integrity HMAC chain: explicitly an SK99-inspired *adaptation*.

NOT a verified reproduction of Schneier--Kelsey (TISSEC 1999). In particular,
we omit the paper's full authenticated-encryption/key-recovery protocol. This
model represents the *trusted initial secret* verifier assumption, enabling a
fairly labelled forward-integrity control in local archive-attack experiments.
"""
from __future__ import annotations
import hashlib,hmac
from dataclasses import dataclass
from baselines.common.adapter import BaselineResult

def _next(s:bytes)->bytes:
    return hashlib.sha256(b'PABLA-SK99-ADAPT-NEXT\x00'+s).digest()

def _record_mac(s:bytes,seq:int,previous:bytes,data:bytes)->bytes:
    framed=seq.to_bytes(8,'big')+len(data).to_bytes(8,'big')+data+previous
    return hmac.new(s, b'PABLA-SK99-ADAPT-RECORD\x00'+framed,hashlib.sha256).digest()

@dataclass(frozen=True)
class Record:
    sequence:int
    payload:bytes
    previous:bytes
    mac:bytes

class SK99Adaptation:
    name='sk99-forward-hmac-adaptation'
    def __init__(self,initial_secret:bytes):
        if not isinstance(initial_secret,bytes) or len(initial_secret)!=32:
            raise ValueError('trusted initial secret must be 32 bytes')
        self._original=initial_secret # verifier trust-root held separately
        self._current=initial_secret
        self.archive:list[Record]=[]
    def ingest(self,events)->BaselineResult:
        for raw in events:
            if not isinstance(raw,bytes):raise ValueError('bytes required')
            seq=len(self.archive)+1
            previous=self.archive[-1].mac if self.archive else b'\x00'*32
            mac=_record_mac(self._current,seq,previous,raw)
            self.archive.append(Record(seq,raw,previous,mac))
            self._current=_next(self._current)
        return BaselineResult('ok',self.name,verified_events=len(self.archive))
    def verify(self)->BaselineResult:
        state=self._original;prior=b'\x00'*32
        for i,item in enumerate(self.archive,1):
            if (item.sequence!=i or item.previous!=prior or
                not hmac.compare_digest(item.mac,_record_mac(state,i,prior,item.payload))):
                return BaselineResult('reject',self.name,reason=f'bad sequence or MAC at {i}')
            prior=item.mac;state=_next(state)
        # Without external freshness evidence, suffix truncation stays silent.
        return BaselineResult('accept',self.name,verified_events=len(self.archive))
    def compromise(self,at_ms:int)->BaselineResult:
        return BaselineResult('ok',self.name,reason='current seed can be copied but earlier seed cannot be derived by forward hash')
    def current_seed_for_attack_testing(self)->bytes:
        return self._current
    def cost(self)->dict:
        return {'status':'not_measured','gas':None,'records':len(self.archive)}
