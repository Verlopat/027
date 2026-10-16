"""Signed checkpoint ledger *TEST DOUBLE*, not an EVM finality/gas model."""
from __future__ import annotations
from .schedule import PublicSchedule
from .checkpoint import Sealed
from .crypto import recover_address
from .evidence import EquivocationProof

class MemoryLedger:
    backend='memory-test-double'
    def __init__(self):
        self.epochs:dict[tuple[bytes,int],PublicSchedule]={}
        self.records:dict[tuple[bytes,int],dict[int,bytes]]={}
        self.revoked:set[tuple[bytes,int]]=set()
        self.tips:dict[tuple[bytes,int],Sealed]={}
    def register(self,collector:bytes,epoch:int,schedule:PublicSchedule):
        key=collector,epoch
        if len(collector)!=32 or epoch<1 or key in self.epochs:raise ValueError('bad registration')
        self.epochs[key]=schedule;self.records[key]={}
    def anchor(self,sealed:Sealed):
        cp=sealed.checkpoint;key=(cp.collector,cp.epoch)
        if key in self.revoked or key not in self.epochs:raise ValueError('revoked or unregistered')
        sch=self.epochs[key];latest=self.tips.get(key)
        if cp.schedule_root!=sch.root or cp.period!=(sch.first if latest is None else latest.checkpoint.period+1):
            raise ValueError('schedule/period mismatch')
        if cp.prev!=(b'\x00'*32 if latest is None else latest.checkpoint.digest()):raise ValueError('bad predecessor')
        if latest is not None and cp.size<latest.checkpoint.size:raise ValueError('size regression')
        pk=sch.public_for(cp.period)
        if not sch.verify(cp.period,pk,list(sealed.key_proof)) or recover_address(cp.digest(),sealed.signature)!=pk:
            raise ValueError('invalid checkpoint signature')
        self.records[key][cp.period]=cp.digest();self.tips[key]=sealed
        return {'backend':self.backend,'period':cp.period,'digest':cp.digest().hex(),'gas_used':None}
    def prove_equivocation(self,proof:EquivocationProof):
        cp=proof.first.checkpoint;key=(cp.collector,cp.epoch)
        if key not in self.epochs or not proof.valid(self.epochs[key]):raise ValueError('invalid public proof')
        self.revoked.add(key);return True
    def anchors(self,collector:bytes,epoch:int)->dict[int,bytes]:
        return self.records[(collector,epoch)].copy()
