"""Persistent append, period seal and crash-idempotent recovery; heartbeat seals."""
from __future__ import annotations
import json
from .crypto import sha, FSState, next_state, secret_for_state, sign_digest
from .checkpoint import Checkpoint,Sealed
from .schedule import PublicSchedule
from .tree import CompactRange
from .wal import PersistentLog
from ..protocol import canonical

class Collector:
    def __init__(self,path,collector_id:bytes,epoch:int,schedule:PublicSchedule,first_seed:bytes):
        if len(collector_id)!=32 or epoch<1:raise ValueError('bad collector id or epoch')
        self.id=collector_id;self.epoch=epoch;self.public=schedule
        self.store=PersistentLog(path,schedule.root,first_seed)
        self.tree=CompactRange()
        for record in self.store.events():self.tree.append(record)
        self._signer=FSState(bytearray(self.store.state()[1]),self.store.state()[2])
    def close(self):self.store.close()
    def append(self,event:dict)->int:
        if self.store.pending_intent():raise ValueError('must finish previous seal before appending')
        data=canonical(event)
        idx=self.store.append(data)
        self.tree.append(data)
        return idx
    def _sign_intent(self,cp:Checkpoint,crash_at:str|None)->Sealed:
        if crash_at=='after_intent':raise RuntimeError('injected crash after durable intent')
        period,seed,prev=self.store.state()[2],self.store.state()[1],self.store.state()[3]
        if period!=cp.period or prev!=cp.prev:raise ValueError('persisted intent mismatch')
        if self.public.public_for(period)!=self._address_of_seed(seed):raise ValueError('seed not in registered schedule')
        sig=sign_digest(secret_for_state(seed),cp.digest())
        proof=tuple(self.public.proof(period))
        record=Sealed(cp,sig,proof)
        if crash_at=='before_commit':raise RuntimeError('injected crash before seal commit')
        successor=next_state(seed)
        self.store.complete_seal(record,successor)
        self._signer._seed[:]=b'\x00'*32
        self._signer=FSState(bytearray(successor),period+1)
        if crash_at=='after_commit':raise RuntimeError('injected crash after atomic seal commit')
        return record
    @staticmethod
    def _address_of_seed(seed:bytes)->bytes:
        from .crypto import address
        return address(secret_for_state(seed))
    def recover(self)->Sealed|None:
        intent=self.store.pending_intent()
        if intent:return self._sign_intent(intent[1],None)
        return None
    def seal(self,wall_ms:int,*,crash_at:str|None=None)->Sealed:
        if type(wall_ms) is not int or wall_ms<0:raise ValueError('invalid timestamp')
        intent=self.store.pending_intent()
        if intent:
            cp=intent[1]
        else:
            period=self.store.state()[2]
            cp=Checkpoint(self.id,self.epoch,period,self.tree.size,self.tree.root(),self.store.state()[3],wall_ms,self.public.root)
            self.store.begin_seal(cp)
        return self._sign_intent(cp,crash_at)
    def heartbeat(self,wall_ms:int)->Sealed:return self.seal(wall_ms)
    def export_events(self)->list[bytes]:return self.store.events()
    def export_seals(self)->list[Sealed]:return self.store.sealed()
