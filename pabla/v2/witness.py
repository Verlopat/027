"""Persistent, stateful witness for contiguous append-only checkpoints.

The witness assumes at most k-1 corrupted members; this reference implements
one independent witness. Missing/faulty delivery is reported, not hidden.
"""
from __future__ import annotations
import json
import sqlite3
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .checkpoint import Sealed
from .schedule import PublicSchedule
from .crypto import recover_address,sha
from .tree import verify_consistency
from .evidence import EquivocationProof

class Witness:
    def __init__(self,path:str|Path,schedule:PublicSchedule,private_key:Ed25519PrivateKey):
        self.db=sqlite3.connect(str(path),isolation_level=None)
        self.db.execute('PRAGMA journal_mode=DELETE');self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS checkpoints(collector TEXT, epoch INTEGER, period INTEGER, data TEXT, PRIMARY KEY (collector,epoch,period))')
        self.db.execute('CREATE TABLE IF NOT EXISTS equivocations(collector TEXT, epoch INTEGER, period INTEGER, evidence TEXT, PRIMARY KEY(collector,epoch,period))')
        self.schedule=schedule
        self.private=private_key
    def close(self):self.db.close()
    def stored(self,collector:bytes,epoch:int)->list[Sealed]:
        return [Sealed.from_dict(json.loads(r[0])) for r in self.db.execute('SELECT data FROM checkpoints WHERE collector=? AND epoch=? ORDER BY period',(collector.hex(),epoch))]
    def receive_equivocation(self,proof:EquivocationProof)->bool:
        """Persist externally supplied, independently verified fork evidence."""
        if not proof.valid(self.schedule):return False
        cp=proof.first.checkpoint
        doc={'first':proof.first.to_dict(),'second':proof.second.to_dict()}
        with self.db:
            self.db.execute('INSERT OR IGNORE INTO equivocations VALUES(?,?,?,?)',
                (cp.collector.hex(),cp.epoch,cp.period,json.dumps(doc,sort_keys=True)))
        return True
    def has_equivocation(self,collector:bytes,epoch:int)->bool:
        return self.db.execute('SELECT 1 FROM equivocations WHERE collector=? AND epoch=? LIMIT 1',
            (collector.hex(),epoch)).fetchone() is not None
    def submit(self,sealed:Sealed,consistency:list[bytes]|None=None,wall_ms:int=0):
        if type(wall_ms) is not int or wall_ms<0:raise ValueError('invalid witness time')
        cp=sealed.checkpoint
        if self.has_equivocation(cp.collector,cp.epoch):return 'REFUSE_EQUIVOCATED',None
        if cp.schedule_root!=self.schedule.root:return 'REFUSE_SCHEDULE',None
        try: expected=self.schedule.public_for(cp.period)
        except ValueError:return 'REFUSE_SCHEDULE',None
        if not self.schedule.verify(cp.period,expected,list(sealed.key_proof)) or recover_address(cp.digest(),sealed.signature)!=expected:
            return 'REFUSE_SIGNATURE',None
        old=self.stored(cp.collector,cp.epoch)
        if old:
            prev=old[-1].checkpoint
            if cp.period<=prev.period:
                earlier={x.checkpoint.period:x for x in old}.get(cp.period)
                if earlier and earlier.checkpoint.digest()!=cp.digest():
                    evidence=EquivocationProof(earlier,sealed)
                    self.receive_equivocation(evidence)
                    return 'EQUIVOCATION',evidence
                return 'DUPLICATE' if earlier else 'REFUSE_STALE',None
            if cp.period!=prev.period+1:return 'REFUSE_GAP',None
            if cp.prev!=prev.digest() or cp.size<prev.size:return 'REFUSE_LINK',None
            if cp.size==prev.size:
                if cp.root!=prev.root:return 'REFUSE_CONSISTENCY',None
            elif not verify_consistency(prev.size,cp.size,prev.root,cp.root,consistency or []):
                return 'REFUSE_CONSISTENCY',None
        elif cp.period!=self.schedule.first or cp.prev!=b'\x00'*32:
            return 'REFUSE_GENESIS',None
        with self.db:
            self.db.execute('INSERT INTO checkpoints VALUES(?,?,?,?)',
                (cp.collector.hex(),cp.epoch,cp.period,json.dumps(sealed.to_dict(),sort_keys=True)))
        message=sha(b'PABLA-v2-WITNESS'+cp.digest()+wall_ms.to_bytes(8,'big'))
        return 'COSIGNED',{'digest':cp.digest().hex(),'wall_ms':wall_ms,'signature':self.private.sign(message).hex()}
