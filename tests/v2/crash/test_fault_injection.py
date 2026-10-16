"""Crash at every observable SQLite execution/transaction boundary.

Not a physical power-failure model; file-system guarantees remain assumptions.
"""
from __future__ import annotations
import pytest
from pabla.v2.collector import Collector
from pabla.v2.schedule import Schedule
from pabla.v2.faults import FaultInjector,InjectedCrash
from pabla.v2.verifier import verify_full
from pabla.v2.witness import Witness
from pabla.v2.tree import consistency_proof,log_leaf
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CID=b'B'*32;SEED=b'J'*32

def _run(path,schedule,fault_at=None):
    collector=Collector(path,CID,1,schedule.public,SEED)
    fi=FaultInjector(fault_at)
    collector.store.set_fault_injector(fi)
    ack=[];issued=[]
    try:
        for i in range(5):
            collector.append({'id':i});ack.append(i)
        issued.append(collector.seal(100))
    except InjectedCrash:
        pass
    finally:
        collector.close()
    return fi.count,ack,issued

def test_every_fault_boundary_preserves_acknowledged_events_and_unique_seals(tmp_path):
    schedule=Schedule.setup(SEED,3)
    total,_,_=_run(tmp_path/'reference.sqlite',schedule)
    assert total>5
    for k in range(1,total+1):
        path=tmp_path/f'fault-{k}.sqlite'
        _,acked,issued=_run(path,schedule,k)
        c=Collector(path,CID,1,schedule.public,SEED)
        try:
            recovered=c.recover()
            if recovered is not None:issued.append(recovered)
            events=c.export_events()
            seen={int(__import__('json').loads(e)['id']) for e in events}
            assert set(acked).issubset(seen)
            # If the seal has not happened, it is safe to finish it now.
            if not c.export_seals():issued.append(c.seal(100))
            persisted=c.export_seals()
            assert persisted and len({s.checkpoint.digest() for s in issued+persisted})==1
            assert verify_full(events,persisted,schedule.public,collector=CID,epoch=1).accepted()
            w=Witness(tmp_path/f'w-{k}.sqlite',schedule.public,Ed25519PrivateKey.generate())
            assert w.submit(persisted[0])[0]=='COSIGNED'
            w.close()
        finally:c.close()
