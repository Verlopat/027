"""Crash at *every observed SQL boundary* across multi-seal and idle heartbeat.

This is an injected exception/transaction consistency check, NOT SIGKILL or
physical-power-loss verification.
"""
from __future__ import annotations
import json
import os
from pabla.v2.collector import Collector
from pabla.v2.faults import FaultInjector, InjectedCrash
from pabla.v2.schedule import Schedule
from pabla.v2.verifier import verify_full
from pabla.v2.witness import Witness
from pabla.v2.tree import consistency_proof,log_leaf
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SEED=b'Z'*32
CID=b'F'*32
# appends between seals + empty heartbeat period
STEPS=[('append',i) for i in range(5)]+[('seal',100)]+\
      [('append',i) for i in range(5,8)]+[('seal',200),('seal',300)]+\
      [('append',i) for i in range(8,10)]+[('seal',400)]

def execute_until_crash(db, public, fault_at=None):
    c=Collector(db,CID,1,public,SEED)
    injector=FaultInjector(fault_at)
    c.store.set_fault_injector(injector)
    acked=set(); emitted=[]
    try:
        for action,value in STEPS:
            if action=='append':
                c.append({'id':value});acked.add(value)
            else:
                emitted.append(c.seal(value))
    except InjectedCrash:
        pass
    finally:
        c.close()
    return injector.count,acked,emitted

def test_all_instrumented_multi_period_sql_boundaries(tmp_path):
    schedule=Schedule.setup(SEED,3)
    total,_,_=execute_until_crash(tmp_path/'reference.db',schedule.public)
    assert total>45
    # Every fault site gets an independent database and deterministic replay.
    lower=int(os.environ.get("PABLA_CRASH_START","1"))
    upper=int(os.environ.get("PABLA_CRASH_END",str(total)))
    for k in range(lower,min(upper,total)+1):
        path=tmp_path/f'crash-{k}.db'
        count,acked,emitted=execute_until_crash(path,schedule.public,k)
        assert count>=k
        c=Collector(path,CID,1,schedule.public,SEED)
        try:
            recovered=c.recover()
            if recovered is not None:emitted.append(recovered)
            # Reconstruct the desired deterministic scenario from persisted
            # events and seals, without re-acknowledging committed records.
            for action,value in STEPS:
                if action=='append':
                    persisted={json.loads(e)['id'] for e in c.export_events()}
                    if value not in persisted:c.append({'id':value})
                else:
                    intended=[100,200,300,400].index(value)+1
                    if len(c.export_seals())<intended:
                        emitted.append(c.seal(value))
            events=c.export_events();seals=c.export_seals()
            ids={json.loads(e)['id'] for e in events}
            assert acked.issubset(ids),(k,acked,ids)
            assert ids==set(range(10))
            assert [s.checkpoint.period for s in seals]==[1,2,3,4]
            assert [s.checkpoint.size for s in seals]==[5,8,8,10]
            assert verify_full(events,seals,schedule.public,collector=CID,epoch=1,
                               now_ms=420,seal_interval_ms=100).accepted(),k
            # Any checkpoint that the collector managed to return pre-crash
            # must be byte-for-byte identical to the recovered period seal.
            canonical={s.checkpoint.period:s.to_dict() for s in seals}
            for signed in emitted:
                assert signed.to_dict()==canonical[signed.checkpoint.period],k
            w=Witness(tmp_path/f'witness-{k}.db',schedule.public,
                      Ed25519PrivateKey.generate())
            try:
                for signed in seals:
                    idx=signed.checkpoint.period-1
                    proof=consistency_proof([log_leaf(x) for x in events[:signed.checkpoint.size]],
                                            seals[idx-1].checkpoint.size) if idx else None
                    assert w.submit(signed,consistency=proof)[0]=='COSIGNED',k
            finally:w.close()
        finally:c.close()
