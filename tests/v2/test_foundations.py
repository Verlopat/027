from pathlib import Path
import os
import sqlite3
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pabla.v2.crypto import sha,sign_digest,secret_for_state
from pabla.v2.backends import ReferenceBackend,selected_backend
from pabla.v2.keystore import FileSeedStore,SqliteSeedStore
from pabla.v2.schedule import Schedule
from pabla.v2.collector import Collector
from pabla.v2.witness import Witness
from pabla.v2.witness_set import WitnessSet,verify_certificate,QuorumCertificate
from pabla.v2.reporting import TrustedPolicy,verify_report
from pabla.v2.envcapture import capture

SEED=b'\x21'*32; CID=b'\x20'*32

def test_environment_manifest(tmp_path):
    (tmp_path/'uv.lock').write_bytes(b'fixed')
    manifest=capture(tmp_path)
    assert manifest['lock_sha256']==sha(b'fixed').hex()
    assert 'tool_versions' in manifest and 'kernel' in manifest

def test_reference_backend_and_selection(monkeypatch):
    d=sha(b'message'); s=ReferenceBackend().sign_digest(1,d)
    assert ReferenceBackend().recover_address(d,s)==ReferenceBackend().address(1)
    monkeypatch.setenv('PABLA_CRYPTO_BACKEND','reference')
    assert selected_backend().name=='reference-python'
    monkeypatch.setenv('PABLA_CRYPTO_BACKEND','garbage')
    with pytest.raises(ValueError):selected_backend()

def test_file_seed_store_permissions_atomic(tmp_path):
    p=tmp_path/'secret.key';s=FileSeedStore(p)
    s.replace(SEED);assert s.load()==SEED; assert p.stat().st_mode&0o777==0o600
    s.replace(b'\x03'*32);assert s.load()==b'\x03'*32
    with pytest.raises(ValueError):s.replace(b'bad')
    assert len(list(tmp_path.iterdir()))==1

def test_sqlite_seed_store_does_not_claim_erasure():
    db=sqlite3.connect(':memory:');db.execute('CREATE TABLE state(id INTEGER,seed BLOB)')
    db.execute('INSERT INTO state VALUES(1,?)',(SEED,));s=SqliteSeedStore(db)
    assert s.load()==SEED;s.replace(b'\x04'*32)
    assert s.load()==b'\x04'*32;s.erase_old()

def test_witness_set_quorum_and_fork(tmp_path):
    schedule=Schedule.setup(SEED,2)
    c=Collector(tmp_path/'collector.db',CID,1,schedule.public,SEED)
    secret=c._signer.snapshot_for_tests()
    w={i:Witness(tmp_path/f'w{i}.db',schedule.public,Ed25519PrivateKey.generate()) for i in ('a','b','c')}
    with pytest.raises(ValueError,match='intersection'):
        WitnessSet(w,2,max_corrupt=1)
    ws=WitnessSet(w,3,max_corrupt=1)
    c.append({'id':1});first=c.seal(100)
    accepted=ws.submit_all(first,wall_ms=200)
    assert accepted.certificate is not None
    assert verify_certificate(accepted.certificate,first,ws.publics,3)
    damaged=QuorumCertificate(accepted.certificate.digest,{**accepted.certificate.receipts,'a':{'digest':'bad'}})
    assert not verify_certificate(damaged,first,ws.publics,3)
    from pabla.v2.checkpoint import Checkpoint,Sealed
    cp=first.checkpoint
    other=Checkpoint(cp.collector,cp.epoch,cp.period,cp.size,sha(b'other'),cp.prev,cp.wall_ms,cp.schedule_root)
    fork=Sealed(other,sign_digest(secret_for_state(secret),other.digest()),first.key_proof)
    collision=ws.submit_all(fork,wall_ms=201)
    assert collision.certificate is None and len(collision.evidence)==3
    assert all(p.valid(schedule.public) for p in ws.gossip())
    for witness in w.values():witness.close()
    c.close()

def test_trusted_policy_verifier_detects_stale_and_corruption(tmp_path):
    schedule=Schedule.setup(SEED,2)
    c=Collector(tmp_path/'c.db',CID,1,schedule.public,SEED)
    c.append({'id':1});sealed=c.seal(1000)
    policy=TrustedPolicy(CID,1,schedule.public,start_ms=0,seal_interval_ms=1000)
    ok=verify_report(c.export_events(),[sealed],policy,now_ms=1200)
    assert ok.status=='ACCEPT' and ok.freshness=='FRESH'
    stale=verify_report(c.export_events(),[sealed],policy,now_ms=5000)
    assert stale.status!='ACCEPT' and stale.freshness=='STALE'
    tampered=verify_report([b'bad'],[sealed],policy,now_ms=1200)
    assert tampered.status=='REJECT_CONTENT_INTEGRITY' and tampered.integrity=='FAIL'
    c.close()
