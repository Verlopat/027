from __future__ import annotations
import copy,json,random,tempfile
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pabla.v2.crypto import (sha,keccak256,address,next_state,secret_for_state,sign_digest,recover_address,N)
from pabla.v2.schedule import Schedule,period_leaf
from pabla.v2.tree import (CompactRange,perfect_root,verify_perfect,log_leaf,reference_root,
    consistency_proof,verify_consistency)
from pabla.v2.checkpoint import Checkpoint,Sealed
from pabla.v2.collector import Collector
from pabla.v2.ledger import MemoryLedger
from pabla.v2.witness import Witness
from pabla.v2.verifier import verify_full,verify_light
from pabla.v2.evidence import EquivocationProof,find_equivocation
from pabla.v2.scheduling import optimal_anchor_times,brute_optimum,online_greedy,online_reservation,valid_schedule
from pabla.v2.attacks import sampled_window_probe,adaptive_drop
from pabla.v2.windows import EventTimes,predict
from pabla.v2.runner import execute

SEED=b'\x31'*32
COL=b'\x47'*32

@pytest.fixture
def schedule():return Schedule.setup(SEED,3)

def test_ethereum_keccak_and_address_vectors():
    assert keccak256(b'').hex()=='c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
    assert address(1).hex()=='7e5f4552091a69125d5dfcb7b8c2659029395bdf'

def test_low_s_deterministic_and_recovery():
    d=sha(b'period-1'); sig=sign_digest(1,d)
    assert sig==sign_digest(1,d)
    assert int.from_bytes(sig[32:64],'big')<=N//2
    assert recover_address(d,sig)==address(1)
    assert recover_address(sha(b'other'),sig)!=address(1)
    high=bytearray(sig);high[32:64]=(N-int.from_bytes(sig[32:64],'big')).to_bytes(32,'big')
    assert recover_address(d,bytes(high)) is None

def test_schedule_merkle_proofs_and_wrong_positions(schedule):
    pub=schedule.public
    assert len(pub.addresses)==8
    for period in range(1,9):
        assert pub.verify(period,pub.public_for(period),pub.proof(period))
        assert not pub.verify(period,address(1),pub.proof(period))
        if period>1:assert not pub.verify(period,pub.public_for(period-1),pub.proof(period))
    assert secret_for_state(next_state(SEED))!=secret_for_state(SEED)

def test_checkpoint_abi_layout_and_roundtrip(schedule):
    cp=Checkpoint(COL,1,1,5,sha(b'payload'),b'\x00'*32,100,schedule.public.root)
    assert len(cp.encode())==9*32
    assert Checkpoint.from_dict(cp.to_dict())==cp
    assert cp.digest()==sha(cp.encode())

def test_compact_tree_matches_reference_all_sizes():
    r=random.Random(2001);c=CompactRange();arr=[]
    for i in range(200):
        ev=r.randbytes(r.randrange(1,100));c.append(ev);arr.append(log_leaf(ev))
        assert c.root()==reference_root(arr)
    assert CompactRange().root()==sha(b'')

def test_consistency_proofs_all_pairs():
    r=random.Random(1);hashes=[log_leaf(r.randbytes(14)) for _ in range(39)]
    for old in range(1,len(hashes)+1):
        pr=consistency_proof(hashes,old)
        assert verify_consistency(old,len(hashes),reference_root(hashes[:old]),reference_root(hashes),pr)

def test_crash_injection_never_self_equivocates(tmp_path,schedule):
    for mode in ('after_intent','before_commit','after_commit'):
        path=tmp_path/(mode+'.db')
        c=Collector(path,COL,1,schedule.public,SEED)
        c.append({'sample':1})
        with pytest.raises(RuntimeError):c.seal(100,crash_at=mode)
        c.close()
        c=Collector(path,COL,1,schedule.public,SEED)
        if mode!='after_commit':
            committed=c.recover()
            assert committed is not None
        else: assert c.recover() is None
        sealed=c.export_seals()
        assert len(sealed)==1
        assert sealed[0].checkpoint.period==1
        assert c.store.state()[2]==2
        with pytest.raises(ValueError,match='stale'):c.store.begin_seal(sealed[0].checkpoint)
        c.close()

def test_heartbeats_witness_anchor_and_full_verifier(tmp_path,schedule):
    c=Collector(tmp_path/'logs.db',COL,1,schedule.public,SEED)
    witness_key=Ed25519PrivateKey.generate()
    w=Witness(tmp_path/'w.db',schedule.public,witness_key)
    ledger=MemoryLedger();ledger.register(COL,1,schedule.public)
    c.append({'event':1}); a=c.seal(100)
    status,receipt=w.submit(a,wall_ms=101)
    assert status=='COSIGNED'
    ledger.anchor(a)
    b=c.heartbeat(200)
    assert w.submit(b,[],wall_ms=201)[0]=='COSIGNED'
    ledger.anchor(b)
    verifier=verify_full(c.export_events(),c.export_seals(),schedule.public,collector=COL,epoch=1,anchors=ledger.anchors(COL,1))
    assert verifier.accepted() and verifier.verified_events==1
    assert verify_light(c.export_seals(),schedule.public,ledger.anchors(COL,1),collector=COL,epoch=1).accepted()
    assert verify_light([a],schedule.public,{},collector=COL,epoch=1,
        receipts={1:receipt},witness_public=witness_key.public_key()).accepted()
    forged_receipt={**receipt,'signature':'00'*64}
    assert not verify_light([a],schedule.public,{},collector=COL,epoch=1,
        receipts={1:forged_receipt},witness_public=witness_key.public_key()).accepted()
    # Archive removed or modified after signature must never verify.
    assert not verify_full([b'evil'],c.export_seals(),schedule.public,collector=COL,epoch=1).accepted()
    assert not verify_full(c.export_events(),[a],schedule.public,collector=COL,epoch=1,anchors=ledger.anchors(COL,1)).accepted()
    w.close();c.close()

def test_witness_refuses_and_produces_public_fraud_proof(tmp_path,schedule):
    c=Collector(tmp_path/'logs.db',COL,1,schedule.public,SEED)
    w=Witness(tmp_path/'w.db',schedule.public,Ed25519PrivateKey.generate())
    original_seed=c._signer.snapshot_for_tests()
    c.append({'log':'honest'});a=c.seal(50)
    assert w.submit(a)[0]=='COSIGNED'
    forged_cp=Checkpoint(COL,1,1,1,sha(b'changed'),b'\x00'*32,50,schedule.public.root)
    forgery=Sealed(forged_cp,sign_digest(secret_for_state(original_seed),forged_cp.digest()),a.key_proof)
    kind,evidence=w.submit(forgery)
    assert kind=='EQUIVOCATION' and evidence.valid(schedule.public)
    ledger=MemoryLedger();ledger.register(COL,1,schedule.public)
    ledger.anchor(a)
    assert ledger.prove_equivocation(evidence)
    with pytest.raises(ValueError):ledger.anchor(c.heartbeat(60))
    assert find_equivocation([a],[forgery])==evidence
    w.close();c.close()

def test_erased_period_key_cannot_forge_prior_period(tmp_path,schedule):
    c=Collector(tmp_path/'a.db',COL,1,schedule.public,SEED)
    c.append({'log':1});sealed=c.seal(20)
    stolen=c._signer.snapshot_for_tests()
    kept,wrong=adaptive_drop(sealed,c.export_events(),stolen,{0})
    v=verify_full(kept,[wrong],schedule.public,collector=COL,epoch=1)
    assert not v.accepted()
    c.close()

def test_adaptive_open_period_can_rewrite_but_sealed_cannot(schedule):
    rows=sampled_window_probe(schedule,[b'a',b'b',b'c'],[0,20,40],50,70,100,[10,30,50,75,110])
    expected=[predict([EventTimes(str(i),a,50,70,100) for i,a in enumerate([0,20,40])],t)
              for t in [10,30,50,75,110]]
    for row,model in zip(rows,expected):
        assert (row['modification_measured'],row['silent_measured'],row['unprovable_measured']) == (
            model.modification,model.silent_suppression,model.unprovable_suppression)
    assert rows[0]['verifier_status']=='ACCEPT' and rows[2]['verifier_status']=='REJECT_AUTHORIZATION'

def test_dp_equals_bruteforce_and_deadlines():
    rng=random.Random(348)
    for n in range(1,13):
        for D in range(1,min(7,n+2)):
            for _ in range(3):
                prices=[rng.randint(1,50) for _ in range(n)]
                value,times=optimal_anchor_times(prices,D)
                assert abs(value-brute_optimum(prices,D)[0])<1e-9
                assert valid_schedule(times,n,D)
                assert valid_schedule(online_greedy(prices,D),n,D)
                assert valid_schedule(online_reservation(prices,D,1,50),n,D)

def test_end_to_end_smoke_real_local_execution(tmp_path):
    result=execute(tmp_path,seed=1234,events=8)
    assert result['honest_verification']=='ACCEPT'
    assert result['adaptive_fork_verification']!='ACCEPT'
    assert result['witness_equivocation']=='EQUIVOCATION'
    assert result['fraud_proof_valid']
    assert result['scheduling']['price_source']=='synthetic'
    assert result['scheduling']['input_sha256'] is None
    assert (tmp_path/'report.json').exists()
