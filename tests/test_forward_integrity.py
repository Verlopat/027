"""Focused PABLA-FI regression and randomized property checks."""
from __future__ import annotations
import copy
import random
from pathlib import Path
import pytest
from pabla.protocol import (Batch, Collector, Policy, ProtocolError, keypair,
    manifest_hash, sign, verify_batch, verify_pending_batch, verify_complete_history)
from pabla.keyschedule import EvolvingSigner, private_from_seed, ratchet, validate_period_proof
from pabla.ledger import InMemoryLedger
from pabla.workloads import adaptive_attack_batch, adaptive_reissue_history, generate_events, rebuild_untrusted
from pabla.experiments import Options, fi_compromise, fi_exposure, fi_frontier, fi_public_replay
from pabla.anchoring import windows,exposed_events
from pabla.keychain_baseline import issue_chain, verify_chain


def setup_fi(method='FI',seed=b'A'*32):
    l=InMemoryLedger()
    schedule=EvolvingSigner.create(seed=seed,count=8)
    schedule.retain_old_for_ablation=method=='FI-noerase'
    l.register_fi('fi-source',1,schedule.root,schedule.count,policy_name=method)
    sk,_=keypair()
    c=Collector('fi-source',1,sk,Policy.for_name(method),evolving=schedule)
    events=generate_events(12,27,'fi-source')
    batches=[]
    for i in range(3): batches.append(c.collect(events[4*i:4*i+4]))
    return l,c,batches


def test_fi_schedule_merkle_inclusion_and_erase():
    schedule=EvolvingSigner.create(seed=bytes.fromhex('17'*32),count=16)
    root=schedule.root
    assert len({schedule.public_keys[i] for i in range(16)})==16
    for p in range(1,17):
        assert validate_period_proof(p,schedule.public_keys[p-1],schedule.proof(p),root,1,16)
        assert not validate_period_proof(p,schedule.public_keys[(p)%16],schedule.proof(p),root,1,16)
    previous=schedule.current_public()
    _,_,_,_=schedule.sign_and_evolve('aa'*32)
    assert previous!=schedule.current_public()
    assert not schedule.historical_seeds
    assert previous!=private_from_seed(schedule.compromised_current_seed_for_test()).public_key().public_bytes_raw().hex()
    assert ratchet(bytes.fromhex('17'*32))==schedule.compromised_current_seed_for_test()


def test_period_substitution_and_backfill_rejected():
    l,c,b=setup_fi()
    l.anchor(b[0]);l.anchor(b[1])
    assert [v.status for v in verify_complete_history(b[:2],l,policy=c.policy,collector_id=c.collector_id,epoch=1)]==['ACCEPT','ACCEPT']
    forged=copy.deepcopy(b[1]);forged.manifest['period']=1
    forged.manifest_digest=manifest_hash(forged.manifest)
    forged.signature=sign(private_from_seed(c.evolving.compromised_current_seed_for_test()),forged.manifest_digest)
    assert verify_batch(forged,l,policy=c.policy,previous=b[0].manifest).status=='REJECT_AUTHORIZATION'
    with pytest.raises(ProtocolError):l.anchor(b[1])
    l.revoke('fi-source',1)
    with pytest.raises(ProtocolError):l.anchor(b[2])


def test_pending_past_period_rewrite_distinguishes_erasure():
    for method,accepted in [('FI',False),('FI-nochain',False),('FI-noerase',True)]:
        l,c,b=setup_fi(method)
        l.anchor(b[0])
        forged=copy.deepcopy(b[1])
        forged.events[0]['payload']['pid']+=1
        forged=rebuild_untrusted(forged,c.policy)
        stolen=c.evolving.historical_seeds.get(2,c.evolving.compromised_current_seed_for_test())
        forged.signature=sign(private_from_seed(stolen),forged.manifest_digest)
        v=verify_pending_batch(forged,l,policy=c.policy,previous=b[0].manifest)
        assert (v.status=='ACCEPT_WITH_WARNING') is accepted,(method,v)


def test_anchored_batch_cannot_be_rewritten_even_with_correct_old_key():
    l,c,b=setup_fi('FI-noerase')
    l.anchor(b[0])
    forged=copy.deepcopy(b[0]);forged.events[0]['payload']['pid']+=2
    forged=rebuild_untrusted(forged,c.policy)
    forged.signature=sign(private_from_seed(c.evolving.historical_seeds[1]),forged.manifest_digest)
    assert verify_batch(forged,l,policy=c.policy).status=='REJECT_ANCHOR'


def test_recovery_schedule_renewal_preserves_old_roots():
    l,c,b=setup_fi()
    for one in b:l.anchor(one)
    newer=EvolvingSigner.create(seed=b'B'*32,count=4,start_period=4)
    l.renew_fi('fi-source',1,newer.root,newer.count)
    c.evolving.renew(newer)
    extra=c.collect(generate_events(2,61,'fi-source'))
    l.anchor(extra)
    assert verify_batch(extra,l,policy=c.policy,previous=b[-1].manifest).status=='ACCEPT'
    assert verify_batch(b[0],l,policy=c.policy).status=='ACCEPT'
    assert l.latest_period('fi-source',1)==4
    assert l.fi_schedule('fi-source',1,4)['root']==newer.root
    assert l.fi_schedule('fi-source',1,3)['root']!=newer.root


def test_at8_regression_not_noop():
    from pabla.protocol import Collector
    sk,pk=keypair();l=InMemoryLedger();l.register('x',1,pk)
    c=Collector('x',1,sk);b=c.collect(generate_events(4,2,'x'));l.anchor(b)
    attacked=adaptive_attack_batch(b,'AT8',c.policy)
    assert attacked.export()!=b.export()
    assert verify_batch(attacked,l,policy=c.policy).status.startswith('REJECT_')


def test_unsigned_adaptive_archive_regression():
    sk,pk=keypair();l=InMemoryLedger();l.register('x',1,pk,policy_name='B3')
    c=Collector('x',1,sk,Policy.for_name('B3'))
    ev=generate_events(12,2,'x');b=[c.collect(ev[i:i+4]) for i in range(0,12,4)]
    assert all(v.status=='ACCEPT' for v in __import__('pabla.protocol',fromlist=['verify_history']).verify_history(
        adaptive_reissue_history(b,c.policy,'BATCH_REORDER'),l,c.policy))
    assert all(v.status=='ACCEPT' for v in __import__('pabla.protocol',fromlist=['verify_history']).verify_history(
        adaptive_reissue_history(b,c.policy,'AT2'),l,c.policy))


def test_keychain_reference_missing_transition():
    root,links,_=issue_chain(b'M'*32,4)
    assert verify_chain(root,links)
    assert not verify_chain(root,links[:2]+links[3:])


def test_e9_measured_differential():
    rows=fi_compromise(Options(trials=1,event_count=12,batch_size=4))
    attack='REWRITE_PREVIOUS_SIGNED_PENDING_PERIOD'
    result={r['method']:r['accepted'] for r in rows if r.get('attack')==attack}
    assert result['FI']==0 and result['FI-noerase']==1 and result['P1']==1 and result['B4']==1
    assert all(r['accepted']==0 for r in rows if r.get('attack')=='REWRITE_ALREADY_ANCHORED')


def test_randomized_exposure_count_10000_cases():
    random_source=random.Random(8173)
    for _ in range(10_000):
        arrivals=[]; t=0
        for _ in range(random_source.randrange(1,25)):
            t+=random_source.randrange(0,31);arrivals.append(t)
        w=windows(arrivals,batch_size=random_source.randrange(1,20),max_dwell_ms=100,
                  max_exposure_ms=50)
        assert max(win.max_wait_ms for win in w)<=50
        compromise=random_source.randrange(0,arrivals[-1]+51)
        last_anchor=max((win.confirmed_ms for win in w if win.confirmed_ms<compromise),default=-1)
        expected=sum(last_anchor<x<=compromise for x in arrivals)
        assert exposed_events(arrivals,w,compromise)==expected


def test_lanl_stream_loader_sha256(tmp_path):
    from pabla.datasets import replay_times
    import hashlib
    sample=b'1,user1,host1\n1,user2,host2\n3,user2,host3\n'
    p=tmp_path/'synthetic-test-only.csv';p.write_bytes(sample)
    arrival,sizes,checksum=replay_times(p)
    assert arrival==[0,0,2000]
    assert sizes==[len(x) for x in sample.splitlines(keepends=True)]
    assert checksum==hashlib.sha256(sample).hexdigest()
    r=fi_public_replay(Options(dataset_path=str(p),event_count=3,batch_size=2))
    assert all(x['status']=='EXECUTED' and x['source_sha256']==checksum for x in r)
