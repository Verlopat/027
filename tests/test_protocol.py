import copy
import json
import pytest
from pabla.protocol import (ProtocolError,Policy,Collector,canonical,loads_strict,digest,
    keypair,public_hex,sign,valid_signature,genesis,event_hash,chain_hash,leaf_hash,
    merkle_proof,merkle_root,verify_proof,verify_batch,verify_history,verify_complete_history,manifest_hash)
from pabla.ledger import InMemoryLedger
from pabla.workloads import generate_events,attack_batch
from pabla.storage import new_run


def fixture_batches(n=6,batches=2,method='P1'):
    ledger=InMemoryLedger()
    sk,pk=keypair()
    ledger.register('alice',1,pk,policy_name=method)
    collector=Collector('alice',1,sk,Policy.for_name(method))
    all_events=generate_events(n*batches,123,'alice')
    artifacts=[]
    for i in range(batches):
        b=collector.collect(all_events[i*n:(i+1)*n])
        if collector.policy.anchor:
            ledger.anchor(b)
        artifacts.append(b)
    return ledger,collector,artifacts


def test_json_permutation_canonical():
    assert canonical({'b':2,'a':[1,2]})==canonical({'a':[1,2],'b':2})

def test_duplicate_json_key_rejected():
    with pytest.raises(ProtocolError): loads_strict('{"a":1,"a":2}')

def test_non_finite_rejected():
    for x in (float('nan'),float('inf')):
        with pytest.raises(ProtocolError): canonical({'bad':x})
    with pytest.raises(ProtocolError): loads_strict('{"bad":NaN}')

def test_unsafe_integer_rejected():
    with pytest.raises(ProtocolError): canonical({'bad':2**62})

def test_surrogate_rejected():
    with pytest.raises(ProtocolError): canonical({'bad':'\ud800'})

def test_cryptographic_signatures():
    sk,pk=keypair(); h=digest('test',b'payload'); sig=sign(sk,h)
    assert valid_signature(pk,h,sig)
    assert not valid_signature(pk,digest('test',b'other'),sig)

def test_domain_separation():
    assert digest('one',b'hello')!=digest('two',b'hello')
    assert digest('same',b'a',b'bc')!=digest('same',b'ab',b'c')

def test_merkle_proofs_multiple_sizes():
    for n in range(1,50):
        leaves=[digest('leaf',i) for i in range(n)]
        root=merkle_root(leaves)
        for i in range(n):
            p=merkle_proof(leaves,i)
            assert verify_proof(leaves[i],p,i,n,root)
            assert not verify_proof(digest('tamper',i),p,i,n,root)

def test_merkle_noncanonical_duplicate_last_rejected():
    leaves=[digest('leaf',i) for i in range(3)]
    p=merkle_proof(leaves,2)
    p[0]=digest('different')
    assert not verify_proof(leaves[2],p,2,3,merkle_root(leaves))

def test_accepts_history():
    l,c,bs=fixture_batches()
    assert [x.status for x in verify_history(bs,l,c.policy)]==['ACCEPT','ACCEPT']

def test_attacks_invalidate_evidence():
    l,c,bs=fixture_batches()
    for attack in ('AT1','AT2','AT3','AT4','AT6','AT8'):
        verdict=verify_batch(attack_batch(bs[0],attack),l,policy=c.policy)
        assert verdict.status.startswith('REJECT_'), (attack,verdict)

def test_archive_unavailable_not_integrity_rejection():
    l,c,bs=fixture_batches()
    assert verify_batch(None,l,policy=c.policy).status=='UNDETERMINED_ARCHIVE_MISSING'

def test_manifest_signature_substitution():
    l,c,bs=fixture_batches()
    tampered=copy.deepcopy(bs[0]);tampered.manifest['last_chain']='ff'*32
    tampered.manifest_digest=manifest_hash(tampered.manifest)
    assert verify_batch(tampered,l,policy=c.policy).status=='REJECT_AUTHORIZATION'

def test_batch_continuity_gap():
    l,c,bs=fixture_batches()
    assert verify_batch(bs[1],l,policy=c.policy).status=='REJECT_CONTINUITY'
    assert [x.status for x in verify_history([bs[0],bs[0]],l,c.policy)][1]=='REJECT_CONTINUITY'

def test_revocation_past_anchors_remain_valid():
    l,c,bs=fixture_batches()
    l.revoke('alice',1)
    assert verify_batch(bs[0],l,policy=c.policy).status=='ACCEPT'
    nxt=c.collect(generate_events(6,999,'alice'))
    with pytest.raises(ProtocolError): l.anchor(nxt)

def test_epoch_rotation():
    l,c,bs=fixture_batches()
    with pytest.raises(ProtocolError): l.register('alice',2,keypair()[1])
    l.revoke('alice',1)
    sk,pk=keypair();l.register('alice',2,pk,recovery=bs[-1].manifest_digest)
    changed=Collector('alice',2,sk)
    b=changed.collect(generate_events(3,4,'alice',2))
    l.anchor(b)
    assert verify_batch(b,l,policy=changed.policy).status=='ACCEPT'

def test_active_stolen_key_is_residual_risk():
    l,c,bs=fixture_batches()
    fake=generate_events(3,555,'alice')
    for i,e in enumerate(fake):e['collector_monotonic_ns']=13+i
    fabricated=c.collect(fake)
    l.anchor(fabricated)
    assert verify_batch(fabricated,l,policy=c.policy,previous=bs[-1].manifest).status=='ACCEPT'

def test_skew_warning():
    l,c,bs=fixture_batches()
    ev=generate_events(2,66,'alice')
    for i,x in enumerate(ev):x['collector_monotonic_ns']=20+i
    b=c.collect(ev,wall_time='2000-01-01T00:00:00.000Z')
    l.anchor(b)
    verdict=verify_batch(b,l,policy=c.policy,previous=bs[-1].manifest)
    assert verdict.status=='ACCEPT_WITH_WARNING' and 'CLOCK_SKEW' in verdict.anomalies

def test_duplicate_anchor_rejected():
    l,c,bs=fixture_batches()
    with pytest.raises(ProtocolError): l.anchor(bs[0])

def test_unregistered_key_rejected():
    l,c,bs=fixture_batches()
    l._identities.pop(('alice',1))
    assert verify_batch(bs[0],l,policy=c.policy).status=='REJECT_AUTHORIZATION'

def test_output_folders_unique(tmp_path):
    assert new_run(tmp_path).name=='test1'
    assert new_run(tmp_path).name=='test2'

def test_all_method_variants_valid():
    for method in ('P1','B1','B2','B3','B4','A1','A2','A3','A4','A5'):
        l,c,bs=fixture_batches(method=method)
        assert [v.status for v in verify_history(bs,l,c.policy)]==['ACCEPT','ACCEPT']


def test_monotonic_warning_does_not_skip_integrity():
    l,c,bs=fixture_batches()
    second=copy.deepcopy(bs[1])
    second.manifest['monotonic_ns'] = bs[0].manifest['monotonic_ns'] - 1
    second.manifest_digest=manifest_hash(second.manifest)
    second.signature=sign(c.private_key,second.manifest_digest)
    # Re-anchor a legitimate regressed-clock batch before testing an archive edit.
    l._anchors[('alice',1,2)]['manifest_hash']=second.manifest_digest
    warning=verify_batch(second,l,policy=c.policy,previous=bs[0].manifest)
    assert warning.status=='ACCEPT_WITH_WARNING',warning
    second.events[0]['payload']['pid'] += 1
    rejected=verify_batch(second,l,policy=c.policy,previous=bs[0].manifest)
    assert rejected.status=='REJECT_CONTENT_INTEGRITY',rejected

def test_policy_downgrade_is_rejected():
    l,c,bs=fixture_batches()
    altered=copy.deepcopy(bs[0])
    altered.manifest['method']='B3'
    altered.manifest_digest=manifest_hash(altered.manifest)
    altered.signature=''
    v=verify_batch(altered,l,policy=c.policy)
    assert v.status=='REJECT_AUTHORIZATION' and 'POLICY_DOWNGRADE' in v.anomalies
    with pytest.raises(TypeError):
        verify_batch(altered,l)

def test_truncated_history_is_rejected_against_chain_tip():
    l,c,bs=fixture_batches(batches=3)
    v=verify_complete_history(bs[:-1],l,policy=c.policy,collector_id='alice',epoch=1)
    assert v[-1].status=='REJECT_CONTINUITY' and 'TRUNCATION' in v[-1].anomalies
    assert all(x.status=='ACCEPT' for x in verify_complete_history(bs,l,policy=c.policy,collector_id='alice',epoch=1))

def test_adaptive_attacker_defeats_unsigned_hash_chain_but_not_signed_anchor():
    from pabla.workloads import adaptive_attack_batch
    for method,expected in [('B3','ACCEPT'),('P1','REJECT_AUTHORIZATION')]:
        l,c,bs=fixture_batches(method=method)
        modified=adaptive_attack_batch(bs[0],'AT1',c.policy)
        verdict=verify_batch(modified,l,policy=c.policy)
        assert verdict.status==expected,verdict

def test_memory_contract_enforces_mandatory_manifest_link():
    l,c,bs=fixture_batches()
    extra = c.collect(generate_events(2,818,'alice'))
    extra.manifest['previous_manifest_hash'] = '00'*32
    extra.manifest_digest=manifest_hash(extra.manifest)
    extra.signature=sign(c.private_key,extra.manifest_digest)
    with pytest.raises(ProtocolError): l.anchor(extra)
