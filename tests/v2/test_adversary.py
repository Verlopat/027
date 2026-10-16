from pabla.v2.adversary import CompromiseView,maximize,strategies
from pabla.v2.schedule import Schedule
from pabla.v2.collector import Collector
from pabla.v2.crypto import sha

def test_attacker_search_uses_verifier_and_respects_key_erasure(tmp_path):
    seed=b'Q'*32;cid=b'X'*32;schedule=Schedule.setup(seed,2)
    c=Collector(tmp_path/'c.db',cid,1,schedule.public,seed)
    for i in range(4):c.append({'id':i})
    prior=c._signer.snapshot_for_tests()
    seal=c.seal(100)
    events=tuple(c.export_events())
    before=CompromiseView(events,(seal,),schedule.public,cid,1,prior,{})
    assert maximize(before,'silent',allow_no_freshness=True).removed_events==1
    next_seed=c._signer.snapshot_for_tests()
    after=CompromiseView(events,(seal,),schedule.public,cid,1,next_seed,{})
    assert maximize(after,'silent',allow_no_freshness=True).removed_events==0
    anchored=CompromiseView(events,(seal,),schedule.public,cid,1,prior,{1:seal.checkpoint.digest()})
    assert maximize(anchored,'silent',allow_no_freshness=True).removed_events==0
    assert len(strategies(anchored))>5
    c.close()


def test_drop_sealed_suffix_requires_trusted_freshness(tmp_path):
    from pabla.v2.verifier import verify_full
    import pytest
    seed=b'R'*32;cid=b'Y'*32;schedule=Schedule.setup(seed,3)
    c=Collector(tmp_path/'history.db',cid,1,schedule.public,seed)
    for i in range(3):c.append({'id':i})
    s1=c.seal(100)
    for i in range(3,7):c.append({'id':i})
    s2=c.seal(200)
    events=tuple(c.export_events());seals=(s1,s2)
    truncated_events=events[:s1.checkpoint.size]
    no_policy=verify_full(list(truncated_events),[s1],schedule.public,
                          collector=cid,epoch=1)
    assert no_policy.accepted()
    with_policy=verify_full(list(truncated_events),[s1],schedule.public,
                            collector=cid,epoch=1,now_ms=250,
                            seal_interval_ms=100,clock_slack_ms=0)
    assert with_policy.status=='REJECT_CONTINUITY'
    view=CompromiseView(events,seals,schedule.public,cid,1,
                        c._signer.snapshot_for_tests(),{},250,100,0)
    names=[item.name for item in strategies(view)]
    assert 'DROP_LAST_SEALED_PERIOD' in names
    assert 'DROP_PERIOD_THEN_HEARTBEAT' in names
    assert maximize(view,'silent').removed_events==0
    missed=maximize(view,'silent',allow_no_freshness=True)
    assert missed.removed_events==4
    assert missed.strategy=='DROP_LAST_SEALED_PERIOD'
    with pytest.raises(ValueError,match='trusted now_ms'):
        maximize(CompromiseView(events,seals,schedule.public,cid,1,
                                c._signer.snapshot_for_tests(),{}),'silent')
    c.close()
