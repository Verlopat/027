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
    assert maximize(before,'silent').removed_events==1
    next_seed=c._signer.snapshot_for_tests()
    after=CompromiseView(events,(seal,),schedule.public,cid,1,next_seed,{})
    assert maximize(after,'silent').removed_events==0
    anchored=CompromiseView(events,(seal,),schedule.public,cid,1,prior,{1:seal.checkpoint.digest()})
    assert maximize(anchored,'silent').removed_events==0
    assert len(strategies(anchored))>5
    c.close()
