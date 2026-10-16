from pabla.v2.streaming import verify_stream
from pabla.v2.verifier import verify_full
from pabla.v2.collector import Collector
from pabla.v2.schedule import Schedule

def test_streaming_equivalent_and_detects_mutations(tmp_path):
    seed=b'W'*32;cid=b'C'*32;sch=Schedule.setup(seed,2)
    c=Collector(tmp_path/'c.db',cid,1,sch.public,seed)
    for i in range(50):c.append({'event':i})
    first=c.seal(100)
    for i in range(25):c.append({'event':i+50})
    last=c.seal(200)
    events=c.export_events();seals=[first,last]
    direct=verify_full(events,seals,sch.public,collector=cid,epoch=1)
    streaming=verify_stream(iter(events),seals,sch.public,collector=cid,epoch=1)
    assert direct.status==streaming.status=='ACCEPT' and streaming.verified_events==75
    damaged=list(events);damaged[20]=b'tampered'
    assert verify_stream(iter(damaged),seals,sch.public,collector=cid,epoch=1).status=='REJECT_CONTENT_INTEGRITY'
    assert verify_stream(iter(events[:-1]),seals,sch.public,collector=cid,epoch=1).status=='REJECT_CONTENT_INTEGRITY'
    assert verify_stream(iter(events+[b'extra']),seals,sch.public,collector=cid,epoch=1).status=='REJECT_CONTINUITY'
    assert verify_stream(iter(events),seals,sch.public,collector=cid,epoch=1,anchors={2:b'bad'}).status=='REJECT_ANCHOR'
    assert verify_stream(iter(events),seals,sch.public,collector=cid,epoch=1,require_anchor=True).status=='REJECT_ANCHOR'
    c.close()
