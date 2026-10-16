"""Baseline checks call each adaptation's actual verifier."""
from dataclasses import replace
from baselines.schneier_kelsey.sk99 import SK99Adaptation
from baselines.anchored_static.anchored import AnchoredStaticAdaptation

def test_forward_hmac_chain_detects_edit_but_not_missing_suffix():
    b=SK99Adaptation(b'A'*32)
    b.ingest([b'one',b'two',b'three'])
    assert b.verify().status=='accept'
    b.archive[1]=replace(b.archive[1],payload=b'forged')
    assert b.verify().status=='reject'
    b.archive[1]=replace(b.archive[1],payload=b'two')
    b.archive.pop()
    assert b.verify().status=='accept' # no external clock/anchor

def test_static_anchoring_rejects_postcollection_edit_and_truncation():
    b=AnchoredStaticAdaptation()
    b.ingest([b'a',b'b']);b.ingest([b'c'])
    assert b.verify().verified_events==3
    original=b.archive[0]
    b.archive[0]=replace(original,events=(b'attack',b'b'))
    assert b.verify().status=='reject'
    b.archive[0]=original
    b.archive.pop()
    assert b.verify().status=='reject'
