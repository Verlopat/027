"""Single-pass, O(log n) state verification of potentially huge event streams.

One immutable ordered Sealed list remains in memory; event records never do.
Compares the same trust roots as verify_full and rejects unsealed data.
"""
from __future__ import annotations
from typing import Iterable
from .checkpoint import Sealed
from .schedule import PublicSchedule
from .crypto import recover_address
from .tree import CompactRange
from .verifier import Verdict

def verify_stream(events:Iterable[bytes],seals:list[Sealed],schedule:PublicSchedule,
                  *,collector:bytes,epoch:int,anchors:dict[int,bytes]|None=None,
                  require_anchor:bool=False,now_ms:int|None=None,
                  seal_interval_ms:int|None=None,clock_slack_ms:int=0)->Verdict:
    try:
        if len(collector)!=32 or epoch<1 or not seals:
            return Verdict('REJECT_CONTINUITY',('EMPTY_HISTORY',))
        if now_ms is not None and (seal_interval_ms is None or seal_interval_ms<=0 or clock_slack_ms<0):
            return Verdict('REJECT_POLICY',('BAD_TIME_POLICY',))
        cp0=seals[0].checkpoint
        if cp0.period!=schedule.first or cp0.prev!=b'\x00'*32:
            return Verdict('REJECT_CONTINUITY',('MISSING_GENESIS_PERIOD',))
        observed=iter(events)
        anchors=anchors if anchors is not None else {}
        tree=CompactRange();pos=0;prev=None
        for entry in seals:
            cp=entry.checkpoint
            if cp.collector!=collector or cp.epoch!=epoch or cp.domain!=cp0.domain:
                return Verdict('REJECT_AUTHORIZATION',('IDENTITY_OR_DOMAIN',))
            if cp.schedule_root!=schedule.root:
                return Verdict('REJECT_AUTHORIZATION',('SCHEDULE_ROOT',))
            if cp.period!=(schedule.first if prev is None else prev.period+1) or cp.prev!=(b'\x00'*32 if prev is None else prev.digest()):
                return Verdict('REJECT_CONTINUITY',('PERIOD_GAP_OR_LINK',))
            if prev is not None and (cp.wall_ms<prev.wall_ms or cp.size<prev.size):
                return Verdict('REJECT_CONTINUITY',('REGRESSION',))
            pk=schedule.public_for(cp.period)
            if not schedule.verify(cp.period,pk,list(entry.key_proof)) or recover_address(cp.digest(),entry.signature)!=pk:
                return Verdict('REJECT_AUTHORIZATION',('BAD_PERIOD_SIGNATURE',))
            while pos<cp.size:
                try:value=next(observed)
                except StopIteration:return Verdict('REJECT_CONTENT_INTEGRITY',('PREMATURE_EOF',))
                if not isinstance(value,bytes):return Verdict('REJECT_CONTENT_INTEGRITY',('NON_BYTES',))
                tree.append(value);pos+=1
            if tree.root()!=cp.root:
                return Verdict('REJECT_CONTENT_INTEGRITY',('MERKLE_ROOT',))
            if cp.period in anchors and anchors[cp.period]!=cp.digest():
                return Verdict('REJECT_ANCHOR',('ANCHOR_MISMATCH',))
            if require_anchor and cp.period not in anchors:
                return Verdict('REJECT_ANCHOR',('ANCHOR_MISSING',))
            prev=cp
        sentinel=object()
        if next(observed,sentinel) is not sentinel:
            return Verdict('REJECT_CONTINUITY',('UNSEALED_ARCHIVE_TAIL',))
        if any(p>prev.period for p in anchors):
            return Verdict('REJECT_CONTINUITY',('ANCHORED_TAIL_MISSING',))
        if now_ms is not None:
            if prev.wall_ms>now_ms+clock_slack_ms:
                return Verdict('REJECT_TIME',('FUTURE_CHECKPOINT',))
            if now_ms-prev.wall_ms>seal_interval_ms+clock_slack_ms:
                return Verdict('REJECT_CONTINUITY',('STALE_HEARTBEAT',))
        return Verdict('ACCEPT',(),len(seals),pos)
    except (TypeError,ValueError,AttributeError,OverflowError,KeyError,IndexError) as e:
        return Verdict('REJECT_MALFORMED',(type(e).__name__,))
