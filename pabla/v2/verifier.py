"""Strict trusted-policy verification. Never trusts policy from a checkpoint."""
from __future__ import annotations
from dataclasses import dataclass
from .checkpoint import Sealed
from .schedule import PublicSchedule
from .crypto import recover_address
from .tree import CompactRange

@dataclass(frozen=True)
class Verdict:
    status:str
    alarms:tuple[str,...]=()
    verified_periods:int=0
    verified_events:int=0
    def accepted(self)->bool:return self.status=='ACCEPT'

def verify_full(events:list[bytes],seals:list[Sealed],schedule:PublicSchedule,
                *,collector:bytes,epoch:int,now_ms:int|None=None,seal_interval_ms:int|None=None,
                clock_slack_ms:int=0,anchors:dict[int,bytes]|None=None,
                require_anchor:bool=False)->Verdict:
    """Fail closed; bound-by-checkpoint root re-evaluation. No open-world truth claim."""
    try:
        if len(collector)!=32 or epoch<1 or not seals:return Verdict('REJECT_CONTINUITY',('EMPTY_HISTORY',))
        if now_ms is not None and (seal_interval_ms is None or seal_interval_ms<=0 or clock_slack_ms<0):
            return Verdict('REJECT_POLICY',('BAD_TIME_POLICY',))
        cp0=seals[0].checkpoint
        if cp0.period!=schedule.first or cp0.prev!=b'\x00'*32:return Verdict('REJECT_CONTINUITY',('MISSING_GENESIS_PERIOD',))
        if any(not isinstance(e,bytes) for e in events):return Verdict('REJECT_CONTENT_INTEGRITY',('INVALID_EVENT_BYTES',))
        if anchors is None:anchors={}
        tree=CompactRange()
        old=None;pos=0
        for item in seals:
            cp=item.checkpoint
            if cp.collector!=collector or cp.epoch!=epoch or cp.domain!=cp0.domain:
                return Verdict('REJECT_AUTHORIZATION',('IDENTITY_OR_DOMAIN',))
            if cp.schedule_root!=schedule.root:return Verdict('REJECT_AUTHORIZATION',('SCHEDULE_ROOT',))
            expected_period=schedule.first if old is None else old.period+1
            if cp.period!=expected_period or (old is not None and cp.prev!=old.digest()):
                return Verdict('REJECT_CONTINUITY',('PERIOD_GAP_OR_LINK',))
            if old is not None and cp.wall_ms<old.wall_ms:
                return Verdict('REJECT_TIME',('CHECKPOINT_TIME_REGRESSION',))
            pk=schedule.public_for(cp.period)
            if not schedule.verify(cp.period,pk,list(item.key_proof)) or recover_address(cp.digest(),item.signature)!=pk:
                return Verdict('REJECT_AUTHORIZATION',('BAD_PERIOD_SIGNATURE',))
            if not pos<=cp.size<=len(events):return Verdict('REJECT_CONTENT_INTEGRITY',('SIZE_OUT_OF_RANGE',))
            while pos<cp.size:
                tree.append(events[pos]);pos+=1
            if tree.root()!=cp.root:return Verdict('REJECT_CONTENT_INTEGRITY',('MERKLE_ROOT',))
            if cp.period in anchors and anchors[cp.period]!=cp.digest():
                return Verdict('REJECT_ANCHOR',('ANCHOR_MISMATCH',))
            if require_anchor and cp.period not in anchors:return Verdict('REJECT_ANCHOR',('ANCHOR_MISSING',))
            old=cp
        if pos!=len(events):return Verdict('REJECT_CONTINUITY',('UNSEALED_ARCHIVE_TAIL',))
        if any(p>old.period for p in anchors):return Verdict('REJECT_CONTINUITY',('ANCHORED_TAIL_MISSING',))
        if now_ms is not None:
            if old.wall_ms>now_ms+clock_slack_ms:return Verdict('REJECT_TIME',('FUTURE_CHECKPOINT',))
            if now_ms-old.wall_ms>seal_interval_ms+clock_slack_ms:
                return Verdict('REJECT_CONTINUITY',('STALE_HEARTBEAT',))
        return Verdict('ACCEPT',(),len(seals),len(events))
    except (TypeError,ValueError,AttributeError,OverflowError,KeyError,IndexError) as e:
        return Verdict('REJECT_MALFORMED',(type(e).__name__,))

def verify_light(seals:list[Sealed],schedule:PublicSchedule,anchors:dict[int,bytes],
                 *,collector:bytes,epoch:int,receipts:dict[int,dict]|None=None,
                 witness_public=None)->Verdict:
    """Checks authenticated checkpoint tips only; makes NO raw-event integrity claim."""
    try:
        if not seals:return Verdict('REJECT_CONTINUITY',('EMPTY_HISTORY',))
        if not anchors and not receipts:return Verdict('REJECT_EXTERNAL_EVIDENCE',('NO_THIRD_PARTY_COMMITMENT',))
        old=None
        for sealed in seals:
            cp=sealed.checkpoint
            if cp.collector!=collector or cp.epoch!=epoch or cp.schedule_root!=schedule.root:
                return Verdict('REJECT_AUTHORIZATION',('IDENTITY',))
            if cp.period!=(schedule.first if old is None else old.period+1) or cp.prev!=(b'\x00'*32 if old is None else old.digest()):
                return Verdict('REJECT_CONTINUITY',('PERIOD_LINK',))
            pk=schedule.public_for(cp.period)
            if not schedule.verify(cp.period,pk,list(sealed.key_proof)) or recover_address(cp.digest(),sealed.signature)!=pk:
                return Verdict('REJECT_AUTHORIZATION',('SIGNATURE',))
            if cp.period in anchors and anchors[cp.period]!=cp.digest():return Verdict('REJECT_ANCHOR',('ANCHOR_CONFLICT',))
            if receipts is not None and cp.period in receipts:
                receipt=receipts[cp.period]
                if witness_public is None or receipt.get('digest')!=cp.digest().hex():
                    return Verdict('REJECT_EXTERNAL_EVIDENCE',('WITNESS_MISMATCH',))
                from .crypto import sha
                from cryptography.exceptions import InvalidSignature
                try:
                    t=receipt['wall_ms']
                    witness_public.verify(bytes.fromhex(receipt['signature']),
                        sha(b'PABLA-v2-WITNESS'+cp.digest()+t.to_bytes(8,'big')))
                except (InvalidSignature,ValueError,TypeError,KeyError,AttributeError):
                    return Verdict('REJECT_EXTERNAL_EVIDENCE',('BAD_COSIGNATURE',))
            old=cp
        if any(p>old.period for p in anchors):return Verdict('REJECT_CONTINUITY',('TRUNCATION',))
        return Verdict('ACCEPT',(),len(seals),old.size)
    except (ValueError,TypeError,AttributeError,OverflowError,KeyError,IndexError) as e:
        return Verdict('REJECT_MALFORMED',(type(e).__name__,))
