"""Trusted time policy and structured verifier findings."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Mapping
from .schedule import PublicSchedule
from .checkpoint import Sealed
from .verifier import verify_full, Verdict
from .witness_set import QuorumCertificate,verify_certificate

@dataclass(frozen=True)
class TrustedPolicy:
    collector:bytes
    epoch:int
    schedule:PublicSchedule
    start_ms:int
    seal_interval_ms:int
    slack_ms:int=0
    require_anchor:bool=False
    quorum:int=0
    witness_keys:Mapping|None=None
    def __post_init__(self):
        if not self.collector or len(self.collector)!=32 or self.epoch<1 or self.start_ms<0 or self.seal_interval_ms<1 or self.slack_ms<0:
            raise ValueError('invalid trusted policy')
        if self.quorum<0 or self.quorum>len(self.witness_keys or {}):raise ValueError('bad quorum')

@dataclass(frozen=True)
class PropertyReport:
    status:str
    integrity:str
    continuity:str
    freshness:str
    anchoring:str
    equivocation:str
    alarms:tuple[str,...]
    verified_events:int
    verified_periods:int


def verify_report(events:list[bytes],seals:list[Sealed],policy:TrustedPolicy,*,now_ms:int,
                  anchors:dict[int,bytes]|None=None,certificate:QuorumCertificate|None=None)->PropertyReport:
    """Failure is never hidden by successful checks; no fake evidence claims."""
    if not isinstance(now_ms,int) or now_ms<policy.start_ms:
        return PropertyReport('REJECT_POLICY','UNKNOWN','UNKNOWN','UNKNOWN','UNKNOWN','UNKNOWN',('BAD_TIME',),0,0)
    v=verify_full(events,seals,policy.schedule,collector=policy.collector,epoch=policy.epoch,
        anchors=anchors,require_anchor=policy.require_anchor)
    alarms=list(v.alarms)
    interval=policy.seal_interval_ms
    expected=policy.schedule.first+(now_ms-policy.start_ms)//interval-1
    tolerated=(policy.slack_ms+interval-1)//interval
    freshness='UNKNOWN'
    if not seals:
        alarms.append('EMPTY_HISTORY')
    else:
        tip=seals[-1].checkpoint
        freshness='STALE' if tip.period<expected-tolerated else 'FRESH'
        if freshness=='STALE':alarms.append('STALE_PERIOD')
        if tip.wall_ms>now_ms+policy.slack_ms:freshness='FUTURE';alarms.append('FUTURE_CHECKPOINT')
    anchoring='NOT_REQUIRED' if not policy.require_anchor else ('OK' if anchors else 'MISSING')
    if policy.quorum:
        if not seals or certificate is None or not verify_certificate(certificate,seals[-1],policy.witness_keys or {},policy.quorum):
            alarms.append('BAD_WITNESS_QUORUM')
    if v.status.startswith('REJECT_ANCHOR'):anchoring='MISMATCH'
    integrity='FAIL' if v.status in ('REJECT_CONTENT_INTEGRITY','REJECT_MALFORMED') else ('OK' if v.accepted() else 'UNKNOWN')
    continuity='FAIL' if v.status=='REJECT_CONTINUITY' else ('OK' if v.accepted() else 'UNKNOWN')
    status='ACCEPT' if v.accepted() and not alarms else (v.status if not v.accepted() else 'REJECT_POLICY')
    return PropertyReport(status,integrity,continuity,freshness,anchoring,'NOT_OBSERVED',tuple(dict.fromkeys(alarms)),v.verified_events,v.verified_periods)
