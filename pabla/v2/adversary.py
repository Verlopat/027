"""Bounded attack search with the REAL trusted-policy verifier as oracle.

This search is not a completeness proof or an optimal adversary. The maximum
reported is over enumerated strategies only, never a formal maximum.
"""
from __future__ import annotations
from collections import Counter
from dataclasses import dataclass
from .checkpoint import Sealed
from .schedule import PublicSchedule
from .crypto import sha
from .attacks import adaptive_drop
from .verifier import verify_full,Verdict

@dataclass(frozen=True)
class CompromiseView:
    events:tuple[bytes,...]
    seals:tuple[Sealed,...]
    schedule:PublicSchedule
    collector:bytes
    epoch:int
    stolen_seed:bytes
    anchors:dict[int,bytes]
    # Trusted wall-clock policy, not taken from the attacker-supplied checkpoints.
    now_ms:int|None=None
    seal_interval_ms:int|None=None
    clock_slack_ms:int=0

@dataclass(frozen=True)
class Candidate:
    name:str
    events:tuple[bytes,...]
    seals:tuple[Sealed,...]

@dataclass(frozen=True)
class SearchResult:
    strategy:str
    removed_events:int
    modified_events:int
    verdict:Verdict
    tested_candidates:int


def _difference(original:tuple[bytes,...],candidate:tuple[bytes,...])->tuple[int,int]:
    a=Counter(original);b=Counter(candidate)
    removed=sum((a-b).values());added=sum((b-a).values())
    return removed, min(removed,added)


def strategies(view:CompromiseView)->list[Candidate]:
    """Public, deterministic attack catalogue; no expected verdicts embedded."""
    events=view.events;seals=view.seals
    rows=[Candidate('HONEST',events,seals)]
    if not seals:return rows
    rows.append(Candidate('TRUNCATE_TAIL',events,seals[:-1]))
    # Suppress each possible sealed suffix together with the events committed
    # exclusively by that suffix. Unlike TRUNCATE_TAIL, these archives can
    # pass signature/root verification if freshness and external commitments
    # are not enforced. Retain genesis; removing it yields an empty history.
    for retained in range(1,len(seals)):
        prefix_end=seals[retained-1].checkpoint.size
        rows.append(Candidate('DROP_LAST_SEALED_PERIOD',
                              events[:prefix_end],seals[:retained]))
    # A key thief may emit a *later* heartbeat after removing a sealed period.
    # This is not an ordinary contiguous continuation: the verifier must catch
    # the missing period even if the thief possesses the later period's key.
    if len(seals)>1:
        from .tree import CompactRange
        from .checkpoint import Checkpoint
        from .crypto import sign_digest,secret_for_state
        prefix_end=seals[-2].checkpoint.size
        retained=seals[:-1]
        next_period=seals[-1].checkpoint.period+1
        if next_period<view.schedule.first+len(view.schedule.addresses):
            tree=CompactRange()
            for e in events[:prefix_end]:tree.append(e)
            last=seals[-1].checkpoint
            heartbeat=Checkpoint(last.collector,last.epoch,next_period,
                                 prefix_end,tree.root(),retained[-1].checkpoint.digest(),
                                 max(last.wall_ms,view.now_ms or last.wall_ms),last.schedule_root)
            fabricated=Sealed(heartbeat,sign_digest(secret_for_state(view.stolen_seed),
                                                    heartbeat.digest()),
                              tuple(view.schedule.proof(next_period)))
            rows.append(Candidate('DROP_PERIOD_THEN_HEARTBEAT',events[:prefix_end],
                                  retained+(fabricated,)))
    rows.append(Candidate('DELETE_LAST_EVENT',events[:-1],seals))
    rows.append(Candidate('DELETE_ALL_EVENTS',(),seals))
    rows.append(Candidate('REPLAY_LAST_SEAL',events,seals+(seals[-1],)))
    if len(events)>1:
        modified=list(events);modified[-1],modified[-2]=modified[-2],modified[-1]
        rows.append(Candidate('REORDER_LAST_TWO',tuple(modified),seals))
    # Only the last period is candidate-reissuable, and the supplied stolen
    # seed is the actual available key, not automatically a past-period key.
    last=seals[-1]
    start=seals[-2].checkpoint.size if len(seals)>1 else 0
    last_events=list(events[start:last.checkpoint.size])
    if last_events:
        prefix=list(events[:start])
        # Preserve period-range semantics by using an independently constructed
        # complete archive, not only the suffix root.
        from .tree import CompactRange
        from .checkpoint import Checkpoint
        from .crypto import sign_digest,secret_for_state
        for action,modified in [('DROP_LAST_REISSUED',list(events[:-1])),
                                ('ALTER_LAST_REISSUED',list(events[:-1])+[b'ADAPTIVE-ATTACK'])]:
            tree=CompactRange()
            for e in modified:tree.append(e)
            cp=last.checkpoint
            forged=Checkpoint(cp.collector,cp.epoch,cp.period,len(modified),tree.root(),cp.prev,cp.wall_ms,cp.schedule_root)
            fake=Sealed(forged,sign_digest(secret_for_state(view.stolen_seed),forged.digest()),last.key_proof)
            rows.append(Candidate(action,tuple(modified),seals[:-1]+(fake,)))
    return rows


def maximize(view:CompromiseView,objective:str='silent',*,allow_no_freshness:bool=False)->SearchResult:
    if objective not in ('silent','modify'):
        raise ValueError('supported objectives: silent, modify')
    # A freshness-free verifier cannot support a silent-suppression bound.
    # Only an explicitly requested ablation may omit the trusted time policy.
    if not allow_no_freshness and (view.now_ms is None or view.seal_interval_ms is None):
        raise ValueError('trusted now_ms and seal_interval_ms required; use allow_no_freshness=True only for ablation')
    time_kwargs={} if allow_no_freshness else {
        'now_ms':view.now_ms,'seal_interval_ms':view.seal_interval_ms,
        'clock_slack_ms':view.clock_slack_ms}
    best=None;attempts=strategies(view)
    for candidate in attempts:
        if candidate.name=='HONEST':continue
        verdict=verify_full(list(candidate.events),list(candidate.seals),view.schedule,
                            collector=view.collector,epoch=view.epoch,anchors=view.anchors,**time_kwargs)
        missing,changed=_difference(view.events,candidate.events)
        value=missing if objective=='silent' else changed
        if verdict.accepted() and value>0 and (best is None or value>best[1]):
            best=(candidate.name,value,missing,changed,verdict)
    if best is None:
        honest=verify_full(list(view.events),list(view.seals),view.schedule,
                           collector=view.collector,epoch=view.epoch,anchors=view.anchors,**time_kwargs)
        return SearchResult('NONE',0,0,honest,len(attempts)-1)
    return SearchResult(best[0],best[2],best[3],best[4],len(attempts)-1)
