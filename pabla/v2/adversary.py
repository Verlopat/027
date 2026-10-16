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


def maximize(view:CompromiseView,objective:str='silent')->SearchResult:
    if objective not in ('silent','modify'):
        raise ValueError('supported objectives: silent, modify')
    best=None;attempts=strategies(view)
    for candidate in attempts:
        if candidate.name=='HONEST':continue
        verdict=verify_full(list(candidate.events),list(candidate.seals),view.schedule,
                            collector=view.collector,epoch=view.epoch,anchors=view.anchors)
        missing,changed=_difference(view.events,candidate.events)
        value=missing if objective=='silent' else changed
        if verdict.accepted() and value>0 and (best is None or value>best[1]):
            best=(candidate.name,value,missing,changed,verdict)
    if best is None:
        honest=verify_full(list(view.events),list(view.seals),view.schedule,
                           collector=view.collector,epoch=view.epoch,anchors=view.anchors)
        return SearchResult('NONE',0,0,honest,len(attempts)-1)
    return SearchResult(best[0],best[2],best[3],best[4],len(attempts)-1)
