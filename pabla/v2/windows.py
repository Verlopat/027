"""Independent event-wise compromise-window model (no verifier calls).

No result is accepted as experimental confirmation without an actual attack
and verifier execution in runner.py.
"""
from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class EventTimes:
    event_id:str
    arrival_ms:int
    seal_ms:int
    witness_ms:int|None
    anchor_ms:int|None

@dataclass(frozen=True)
class WindowCounts:
    modification:int
    silent_suppression:int
    unprovable_suppression:int

def predict(events:list[EventTimes],compromise_ms:int)->WindowCounts:
    if type(compromise_ms) is not int or compromise_ms<0:raise ValueError('bad compromise time')
    mod=silent=unprov=0
    for e in events:
        if e.arrival_ms>compromise_ms:continue
        if e.seal_ms>compromise_ms:mod+=1;silent+=1
        external=min([x for x in (e.witness_ms,e.anchor_ms) if x is not None],default=None)
        if external is None or external>compromise_ms:unprov+=1
    return WindowCounts(mod,silent,unprov)
