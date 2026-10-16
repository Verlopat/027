"""Comparable baseline adapter result contract.

A baseline that has not run must return not_run with a reason rather than a
pretend result; security verdicts must originate in the baseline's verifier.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol,Iterable

@dataclass(frozen=True)
class BaselineResult:
    status:str
    method:str
    evidence_path:str|None=None
    reason:str|None=None
    verified_events:int|None=None

class BaselineAdapter(Protocol):
    name:str
    def ingest(self,events:Iterable[bytes])->BaselineResult: ...
    def verify(self)->BaselineResult: ...
    def compromise(self,at_ms:int)->BaselineResult: ...
    def cost(self)->dict: ...

class MissingBaseline:
    """Explicitly unavailable real integration; NOT a stand-in algorithm."""
    def __init__(self,name:str,reason:str):self.name=name;self.reason=reason
    def ingest(self,events):return BaselineResult('not_run',self.name,reason=self.reason)
    def verify(self):return BaselineResult('not_run',self.name,reason=self.reason)
    def compromise(self,at_ms):return BaselineResult('not_run',self.name,reason=self.reason)
    def cost(self):return {'status':'not_run','reason':self.reason,'gas':None}
