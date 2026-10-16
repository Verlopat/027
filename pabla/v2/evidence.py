"""Public evidence of two different valid signatures for one period."""
from __future__ import annotations
from dataclasses import dataclass
from .checkpoint import Sealed
from .crypto import recover_address
from .schedule import PublicSchedule

@dataclass(frozen=True)
class EquivocationProof:
    first:Sealed
    second:Sealed
    def valid(self, schedule:PublicSchedule)->bool:
        a,b=self.first.checkpoint,self.second.checkpoint
        if a.collector!=b.collector or a.epoch!=b.epoch or a.period!=b.period or a.digest()==b.digest():return False
        if a.schedule_root!=schedule.root or b.schedule_root!=schedule.root:return False
        try:
            who=schedule.public_for(a.period)
            return (schedule.verify(a.period,who,list(self.first.key_proof)) and
                    schedule.verify(b.period,who,list(self.second.key_proof)) and
                    recover_address(a.digest(),self.first.signature)==who and
                    recover_address(b.digest(),self.second.signature)==who)
        except (ValueError,TypeError,AttributeError,OverflowError):
            return False

def find_equivocation(first:list[Sealed],second:list[Sealed])->EquivocationProof|None:
    rhs={(s.checkpoint.collector,s.checkpoint.epoch,s.checkpoint.period):s for s in second}
    for a in first:
        cp=a.checkpoint
        b=rhs.get((cp.collector,cp.epoch,cp.period))
        if b is not None and cp.digest()!=b.checkpoint.digest():return EquivocationProof(a,b)
    return None
