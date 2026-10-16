"""Online deadline/size-based anchoring and exposure calculations.

Time units are integer milliseconds from trace start. The adaptive policy
flushes at an event-count threshold, max dwell, or W_max, whichever is first.
It minimizes the number of fixed-cost anchors among contiguous windows under
these constraints, but is not a globally gas-optimal EVM strategy.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Sequence

@dataclass(frozen=True)
class Window:
    first_index: int
    last_index: int
    first_arrival_ms: int
    confirmed_ms: int
    @property
    def count(self) -> int: return self.last_index-self.first_index+1
    @property
    def max_wait_ms(self) -> int: return self.confirmed_ms-self.first_arrival_ms


def windows(arrivals: Sequence[int], *, batch_size: int, max_dwell_ms: int,
            max_exposure_ms: int, mode: str = 'adaptive', fixed_interval_ms: int | None = None) -> list[Window]:
    if not arrivals: return []
    if batch_size < 1 or max_dwell_ms <= 0 or max_exposure_ms <= 0:
        raise ValueError('invalid anchoring limits')
    if mode not in ('adaptive','fixed'):
        raise ValueError('invalid mode')
    if mode == 'fixed' and (fixed_interval_ms is None or fixed_interval_ms <= 0):
        raise ValueError('fixed interval required')
    if any(int(t) != t or t < 0 for t in arrivals) or any(b<a for a,b in zip(arrivals,arrivals[1:])):
        raise ValueError('arrivals must be nonnegative sorted milliseconds')
    result=[]
    begin=0
    while begin < len(arrivals):
        first=int(arrivals[begin])
        deadline = (min(first+max_dwell_ms,first+max_exposure_ms)
                    if mode=='adaptive' else (first//fixed_interval_ms+1)*fixed_interval_ms)
        end=begin
        while end+1<len(arrivals) and arrivals[end+1]<deadline and end-begin+1<batch_size:
            end+=1
        close=int(arrivals[end]) if end-begin+1>=batch_size else deadline
        result.append(Window(begin,end,first,close))
        begin=end+1
    return result


def exposed_events(arrivals: Sequence[int], anchored: Sequence[Window], compromise_ms: int) -> int:
    """Count arrivals since the last confirmed anchor strictly before theft."""
    last_confirmed=max((w.confirmed_ms for w in anchored if w.confirmed_ms < compromise_ms),default=-1)
    return sum(last_confirmed < t <= compromise_ms for t in arrivals)


def exposed_interval_ms(anchored: Sequence[Window], compromise_ms: int) -> int:
    last_confirmed=max((w.confirmed_ms for w in anchored if w.confirmed_ms < compromise_ms),default=0)
    return compromise_ms-last_confirmed
