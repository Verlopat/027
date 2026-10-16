"""Exact offline and online policies on an externally measured price trace."""
from __future__ import annotations
import csv,hashlib,json,statistics
from pathlib import Path
from pabla.v2.scheduling import optimal_anchor_times,online_greedy,online_reservation,valid_schedule

def read_price_trace(path:str|Path)->tuple[list[float],str]:
    raw=Path(path).read_bytes();digest=hashlib.sha256(raw).hexdigest()
    rows=list(csv.DictReader(raw.decode('utf8').splitlines()))
    if not rows:raise ValueError('gas trace is empty')
    if not {'price','source'} <= set(rows[0]):raise ValueError('price and source fields are required')
    values=[]
    for row in rows:
        if row['source'].strip() in ('synthetic','model',''):
            raise ValueError('price trace must identify a real external source')
        value=float(row['price'])
        if not 0<value<float('inf'):raise ValueError('invalid real gas price')
        values.append(value)
    return values,digest

def compare(prices:list[float],deadline:int,window:int|None=None)->list[dict]:
    """Return measured-input scheduling costs without stochastic inference."""
    opt,opt_times=optimal_anchor_times(prices,deadline)
    fixed=online_greedy(prices,deadline)
    reservation=online_reservation(prices,deadline,min(prices),max(prices))
    rows=[]
    for name,times in [('offline_optimal',opt_times),('online_greedy',fixed),('online_reservation',reservation)]:
        assert valid_schedule(times,len(prices),deadline)
        cost=sum(prices[i] for i in times)
        rows.append({'policy':name,'deadline':deadline,'anchors':len(times),'cost_price_units':cost,
                     'ratio_to_optimum':cost/opt,'times':times})
    return rows
