"""Exact discrete offline anchoring optimum and deadline-safe online policies."""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass
from math import sqrt

def optimal_anchor_times(prices:list[float],deadline:int)->tuple[float,list[int]]:
    """Minimize sum of prices, requiring every D consecutive slots has an anchor.

    Equivalent: first anchor within [0,D), each gap <= D, last within D
    slots of the horizon. Monotone deque yields O(T) time and space.
    """
    n=len(prices)
    if n==0:return 0.0,[]
    if type(deadline) is not int or deadline<1 or any(not isinstance(p,(int,float)) or p<=0 or p!=p or p==float('inf') for p in prices):
        raise ValueError('deadline>=1 and prices finite positive')
    dp=[0.0]*n;pre=[-1]*n
    q=deque()
    for t,p in enumerate(prices):
        while q and q[0]<t-deadline:q.popleft()
        if t<deadline and (not q or 0<=dp[q[0]]):
            best=0.0;parent=-1
        elif q:
            parent=q[0];best=dp[parent]
        else:raise ValueError('unsatisfiable deadline')
        dp[t]=float(p)+best;pre[t]=parent
        while q and dp[q[-1]]>=dp[t]:q.pop()
        q.append(t)
    end=min(range(max(0,n-deadline),n),key=lambda i:dp[i]);times=[]
    while end!=-1:
        times.append(end);end=pre[end]
    return dp[times[0]],times[::-1]

def valid_schedule(times:list[int],n:int,D:int)->bool:
    return (n==0 and not times) or (n>0 and bool(times) and times==sorted(set(times)) and
            all(0<=t<n for t in times) and times[0]<D and n-1-times[-1]<D and
            all(b-a<=D for a,b in zip(times,times[1:])))

def brute_optimum(prices:list[float],D:int):
    """Independent exponential oracle, only small fixtures (n <= 20)."""
    n=len(prices)
    if n>20:raise ValueError('brute force limited to 20 time slots')
    if n==0:return 0.0,[]
    if D<1:raise ValueError('invalid D')
    best=None
    for bits in range(1,1<<n):
        selected=[i for i in range(n) if bits>>i&1]
        if valid_schedule(selected,n,D):
            price=sum(prices[i] for i in selected)
            if best is None or price<best[0]-1e-12:best=(price,selected)
    return best

def online_greedy(prices:list[float],D:int)->list[int]:
    if not prices:return []
    if D<1:raise ValueError('bad deadline')
    times=[];last=-1
    for i in range(len(prices)):
        if i-last>=D:times.append(i);last=i
    if not times: times.append(len(prices)-1)
    return times

def online_reservation(prices:list[float],D:int,min_price:float,max_price:float)->list[int]:
    if not 0<min_price<=max_price or D<1:raise ValueError('bad parameters')
    threshold=sqrt(min_price*max_price)
    times=[];last=-1
    for i,price in enumerate(prices):
        if price<=threshold or i-last>=D:
            times.append(i);last=i
    if prices and not times: times.append(len(prices)-1)
    return times
