"""Deterministic persistence-boundary fault injection (reference testing only)."""
from __future__ import annotations

class InjectedCrash(RuntimeError):pass

class FaultInjector:
    """Inject at a numbered before/after SQL execution or transaction commit boundary."""
    def __init__(self,crash_at:int|None=None):
        if crash_at is not None and crash_at<1:raise ValueError('invalid fault index')
        self.crash_at=crash_at;self.count=0;self.events=[]
    def hit(self,label:str)->None:
        self.count+=1;self.events.append(label)
        if self.count==self.crash_at:raise InjectedCrash(f'fault at boundary {self.count}: {label}')

class FaultyConnection:
    """Wrapper respects sqlite transaction context semantics on exceptions."""
    def __init__(self,db,injector:FaultInjector):self.db=db;self.injector=injector
    def execute(self,*args,**kwargs):
        self.injector.hit('before.execute')
        result=self.db.execute(*args,**kwargs)
        self.injector.hit('after.execute')
        return result
    def __enter__(self):
        self.injector.hit('before.transaction')
        self.db.__enter__()
        return self
    def __exit__(self,*args):
        result=self.db.__exit__(*args)
        self.injector.hit('after.transaction')
        return result
    def close(self):return self.db.close()
    def __getattr__(self,name):return getattr(self.db,name)
