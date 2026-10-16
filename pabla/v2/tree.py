"""RFC 6962 append-only tree plus a separate perfect tree for FS schedules."""
from __future__ import annotations
from .crypto import sha
from ..ct_baseline import (leaf as log_leaf, node as log_node, root as reference_root,
    inclusion_proof, verify_inclusion, consistency_proof, verify_consistency)

def perfect_root(hashes:list[bytes])->bytes:
    if not hashes or len(hashes)&(len(hashes)-1):raise ValueError('schedule must have 2^h leaves')
    if any(len(h)!=32 for h in hashes):raise ValueError('invalid leaf')
    layer=list(hashes)
    while len(layer)>1:
        layer=[sha(b'\x01'+layer[i]+layer[i+1]) for i in range(0,len(layer),2)]
    return layer[0]

def perfect_proof(hashes:list[bytes], index:int)->list[bytes]:
    if not hashes or len(hashes)&(len(hashes)-1) or not 0<=index<len(hashes): raise ValueError('bad schedule index')
    layer=list(hashes); path=[]
    while len(layer)>1:
        path.append(layer[index^1])
        layer=[sha(b'\x01'+layer[i]+layer[i+1]) for i in range(0,len(layer),2)]
        index>>=1
    return path

def verify_perfect(leaf:bytes,index:int,height:int,proof:list[bytes],expected:bytes)->bool:
    if len(leaf)!=32 or len(expected)!=32 or index<0 or index>=1<<height or len(proof)!=height:return False
    v=leaf
    for other in proof:
        if len(other)!=32:return False
        v=sha(b'\x01'+(other+v if index&1 else v+other))
        index>>=1
    return v==expected

class CompactRange:
    """O(log n) memory and amortized O(1) hashes for append."""
    def __init__(self):
        self.size=0
        self._peaks:dict[int,bytes]={}
    def append(self, payload:bytes)->None:
        item=log_leaf(payload); level=0; n=self.size
        while n&1:
            item=log_node(self._peaks.pop(level),item)
            n>>=1;level+=1
        self._peaks[level]=item
        self.size+=1
    def root(self)->bytes:
        if not self._peaks:return sha(b'')
        result=None
        for height in sorted(self._peaks):
            result=self._peaks[height] if result is None else log_node(self._peaks[height],result)
        return result
