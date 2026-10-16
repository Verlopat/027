"""PABLA-v2 reference cryptography: raw SHA256 ABI digests and secp256k1.

Pure-Python ECC/Keccak is an interoperability REFERENCE, not a constant-time
production implementation. For deployment, use a hardened native library and
secure key storage. Signature nonces follow RFC 6979 and s is canonical low-s.
"""
from __future__ import annotations
import hashlib
import hmac
from dataclasses import dataclass, field

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
_MASK = (1 << 64)-1
_RC = [0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,
0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,
0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,
0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,
0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,
0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]
_ROT = [[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]

def keccak256(data: bytes) -> bytes:
    """Legacy Ethereum Keccak-256 (NOT NIST SHA3-256)."""
    lanes = [0]*25
    padded = bytearray(data) + b'\x01'
    while len(padded) % 136 != 135:
        padded.append(0)
    padded.append(0x80)
    for start in range(0,len(padded),136):
        chunk = padded[start:start+136]
        for i in range(17):
            lanes[i] ^= int.from_bytes(chunk[i*8:i*8+8], 'little')
        for rc in _RC:
            c = [lanes[x]^lanes[x+5]^lanes[x+10]^lanes[x+15]^lanes[x+20] for x in range(5)]
            d = [c[(x-1)%5]^((c[(x+1)%5]<<1 | c[(x+1)%5]>>63)&_MASK) for x in range(5)]
            for x in range(5):
                for y in range(5): lanes[x+5*y] ^= d[x]
            b = [0]*25
            for x in range(5):
                for y in range(5):
                    v = lanes[x+5*y]
                    r = _ROT[x][y]
                    b[y+5*((2*x+3*y)%5)] = ((v<<r)|(v>>(64-r)))&_MASK if r else v
            for x in range(5):
                for y in range(5): lanes[x+5*y]=b[x+5*y]^((~b[(x+1)%5+5*y])&b[(x+2)%5+5*y])
            lanes[0]^=rc
    return b''.join(v.to_bytes(8,'little') for v in lanes)[:32]

def sha(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def framed(label: str, *items: bytes) -> bytes:
    if not isinstance(label,str) or not label.isascii(): raise ValueError('domain label must be ASCII')
    b=label.encode('ascii')
    return sha(len(b).to_bytes(4,'big')+b+b''.join(len(x).to_bytes(8,'big')+x for x in items))

def word(value: int) -> bytes:
    if type(value) is not int or not 0<=value<2**64: raise ValueError('invalid uint64')
    return value.to_bytes(32,'big')

def b32(value: bytes) -> bytes:
    if not isinstance(value,bytes) or len(value)!=32: raise ValueError('expected bytes32')
    return value

def abi_address(value: bytes) -> bytes:
    if not isinstance(value,bytes) or len(value)!=20: raise ValueError('expected address20')
    return b'\x00'*12 + value

def _add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0]==b[0] and (a[1]+b[1])%P==0: return None
    if a==b:
        if a[1]==0: return None
        slope=(3*a[0]*a[0])*pow(2*a[1], -1, P)%P
    else: slope=(b[1]-a[1])*pow((b[0]-a[0])%P,-1,P)%P
    x=(slope*slope-a[0]-b[0])%P
    return x,(slope*(a[0]-x)-a[1])%P

def _mul(k:int, point=G):
    result=None
    while k:
        if k&1: result=_add(result, point)
        point=_add(point,point)
        k >>= 1
    return result

def address(secret:int) -> bytes:
    if type(secret) is not int or not 1<=secret<N: raise ValueError('invalid secp256k1 secret')
    p=_mul(secret)
    return keccak256(p[0].to_bytes(32,'big')+p[1].to_bytes(32,'big'))[-20:]

def _nonces(secret:int, digest:bytes):
    x=secret.to_bytes(32,'big'); h=(int.from_bytes(digest,'big')%N).to_bytes(32,'big')
    v=b'\x01'*32; k=b'\x00'*32
    k=hmac.new(k,v+b'\x00'+x+h,hashlib.sha256).digest(); v=hmac.new(k,v,hashlib.sha256).digest()
    k=hmac.new(k,v+b'\x01'+x+h,hashlib.sha256).digest(); v=hmac.new(k,v,hashlib.sha256).digest()
    while True:
        v=hmac.new(k,v,hashlib.sha256).digest(); candidate=int.from_bytes(v,'big')
        if 1<=candidate<N: yield candidate
        k=hmac.new(k,v+b'\x00',hashlib.sha256).digest(); v=hmac.new(k,v,hashlib.sha256).digest()

def sign_digest(secret:int, digest:bytes) -> bytes:
    b32(digest)
    if type(secret) is not int or not 1<=secret<N: raise ValueError('invalid secp key')
    z=int.from_bytes(digest,'big')
    for k in _nonces(secret,digest):
        pt=_mul(k)
        if pt[0]>=N: continue # Ethereum's v cannot encode the rare high-x branch
        r=pt[0]%N
        s=pow(k,-1,N)*(z+r*secret)%N
        if not r or not s: continue
        recovery=pt[1]&1
        if s>N//2: s=N-s; recovery ^= 1
        return r.to_bytes(32,'big')+s.to_bytes(32,'big')+bytes([27+recovery])
    raise RuntimeError('RFC6979 exhausted')

def recover_address(digest:bytes, signature:bytes) -> bytes | None:
    try:
        b32(digest)
        if not isinstance(signature,bytes) or len(signature)!=65 or signature[64] not in (27,28): return None
        r=int.from_bytes(signature[:32],'big'); s=int.from_bytes(signature[32:64],'big')
        if not 1<=r<N or not 1<=s<=N//2: return None
        x=r
        y2=(x*x*x+7)%P
        y=pow(y2,(P+1)//4,P)
        if y*y%P!=y2: return None
        if (y&1)!=(signature[64]-27):y=(-y)%P
        R=(x,y)
        u1=(-int.from_bytes(digest,'big')*pow(r,-1,N))%N
        u2=(s*pow(r,-1,N))%N
        Q=_add(_mul(u1),_mul(u2,R))
        if Q is None: return None
        return keccak256(Q[0].to_bytes(32,'big')+Q[1].to_bytes(32,'big'))[-20:]
    except (ValueError,ZeroDivisionError,TypeError): return None

def next_state(seed:bytes) -> bytes:
    return framed('PABLA-FSPRG-NEXT-v2',b32(seed))

def secret_for_state(seed:bytes) -> int:
    b32(seed)
    count=0
    while True:
        k=int.from_bytes(framed('PABLA-FSPRG-SK-v2',seed,count.to_bytes(4,'big')),'big')
        if 1<=k<N:return k
        count+=1

@dataclass
class FSState:
    _seed:bytearray=field(repr=False)
    period:int=1
    def __post_init__(self):
        if len(self._seed)!=32 or self.period<1: raise ValueError('invalid FS state')
    def secret(self)->int: return secret_for_state(bytes(self._seed))
    def advance(self)->None:
        future=next_state(bytes(self._seed))
        self._seed[:]=b'\x00'*len(self._seed)
        self._seed=bytearray(future)
        self.period+=1
    def snapshot_for_tests(self)->bytes:return bytes(self._seed)
