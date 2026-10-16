"""Cryptographic provider abstraction. Reference ECC is not constant time."""
from __future__ import annotations
from typing import Protocol
import os
from . import crypto

class SignerBackend(Protocol):
    name: str
    def address(self, secret: int) -> bytes: ...
    def sign_digest(self, secret: int, digest: bytes) -> bytes: ...
    def recover_address(self, digest: bytes, signature: bytes) -> bytes | None: ...
    def keccak256(self, data: bytes) -> bytes: ...

class ReferenceBackend:
    name = 'reference-python'
    def address(self, secret: int) -> bytes: return crypto.address(secret)
    def sign_digest(self, secret: int, digest: bytes) -> bytes: return crypto.sign_digest(secret,digest)
    def recover_address(self, digest: bytes, signature: bytes) -> bytes | None: return crypto.recover_address(digest, signature)
    def keccak256(self, data: bytes) -> bytes: return crypto.keccak256(data)

class NativeBackend:
    name = 'libsecp256k1-coincurve'
    def __init__(self):
        from coincurve import PrivateKey, PublicKey  # noqa: F401
        from Crypto.Hash import keccak  # noqa: F401
    def address(self, secret: int) -> bytes:
        from coincurve import PrivateKey
        from Crypto.Hash import keccak
        if type(secret) is not int or not 1 <= secret < crypto.N:
            raise ValueError('bad private key')
        pub=PrivateKey(secret.to_bytes(32,'big')).public_key.format(compressed=False)[1:]
        k=keccak.new(digest_bits=256);k.update(pub)
        return k.digest()[-20:]
    def sign_digest(self, secret: int, digest: bytes) -> bytes:
        from coincurve import PrivateKey
        crypto.b32(digest)
        if type(secret) is not int or not 1 <= secret < crypto.N: raise ValueError('bad key')
        sig=PrivateKey(secret.to_bytes(32,'big')).sign_recoverable(digest,hasher=None)
        r=int.from_bytes(sig[:32],'big');s=int.from_bytes(sig[32:64],'big')
        parity=sig[64]&1
        if s>crypto.N//2:s=crypto.N-s;parity^=1
        if not 1<=r<crypto.N:return crypto.sign_digest(secret,digest)
        return r.to_bytes(32,'big')+s.to_bytes(32,'big')+bytes([27+parity])
    def recover_address(self, digest: bytes, signature: bytes) -> bytes | None:
        try:
            from coincurve import PublicKey
            from Crypto.Hash import keccak
            crypto.b32(digest)
            if not isinstance(signature,bytes) or len(signature)!=65 or signature[64] not in (27,28):return None
            r=int.from_bytes(signature[:32],'big');s=int.from_bytes(signature[32:64],'big')
            if not 1<=r<crypto.N or not 1<=s<=crypto.N//2:return None
            rec=signature[:64]+bytes([signature[64]-27])
            pub=PublicKey.from_signature_and_message(rec,digest,hasher=None).format(compressed=False)[1:]
            k=keccak.new(digest_bits=256);k.update(pub)
            return k.digest()[-20:]
        except (ValueError,TypeError):return None
    def keccak256(self, data: bytes) -> bytes:
        from Crypto.Hash import keccak
        k=keccak.new(digest_bits=256);k.update(data);return k.digest()

def selected_backend() -> SignerBackend:
    mode=os.getenv('PABLA_CRYPTO_BACKEND','auto').lower()
    if mode not in ('auto','reference','native'):raise ValueError('PABLA_CRYPTO_BACKEND must be auto,reference,native')
    if mode=='reference':return ReferenceBackend()
    try:return NativeBackend()
    except ImportError:
        if mode=='native':raise RuntimeError('Native crypto requested but coincurve/pycryptodome not installed') from None
        return ReferenceBackend()
