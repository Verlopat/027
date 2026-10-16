"""Native/reference differential vectors; skip explicitly if optional native unavailable."""
from __future__ import annotations
import random
import pytest
from pabla.v2.backends import ReferenceBackend, NativeBackend
from pabla.v2.crypto import N

def test_native_reference_ecdsa_300_reproducible_vectors():
    pytest.importorskip('coincurve')
    pytest.importorskip('Crypto.Hash.keccak')
    reference=ReferenceBackend();native=NativeBackend()
    rng=random.Random(20261016)
    for _ in range(300):
        key=rng.randrange(1,N);digest=rng.getrandbits(256).to_bytes(32,'big')
        expected=reference.sign_digest(key,digest)
        assert native.address(key)==reference.address(key)
        assert native.sign_digest(key,digest)==expected
        assert native.recover_address(digest,expected)==reference.recover_address(digest,expected)
        assert native.recover_address(digest,expected)==native.address(key)
        high_s=(N-int.from_bytes(expected[32:64],'big')).to_bytes(32,'big')
        modified=expected[:32]+high_s+expected[64:]
        assert native.recover_address(digest,modified) is None
        assert reference.recover_address(digest,modified) is None
