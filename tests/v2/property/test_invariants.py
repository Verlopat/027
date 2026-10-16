from hypothesis import given, strategies as st, settings
from pabla.v2.crypto import sha,N,sign_digest,recover_address,address
from pabla.v2.tree import CompactRange,log_leaf,reference_root,perfect_root,perfect_proof,verify_perfect
from pabla.v2.scheduling import optimal_anchor_times,brute_optimum,valid_schedule,online_greedy,online_reservation
from pabla.v2.checkpoint import Checkpoint

@given(st.lists(st.binary(min_size=0,max_size=64),min_size=0,max_size=600))
def test_compact_tree_reference(items):
    tree=CompactRange();leaves=[]
    for ev in items:tree.append(ev);leaves.append(log_leaf(ev))
    assert tree.root()==reference_root(leaves)

@given(st.integers(min_value=1,max_value=7),st.integers(min_value=0,max_value=127))
def test_perfect_sibling_proof(height,index):
    n=1<<height;i=index%n
    leaves=[sha(j.to_bytes(4,'big')) for j in range(n)]
    root=perfect_root(leaves);proof=perfect_proof(leaves,i)
    assert verify_perfect(leaves[i],i,height,proof,root)
    assert not verify_perfect(sha(b'wrong'),i,height,proof,root)
    assert not verify_perfect(leaves[i],i,height,proof,sha(b'wrong'))
    assert not verify_perfect(leaves[i],i,height-1,proof,root)

@given(st.integers(min_value=1,max_value=2**64-1),st.integers(min_value=0,max_value=2**64-1))
def test_checkpoint_canonical_abi(period,wall):
    cp=Checkpoint(b'c'*32,1,period,0,sha(b''),b'\x00'*32,wall,b'r'*32)
    assert Checkpoint.from_dict(cp.to_dict())==cp
    assert cp.digest()==sha(cp.encode())
    changed=Checkpoint(cp.collector,cp.epoch,cp.period,cp.size,cp.root,cp.prev,cp.wall_ms^1,cp.schedule_root)
    assert changed.encode()!=cp.encode() and changed.digest()!=cp.digest()

@given(st.integers(min_value=1,max_value=N-1),st.binary(min_size=32,max_size=32))
def test_low_s_address_recovery(secret,digest):
    sig=sign_digest(secret,digest)
    assert sig[64] in (27,28)
    assert int.from_bytes(sig[32:64],'big')<=N//2
    assert recover_address(digest,sig)==address(secret)
    high=bytearray(sig);high[32:64]=(N-int.from_bytes(sig[32:64],'big')).to_bytes(32,'big')
    assert recover_address(digest,bytes(high)) is None

@given(st.lists(st.integers(min_value=1,max_value=100),min_size=1,max_size=13),st.integers(min_value=1,max_value=6))
def test_offline_vs_oracle(prices,deadline):
    val,times=optimal_anchor_times(prices,deadline)
    oracle=brute_optimum(prices,deadline)
    assert abs(val-oracle[0])<1e-8
    assert valid_schedule(times,len(prices),deadline)
    assert valid_schedule(online_greedy(prices,deadline),len(prices),deadline)
    assert valid_schedule(online_reservation(prices,deadline,1,100),len(prices),deadline)
