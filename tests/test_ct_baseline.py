import copy
from pabla.ct_baseline import (CTBaseline, leaf, root, inclusion_proof,
                               verify_inclusion, consistency_proof, verify_consistency)
from pabla.protocol import keypair
from pabla.workloads import generate_events


def test_inclusion_and_consistency_over_all_tree_sizes():
    hashes = [leaf(bytes([i])) for i in range(45)]
    for new_size in range(1,len(hashes)+1):
        sub=hashes[:new_size]
        for index in range(new_size):
            proof=inclusion_proof(sub,index)
            assert verify_inclusion(sub[index],index,new_size,proof,root(sub)),(new_size,index)
            assert not verify_inclusion(leaf(b'wrong'),index,new_size,proof,root(sub))
        for old_size in range(new_size+1):
            proof=consistency_proof(sub,old_size)
            assert verify_consistency(old_size,new_size,root(sub[:old_size]),root(sub),proof),(old_size,new_size)
            if old_size and old_size != new_size:
                assert not verify_consistency(old_size,new_size,root(sub[:old_size]),leaf(b'wrong'),proof)


def test_signed_checkpoint_and_fork():
    sk,pk=keypair()
    log=CTBaseline(sk)
    for event in generate_events(5,991):
        log.append(event)
    old=log.checkpoint()
    assert log.verify_checkpoint(old,pk)
    log.append(generate_events(1,992)[0])
    latest=log.checkpoint()
    assert log.verify_checkpoint(latest,pk)
    proof=consistency_proof(log.hashes,old['size'])
    assert verify_consistency(old['size'],latest['size'],bytes.fromhex(old['root']),bytes.fromhex(latest['root']),proof)
    forged=copy.deepcopy(latest)
    forged['root']='ff'*32
    assert not log.verify_checkpoint(forged,pk)
