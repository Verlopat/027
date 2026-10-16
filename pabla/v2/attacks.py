"""Attack probes run against the real verifier, not expected-result booleans."""
from __future__ import annotations
import json
from .crypto import secret_for_state, sign_digest, next_state
from .checkpoint import Checkpoint,Sealed
from .tree import CompactRange
from .verifier import verify_full
from .schedule import Schedule


def adaptive_drop(sealed:Sealed,events:list[bytes],stolen_seed:bytes,drop_indices:set[int])->tuple[list[bytes],Sealed]:
    """Recompute entire prefix root, counters and signature with available seed.

    The attacker does not get earlier keys. Supply the actual stolen key state;
    if it is from a different period, the verifier rejects the new signature.
    """
    cp=sealed.checkpoint
    kept=[e for i,e in enumerate(events) if i not in drop_indices]
    tree=CompactRange()
    for e in kept:tree.append(e)
    edited=Checkpoint(cp.collector,cp.epoch,cp.period,len(kept),tree.root(),cp.prev,cp.wall_ms,cp.schedule_root)
    return kept,Sealed(edited,sign_digest(secret_for_state(stolen_seed),edited.digest()),sealed.key_proof)


def sampled_window_probe(schedule:Schedule,events:list[bytes],arrival_ms:list[int],seal_ms:int,
                         witness_ms:int|None,anchor_ms:int|None,compromise_times:list[int])->list[dict]:
    """One-seal controlled attack experiment with an independent verifier.

    Model is in windows.py and never imported here. Signature erasure and the
    witness/anchor custody are separately determined from measured artifacts.
    """
    if len(events)!=len(arrival_ms) or not events or sorted(arrival_ms)!=arrival_ms:raise ValueError('bad trace')
    cp_tree=CompactRange()
    for e in events:cp_tree.append(e)
    cp=Checkpoint(b'\x65'*32,1,schedule.public.first,len(events),cp_tree.root(),b'\x00'*32,seal_ms,schedule.public.root)
    base=Sealed(cp,sign_digest(secret_for_state(schedule.state.snapshot_for_tests()),cp.digest()),tuple(schedule.public.proof(cp.period)))
    current_seed=schedule.state.snapshot_for_tests()
    future_seed=next_state(current_seed)
    outputs=[]
    for t in compromise_times:
        arrived={i for i,a in enumerate(arrival_ms) if a<=t}
        if not arrived:
            outputs.append({'time_ms':t,'modification_measured':0,'silent_measured':0,'unprovable_measured':0,
                            'verifier_status':'NO_ARRIVED_EVENTS'});continue
        seed=current_seed if t<seal_ms else future_seed
        kept,forged=adaptive_drop(base,events,seed,arrived)
        anchors={cp.period:cp.digest()} if anchor_ms is not None and anchor_ms<=t else {}
        verdict=verify_full(kept,[forged],schedule.public,collector=cp.collector,epoch=1,anchors=anchors)
        # The verifier is the attack success oracle, not the window formula.
        accepted=verdict.accepted()
        # Honest independent witness/ledger custody is the source of a public
        # existence proof. No third party has it until its receipt/delivery.
        external_held=((witness_ms is not None and witness_ms<=t) or
                       (anchor_ms is not None and anchor_ms<=t))
        outputs.append({'time_ms':t,'modification_measured':len(arrived) if accepted else 0,
                        'silent_measured':len(arrived) if accepted else 0,
                        'unprovable_measured':0 if external_held else len(arrived),
                        'verifier_status':verdict.status,'arrived':len(arrived),
                        'external_custody':external_held})
    return outputs
