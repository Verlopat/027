"""Generated, labelled synthetic telemetry and isolated attack mutations."""
from __future__ import annotations
import copy
import random
from datetime import datetime, timedelta, timezone
from typing import Any
from .protocol import Batch, Policy, canonical, digest, manifest_hash, sign, utc_now, genesis, chain_hash, event_hash, leaf_hash, merkle_root


def generate_events(count: int, seed: int, collector: str = 'collector-001', epoch: int = 1,
                    *, timestamp: str | None = None) -> list[dict]:
    if not 1 <= count <= 1_000_000:
        raise ValueError('count must be in [1, 1_000_000]')
    rng = random.Random(seed)
    base = datetime.fromisoformat((timestamp or utc_now()).replace('Z', '+00:00'))
    result = []
    for i in range(count):
        label = rng.choice(('process_start','network_flow','auth_attempt','file_open','dns_query'))
        ev = {'event_id':digest('PABLA-TEST-EVENT-ID',collector,epoch,seed,i),
              'collector_id':collector,'collector_epoch':epoch,
              'source_host':f'host-{rng.randrange(1,129):03d}',
              'event_type':label, 'severity':rng.choice(('low','medium','high','critical')),
              'event_time_utc':(base+timedelta(milliseconds=(i//10+rng.randrange(0,3)))).isoformat(timespec='milliseconds').replace('+00:00','Z'),
              'collector_monotonic_ns':i+1,
              'payload':{'pid':rng.randrange(1,65536), 'process':rng.choice(('/bin/bash','/usr/bin/ssh','/usr/bin/python3')),
                         'uid':rng.randrange(1,10000), 'success':bool(rng.getrandbits(1))}}
        result.append(ev)
    return result


def attack_batch(batch: Batch, attack: str, *, seed: int = 0) -> Batch | None:
    """Changes archived evidence only; original evidence and chain are never mutated.

    AT5 is instead generated as a legitimate signed out-of-window timestamp trial.
    AT7 and AT9 operate at the collector/ledger level in experiments.
    """
    if attack == 'AT10':
        return None
    copied = copy.deepcopy(batch)
    if attack == 'AT1':
        copied.events[0]['payload']['pid'] += 1
    elif attack == 'AT2':
        copied.events.pop(len(copied.events)//2)
    elif attack == 'AT3':
        if len(copied.events) < 2:
            raise ValueError('AT3 requires multiple events')
        copied.events[0],copied.events[-1] = copied.events[-1],copied.events[0]
    elif attack == 'AT4':
        copied.events.insert(1,copy.deepcopy(copied.events[0]))
    elif attack == 'AT6':
        copied.signature = '00'*64
    elif attack == 'AT8':
        copied.manifest['merkle_root'] = 'ab'*32
        copied.manifest_digest = manifest_hash(copied.manifest)
    else:
        raise ValueError(f'attack {attack} must be created at collector/ledger level')
    return copied


def rebuild_untrusted(batch: Batch, policy: Policy) -> Batch:
    """Recompute all public fields after tampering, never forge a protected signature.

    Unlike a naive mutation, an unsigned attacker can rewrite range/count
    metadata. Changes after a batch boundary need history-level recomputation.
    """
    from .protocol import ProtocolError
    copy_batch=copy.deepcopy(batch)
    m=copy_batch.manifest
    if not copy_batch.events:
        raise ProtocolError('empty archive cannot be represented as a batch')
    m['event_count']=len(copy_batch.events)
    m['last_sequence']=m['first_sequence']+len(copy_batch.events)-1
    prev=m['first_previous_chain'] if policy.chain else '00'*32
    leaves=[]
    for i,ev in enumerate(copy_batch.events):
        seq=m['first_sequence']+i
        evhash=event_hash(m['collector_id'],m['epoch'],seq,ev)
        prev=chain_hash(m['collector_id'],m['epoch'],seq,prev,evhash) if policy.chain else '00'*32
        leaves.append(leaf_hash(seq,evhash,prev))
    m['merkle_root']=merkle_root(leaves)
    m['last_chain']=prev if policy.chain else '00'*32
    copy_batch.leaves=leaves
    copy_batch.manifest_digest=manifest_hash(m)
    return copy_batch


def adaptive_attack_batch(batch: Batch, attack: str, policy: Policy) -> Batch:
    """Adaptive archive attacker without the collector signing key.

    AT8 must be a REAL substitution, never an honest-batch no-op. Any attack
    that accidentally leaves the artifact unchanged causes the trial to fail.
    """
    modified=attack_batch(batch,attack)
    if modified is None:
        raise ValueError('archive deletion requires history-level attack')
    if attack=='AT8':
        # Substitute a genuinely different event set, then compute its root.
        # The public Merkle computation is possible without knowing the key;
        # the ORIGINAL signature is deliberately retained and thus invalid.
        modified.events[0]['payload']['pid'] += 17
    result=rebuild_untrusted(modified,policy)
    if canonical(result.export()) == canonical(batch.export()):
        raise AssertionError(f'adaptive attack {attack} produced an unchanged artifact')
    return result


def adaptive_reissue_history(batches: list[Batch], policy: Policy, attack: str) -> list[Batch]:
    """Re-issue complete unsigned histories after modification.

    This models the strongest no-key attacker for B3: hashes and apparent
    sequence numbers are fully rewritten. It cannot defeat signed checkpoints
    or immutable anchors and must not be used to claim it can.
    """
    if not batches:
        raise ValueError('need history')
    from .protocol import Collector, keypair
    source=[copy.deepcopy(b.events) for b in batches]
    if attack=='MIDDLE_BATCH_DELETE':
        if len(source)<3: raise ValueError('need three batches')
        source.pop(1)
    elif attack=='TAIL_TRUNCATION':
        if len(source)<2: raise ValueError('need two batches')
        source.pop()
    elif attack=='BATCH_REORDER':
        if len(source)<3: raise ValueError('need three batches')
        source[1],source[2]=source[2],source[1]
    elif attack=='CROSS_BATCH_SPLICE':
        if len(source)<3: raise ValueError('need three batches')
        source[1][-1],source[2][0]=source[2][0],source[1][-1]
        # A contiguous resubmission must respect each batch's monotonic order;
        # an adaptive untrusted attacker may reassign local monotonic counters.
    elif attack=='AT2':
        source[0].pop(len(source[0])//2)
    elif attack=='AT4':
        original=copy.deepcopy(source[0][0]);original['event_id']=digest('REISSUED-EVENT-ID', original['event_id'])
        source[0].insert(1,original)
    else:
        raise ValueError(f'unsupported adaptive history attack {attack}')
    sk,_=keypair()
    fake=Collector(batches[0].manifest['collector_id'],batches[0].manifest['epoch'],sk,policy)
    output=[]
    monotonic_counter=1
    for evs in source:
        for ev in evs:
            ev['collector_monotonic_ns']=monotonic_counter
            monotonic_counter+=1
        output.append(fake.collect(evs))
    return output
