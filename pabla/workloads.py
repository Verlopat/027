"""Generated, labelled synthetic telemetry and isolated attack mutations."""
from __future__ import annotations
import copy
import random
from datetime import datetime, timedelta, timezone
from typing import Any
from .protocol import Batch, canonical, digest, manifest_hash, sign, utc_now


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
              'event_time_utc':base.isoformat(timespec='milliseconds').replace('+00:00','Z'),
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
