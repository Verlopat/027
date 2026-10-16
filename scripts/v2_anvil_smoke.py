#!/usr/bin/env python3
"""Real EVM signed-checkpoint/period/fraud-proof integration smoke test.

This requires running Anvil and Foundry-compiled AnchorLogV2. It does not
simulate receipts or substitute a memory ledger. Gas values come from EVM.
"""
from __future__ import annotations
import json,os,tempfile
from pathlib import Path
from pabla.v2.evm import EvmV2Ledger
from pabla.v2.schedule import Schedule
from pabla.v2.checkpoint import Checkpoint,Sealed
from pabla.v2.collector import Collector
from pabla.v2.crypto import sha,secret_for_state,sign_digest


def run():
    ledger=EvmV2Ledger(rpc=os.getenv('PABLA_RPC','http://127.0.0.1:8545'))
    receipts={'deploy':ledger.deploy()}
    collector_id=sha(b'v2-anvil-integration')
    seed=sha(b'v2-anvil-disposable-test-seed')
    schedule=Schedule.setup(seed,3)
    receipts['register']=ledger.register(collector_id,1,schedule.public)
    with tempfile.TemporaryDirectory() as folder:
        c=Collector(Path(folder)/'collector.sqlite',collector_id,1,schedule.public,seed)
        stolen_seed=c._signer.snapshot_for_tests()
        c.append({'event':'known-valid','n':1})
        first=c.seal(100)
        receipts['anchor_1']=ledger.anchor(first)
        c.append({'event':'another-valid','n':2})
        second=c.seal(200)
        receipts['anchor_2']=ledger.anchor(second)
        latest=ledger.latest(collector_id,1)
        assert latest['period']==2 and latest['digest']==second.checkpoint.digest().hex()
        original=first.checkpoint
        fork=Checkpoint(original.collector,original.epoch,original.period,original.size,
             sha(b'competing-root'),original.prev,original.wall_ms,original.schedule_root)
        competing=Sealed(fork,sign_digest(secret_for_state(stolen_seed),fork.digest()),first.key_proof)
        receipts['equivocation']=ledger.prove_equivocation(first,competing)
        assert ledger.revoked_at(collector_id,1)>0
        c.close()
    assert all(r['gas_used']>0 for r in receipts.values())
    result={'backend':ledger.backend,'chain_id':receipts['deploy']['chain_id'],
            'contract':receipts['deploy']['contract_address'],
            'gas_receipts':receipts,'revocation_block':ledger.revoked_at(collector_id,1)}
    output=Path(os.getenv('PABLA_V2_EVM_OUTPUT','output/v2-anvil-smoke.json'))
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,sort_keys=True,indent=2))
    print(json.dumps({'status':'ok','backend':ledger.backend,'gas':{k:v['gas_used'] for k,v in receipts.items()}},indent=2))
if __name__=='__main__':run()
