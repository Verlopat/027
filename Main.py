#!/usr/bin/env python3
"""Unified PABLA execution: smoke example, E1-E7 trials, analysis, figures.

Default automatic mode uses *only* the clearly labeled local test double when
Anvil deployment is unavailable. --require-chain never silently falls back.
"""
from __future__ import annotations
import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

from pabla.experiments import Options, run_all, ledger_for
from pabla.protocol import Collector, Policy, keypair, merkle_proof, verify_batch, verify_proof, event_hash, chain_hash, leaf_hash, genesis
from pabla.storage import RunIndex, new_run, save_batch, write_json
from pabla.workloads import generate_events
from pabla.analysis import aggregate, figures


def main() -> int:
    parser=argparse.ArgumentParser(description='PABLA research workflow')
    parser.add_argument('--output',default='output')
    parser.add_argument('--backend',choices=['memory','anvil','auto'],default='auto')
    parser.add_argument('--profile',choices=['pilot','full'],default='pilot')
    parser.add_argument('--trials',type=int,default=None)
    parser.add_argument('--events',type=int,default=None)
    parser.add_argument('--batch-size',type=int,default=12)
    parser.add_argument('--seed',type=int,default=739391)
    parser.add_argument('--rpc',default=os.getenv('PABLA_RPC','http://127.0.0.1:8545'))
    parser.add_argument('--address',default=os.getenv('PABLA_CONTRACT',''))
    parser.add_argument('--require-chain',action='store_true')
    args=parser.parse_args()
    if args.profile=='full':
        trials=args.trials or 30
        count=args.events or 10000
    else:
        trials=args.trials or 2
        count=args.events or 24
    if trials<1 or not 2<=count<=1000000 or not 2<=args.batch_size<=10000:
        parser.error('trials>=1, events in [2,1000000], batch size in [2,10000]')
    backend=args.backend
    if backend=='auto':
        backend='anvil' if args.address and Path('contracts/out/CollectorAnchorRegistry.sol/CollectorAnchorRegistry.json').exists() else 'memory'
    if args.require_chain and backend!='anvil':
        parser.error('live contract required: compile/deploy and configure PABLA_CONTRACT')
    options=Options(profile=args.profile,seed=args.seed,trials=trials,event_count=count,
                    batch_size=args.batch_size,backend=backend,rpc=args.rpc,contract_address=args.address)
    # Validate actual chain before allocating output/testN.
    check=ledger_for(options)
    run=new_run(args.output)
    log=logging.getLogger('pabla')
    log.setLevel(logging.INFO)
    log.addHandler(logging.FileHandler(run/'logs'/'run.log'))
    log.addHandler(logging.StreamHandler(sys.stdout))
    log.info('run=%s backend=%s profile=%s trials=%s',run,check.backend,args.profile,trials)
    if backend=='memory':
        log.warning('IN-MEMORY TEST DOUBLE: no Ethereum deployment or on-chain gas/finality measurements')
    start=time.perf_counter_ns()
    try:
        index=RunIndex(run)
        sk,pk=keypair()
        collector=Collector(f'collector-demo-{run.name}',1,sk,Policy.for_name('P1'))
        check.register(collector.collector_id,1,pk)
        n=min(count,args.batch_size)
        batch=collector.collect(generate_events(n,args.seed,collector.collector_id))
        receipt=check.anchor(batch)
        verdict=verify_batch(batch,check,policy=collector.policy)
        if verdict.status!='ACCEPT':
            raise AssertionError(f'valid example rejected: {verdict}')
        path=save_batch(run,batch,receipt)
        index.add_batch(batch,path,check.backend)
        proof=merkle_proof(batch.leaves,n//2)
        if not verify_proof(batch.leaves[n//2],proof,n//2,n,batch.manifest['merkle_root']):
            raise AssertionError('inclusion proof mismatch')
        write_json(run/'artifacts'/'inclusion_proof.json',{'leaf':batch.leaves[n//2],
                   'leaf_index':n//2,'leaf_count':n,'siblings':proof,'root':batch.manifest['merkle_root']})
        index.close()
        experiments=run_all(run,options)
        summary=aggregate(experiments,run)
        plots=figures(run,summary)
        report={'status':'completed', 'backend':check.backend, 'profile':args.profile,
                'test_events':count, 'trials':trials, 'experiment_rows':{x:len(y) for x,y in experiments.items()},
                'artifacts':str(path),'figures':plots,'elapsed_s':(time.perf_counter_ns()-start)/1e9}
        write_json(run/'report.json',report)
        log.info('Report: %s',run/'report.json')
        return 0
    except Exception as exc:
        write_json(run/'failure.json',{'type':type(exc).__name__,'error':str(exc)})
        log.exception('Experiment failed')
        return 1

if __name__=='__main__':
    raise SystemExit(main())
