"""Reproducible PABLA experiments E1-E7, with explicit backend provenance.

No labels are passed to the verifier. Every recorded verdict is computed by a
real invocation of the protocol verifier, not a hardcoded accuracy matrix.
"""
from __future__ import annotations

import copy
import csv
import json
import math
import os
import random
import resource
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .ledger import InMemoryLedger
from .protocol import Collector, Policy, ProtocolError, Batch, keypair, manifest_hash, sign, utc_now, verify_batch, verify_history, verify_complete_history
from .storage import RunIndex, archive_size, manifest_metadata, save_batch, write_json, write_jsonl
from .workloads import attack_batch, adaptive_attack_batch, adaptive_reissue_history, generate_events

METHODS = ('P1','B1','B2','B3','B4','A1','A2','A3','A4','A5')
ATTACKS = ('AT1','AT2','AT3','AT4','AT5','AT6','AT7','AT8','AT9','AT10', 'TAIL_TRUNCATION', 'MIDDLE_BATCH_DELETE', 'BATCH_REORDER', 'CROSS_BATCH_SPLICE', 'FORK')


@dataclass
class Options:
    profile: str = 'pilot'
    seed: int = 739391
    trials: int = 2
    event_count: int = 24
    batch_size: int = 12
    backend: str = 'memory'
    rpc: str = 'http://127.0.0.1:8545'
    contract_address: str = ''
    abi_path: str = 'contracts/out/CollectorAnchorRegistry.sol/CollectorAnchorRegistry.json'
    base_timestamp: str = ''
    dataset_path: str = ''


_ANVIL_SNAPSHOT: dict[str, Any] = {}

def init_chain_snapshot(options: Options) -> None:
    """Take a stable post-deployment (and post-smoke) Anvil state snapshot.

    Snapshot/revert is an experimental reset, not Ethereum transaction finality.
    """
    global _ANVIL_SNAPSHOT
    if options.backend != 'anvil':
        _ANVIL_SNAPSHOT = {}
        return
    from .ledger import AnvilLedger
    chain = AnvilLedger(options.rpc, options.contract_address, options.abi_path)
    response=chain.web3.provider.make_request('evm_snapshot',[])
    if 'result' not in response:
        raise ProtocolError(f'Anvil snapshot failed: {response}')
    _ANVIL_SNAPSHOT={'id':response['result'],'rpc':options.rpc,'contract':options.contract_address}

def ledger_for(options: Options):
    if options.backend == 'memory':
        return InMemoryLedger()
    if options.backend == 'anvil':
        if not options.contract_address:
            raise ProtocolError('anvil requires deployed contract address')
        from .ledger import AnvilLedger
        ledger=AnvilLedger(options.rpc, options.contract_address, options.abi_path)
        if _ANVIL_SNAPSHOT:
            if (_ANVIL_SNAPSHOT['rpc'],_ANVIL_SNAPSHOT['contract']) != (options.rpc,options.contract_address):
                raise ProtocolError('Anvil snapshot belongs to a different deployment')
            reverted=ledger.web3.provider.make_request('evm_revert',[_ANVIL_SNAPSHOT['id']])
            if reverted.get('result') is not True:
                raise ProtocolError(f'Anvil snapshot revert failed: {reverted}')
            new=ledger.web3.provider.make_request('evm_snapshot',[])
            if not new.get('result'):
                raise ProtocolError(f'Anvil re-snapshot failed: {new}')
            _ANVIL_SNAPSHOT['id']=new['result']
        return ledger
    raise ValueError('unsupported ledger backend')


def _make(options: Options, method: str, seed: int, count: int, batch_size: int,
          *, collector_id: str = 'collector-001', epoch: int = 1, events: list[dict] | None = None):
    ledger = ledger_for(options)
    if not options.base_timestamp:
        options.base_timestamp = utc_now()
    if options.backend == 'anvil':
        # Pseudonymous collectors avoid registry collisions across independent trials.
        # The payload generator seed remains paired across comparison methods.
        collector_id = f'trial-{time.time_ns()}-{method}'
    sk, pk = keypair()
    policy = Policy.for_name(method)
    if policy.forward_integrity:
        from .keyschedule import EvolvingSigner
        schedule=EvolvingSigner.create(count=min(10000, max(4, (count+batch_size-1)//batch_size+2)))
        schedule.retain_old_for_ablation=(method=="FI-noerase")
        ledger.register_fi(collector_id,epoch,schedule.root,schedule.count,policy_name=method)
        collector=Collector(collector_id,epoch,sk,policy,evolving=schedule)
    else:
        ledger.register(collector_id, epoch, pk, policy_name=method)
        collector = Collector(collector_id, epoch, sk, policy)
    if events is None:
        events = generate_events(count, seed, collector_id, epoch, timestamp=options.base_timestamp)
    batches: list[Batch] = []
    receipts = []
    build_ns = 0
    anchor_ns = 0
    batch_size = 1 if method == 'B1' else batch_size
    for offset in range(0, count, batch_size):
        t0 = time.perf_counter_ns()
        batch = collector.collect(events[offset:offset+batch_size])
        build_ns += time.perf_counter_ns() - t0
        batches.append(batch)
        if policy.anchor:
            ta = time.perf_counter_ns()
            receipts.append(ledger.anchor(batch))
            anchor_ns += time.perf_counter_ns() - ta
    tv = time.perf_counter_ns()
    verdicts = verify_history(batches, ledger, policy)
    verify_ns = time.perf_counter_ns() - tv
    if any(v.status != 'ACCEPT' for v in verdicts):
        raise AssertionError(f'{method} valid baseline failed: {[v.as_dict() for v in verdicts]}')
    ledger.measurement_anchor_ns = anchor_ns
    return ledger, collector, batches, receipts, build_ns, verify_ns


def _row(exp: str, method: str, trial: int, ledger: Any, **fields: Any) -> dict[str, Any]:
    return {'experiment':exp, 'method':method, 'trial':trial,'backend':ledger.backend, **fields}


def _record_status(result, expected_attack: bool = True) -> bool:
    if result.status == 'ACCEPT':
        return False
    if result.status == 'ACCEPT_WITH_WARNING':
        return True
    if result.status == 'UNDETERMINED_ARCHIVE_MISSING':
        return True  # availability anomaly; never call this a cryptographic integrity rejection
    return result.status.startswith('REJECT_')


def integrity(options: Options) -> list[dict]:
    rows = []
    for trial in range(options.trials):
        for method in ('P1','B1','B2','B3','B4','A3','A4','A5'):
            for attack in ('AT1','AT6','AT8'):
                l,c,bs,_,_,_ = _make(options,method,options.seed+trial,options.event_count,options.batch_size)
                for model in ('naive','adaptive'):
                    attacked = attack_batch(bs[0], attack) if model=='naive' else adaptive_attack_batch(bs[0],attack,c.policy)
                    t0 = time.perf_counter_ns()
                    v = verify_batch(attacked, l, policy=c.policy)
                    rows.append(_row('E1',method,trial,l,attack=attack,attacker_model=model,verdict=v.status,
                                     anomalies=';'.join(v.anomalies), detected=int(_record_status(v)),
                                     verify_ns=time.perf_counter_ns()-t0,valid_case=False))
                good = verify_batch(bs[0], l, policy=c.policy)
                rows.append(_row('E1',method,trial,l,attack='NONE',verdict=good.status,
                                 anomalies=';'.join(good.anomalies),attacker_model='none',detected=int(_record_status(good)),valid_case=True))
            # AT7 is a rejected submission, not retroactive rejection of a valid old anchor.
            l,c,bs,_,_,_ = _make(options,method,options.seed+trial,options.event_count,options.batch_size)
            l.revoke(c.collector_id,c.epoch)
            next_events = generate_events(options.batch_size,options.seed+trial+9876,c.collector_id,c.epoch)
            for i,ev in enumerate(next_events):
                ev['collector_monotonic_ns'] = options.event_count+i+1
            candidate = c.collect(next_events)
            rejected = False
            failure = ''
            if c.policy.anchor:
                try:
                    l.anchor(candidate)
                except (ProtocolError, ValueError) as exc:
                    rejected = True
                    failure = type(exc).__name__
            rows.append(_row('E1',method,trial,l,attack='AT7',verdict='REJECT_SUBMISSION' if rejected else 'UNCONTROLLED_OFFCHAIN',
                             anomalies=failure,attacker_model='revoked-submission',detected=int(rejected),valid_case=False))
    return rows


def continuity(options: Options) -> list[dict]:
    rows = []
    for trial in range(options.trials):
        for method in ('P1','B1','B2','B3','B4','A1','A2'):
            l,c,bs,_,_,_ = _make(options,method,options.seed+trial,options.event_count,options.batch_size)
            for attack in ('AT2','AT3','AT4','AT10'):
                # B1 commits one event per record; AT3 is a cross-batch swap.
                if method == 'B1' and attack == 'AT3' and len(bs) > 1:
                    changed = [copy.deepcopy(x) for x in bs]
                    changed[0].events[0], changed[1].events[0] = changed[1].events[0],changed[0].events[0]
                    v = verify_history(changed,l,c.policy)[0]
                else:
                    if method == 'B1' and attack == 'AT4':
                        # Replay the same on-chain event by repeating an archive artifact.
                        changed = [bs[0],bs[0]]
                        v = verify_history(changed,l,c.policy)[1]
                    else:
                        changed = attack_batch(bs[0],attack)
                        v = verify_batch(changed,l,policy=c.policy)
                rows.append(_row('E2',method,trial,l,attack=attack,attacker_model='naive',verdict=v.status,
                                 anomalies=';'.join(v.anomalies),detected=int(_record_status(v)),valid_case=False))
                if attack in ('AT2','AT4'):
                    if method == 'B3':
                        revised=adaptive_reissue_history(bs,c.policy,attack)
                        adv=verify_history(revised,l,c.policy)
                        v_ad=next((q for q in adv if _record_status(q)),adv[-1])
                        detected_ad=int(any(_record_status(q) for q in adv))
                    elif method == 'B1':
                        mutated=None if attack=='AT2' else adaptive_attack_batch(bs[0],attack,c.policy)
                        v_ad=verify_batch(mutated,l,policy=c.policy)
                        detected_ad=int(_record_status(v_ad))
                    else:
                        mutated=adaptive_attack_batch(bs[0],attack,c.policy)
                        v_ad=verify_batch(mutated,l,policy=c.policy)
                        detected_ad=int(_record_status(v_ad))
                    rows.append(_row('E2',method,trial,l,attack=attack,attacker_model='adaptive',
                                     verdict=v_ad.status,anomalies=';'.join(v_ad.anomalies),
                                     detected=detected_ad,valid_case=False))
            if len(bs)>2 and method != 'B1':
                for history_attack in ('MIDDLE_BATCH_DELETE','BATCH_REORDER','CROSS_BATCH_SPLICE','FORK'):
                    history=copy.deepcopy(bs)
                    if history_attack=='MIDDLE_BATCH_DELETE':
                        history.pop(1)
                    elif history_attack=='BATCH_REORDER':
                        history[1],history[2]=history[2],history[1]
                    elif history_attack=='CROSS_BATCH_SPLICE':
                        history[1].events[-1],history[2].events[0]=history[2].events[0],history[1].events[-1]
                    else:
                        forged=history[1]
                        forged.events[0]['payload']['pid']+=1
                        # Key compromise can re-sign, but the first legitimate
                        # fork is already anchored. A second fork must mismatch.
                        from .protocol import chain_hash,event_hash,leaf_hash,merkle_root
                        prev=forged.manifest['first_previous_chain'] if c.policy.chain else '00'*32
                        leaves=[]
                        for j,ev in enumerate(forged.events):
                            seq=forged.manifest['first_sequence']+j
                            h=event_hash(c.collector_id,c.epoch,seq,ev)
                            prev=chain_hash(c.collector_id,c.epoch,seq,prev,h) if c.policy.chain else '00'*32
                            leaves.append(leaf_hash(seq,h,prev))
                        forged.manifest['last_chain']=prev
                        forged.manifest['merkle_root']=merkle_root(leaves)
                        forged.manifest_digest=manifest_hash(forged.manifest)
                        forged.signature=sign(c.private_key,forged.manifest_digest) if c.policy.sign_batches else ''
                    findings=verify_complete_history(history,l,policy=c.policy,collector_id=c.collector_id,epoch=c.epoch)
                    detected=any(_record_status(z) for z in findings)
                    v=next((z for z in findings if _record_status(z)),findings[-1])
                    rows.append(_row('E2',method,trial,l,attack=history_attack,
                                     attacker_model='history-attack' if history_attack!='FORK' else 'authorized-key-fork',
                                     verdict=v.status,anomalies=';'.join(v.anomalies),
                                     detected=int(detected),valid_case=False))
                    if method=='B3' and history_attack!='FORK':
                        reconstructed=adaptive_reissue_history(bs,c.policy,history_attack)
                        adaptive_verdicts=verify_history(reconstructed,l,c.policy)
                        av=next((q for q in adaptive_verdicts if _record_status(q)),adaptive_verdicts[-1])
                        rows.append(_row('E2',method,trial,l,attack=history_attack,
                                         attacker_model='adaptive',verdict=av.status,
                                         anomalies=';'.join(av.anomalies),
                                         detected=int(any(_record_status(q) for q in adaptive_verdicts)),
                                         valid_case=False))
            honest = verify_history(bs,l,c.policy)
            # Tail truncation must be assessed against the *trusted ledger tip*.
            if method in ('P1','B1','B4','A1','A2') and len(bs)>1:
                missing_tail = verify_complete_history(bs[:-1],l,policy=c.policy,collector_id=c.collector_id,epoch=c.epoch)
                bad = missing_tail[-1]
                rows.append(_row('E2',method,trial,l,attack='TAIL_TRUNCATION',attacker_model='archive-truncation',
                                 verdict=bad.status,anomalies=';'.join(bad.anomalies),detected=int(_record_status(bad)),valid_case=False))
            rows.append(_row('E2',method,trial,l,attack='NONE',attacker_model='none',verdict=honest[-1].status,
                             anomalies=';'.join(honest[-1].anomalies),
                             detected=int(any(_record_status(x) for x in honest)),valid_case=True))
    return rows


def overhead(options: Options) -> list[dict]:
    rows = []
    for trial in range(options.trials):
        methods=list(('P1','B1','B2','B3','B4','FI'))
        random.Random(options.seed+trial).shuffle(methods)
        for method in methods:
            count = min(options.event_count, 250 if method == 'B1' and options.profile != 'full' else 10_000)
            l,c,bs,receipts,build_ns,verify_ns = _make(options,method,options.seed+trial,count,
                                                         min(options.batch_size,count))
            # Empty fields mean unmeasured, not zero-cost blockchain writes.
            evm = l.backend == 'anvil-evm'
            rows.append(_row('E3',method,trial,l,events=count,batches=len(bs),
                transactions=len(receipts),tx_per_event=len(receipts)/count,
                evm_gas_used=sum(r.get('gas_used',0) for r in receipts) if evm else None,
                evm_input_bytes=sum(r.get('transaction_input_bytes',0) for r in receipts) if evm else None,
                receipt_tx_hashes=json.dumps([r.get('tx_hash') for r in receipts]),
                receipt_block_numbers=json.dumps([r.get('block_number') for r in receipts]),
                receipt_gas_per_tx=json.dumps([r.get('gas_used') for r in receipts]) if evm else None,
                build_ns_per_event=build_ns/count,anchor_ns_per_event=l.measurement_anchor_ns/count,verify_ns_per_event=verify_ns/count,
                encoded_artifact_bytes=sum(len(json.dumps(b.export())) for b in bs),
                method_order=methods.index(method), chain_reset_before_method=bool(_ANVIL_SNAPSHOT) if evm else True,
                measurement_type='measured-anvil-snapshot-reset' if evm and _ANVIL_SNAPSHOT else ('measured-anvil-shared-state' if evm else 'measured-nonchain-test-double')))
    return rows


def tradeoff(options: Options) -> list[dict]:
    """Physically paced streams, not fabricated event-to-anchor times.

    --profile full runs all four prescribed rates and batch sizes; 10 event/s
    at 10,000 events intentionally takes substantial wall clock time.
    """
    rows = []
    sizes = (10,100,1000,10000) if options.profile=='full' else (10,100)
    rates = (10,100,1000,10000) if options.profile=='full' else (1000,10000)
    for trial in range(options.trials):
        for requested_bs in sizes:
            for rate in rates:
                count = options.event_count if options.profile=='full' else min(options.event_count,24)
                bs=min(requested_bs,count)
                methods = ['P1','B4','FI']
                random.Random(options.seed + trial + rate + bs).shuffle(methods)
                for method in methods:
                    ledger=ledger_for(options)
                    identifier = f'e4-{time.time_ns()}-{method}' if options.backend=='anvil' else 'e4-collector'
                    sk,pk=keypair()
                    if method=='FI':
                        from .keyschedule import EvolvingSigner
                        schedule=EvolvingSigner.create(count=min(10000,(count+bs-1)//bs+2))
                        ledger.register_fi(identifier,1,schedule.root,schedule.count)
                        collector=Collector(identifier,1,sk,Policy.for_name(method),evolving=schedule)
                    else:
                        ledger.register(identifier,1,pk,policy_name=method)
                        collector=Collector(identifier,1,sk,Policy.for_name(method))
                    events=generate_events(count,options.seed+trial,identifier,1,timestamp=options.base_timestamp or utc_now())
                    pending=[];arrivals=[];delays=[];build_ns=0;verify_ns=0;anchor_ns=0;receipts=[]
                    start=time.perf_counter()
                    for i,event in enumerate(events):
                        target=start+i/rate
                        remaining=target-time.perf_counter()
                        if remaining>0:
                            time.sleep(remaining)
                        arrive=time.perf_counter_ns()
                        pending.append(event);arrivals.append(arrive)
                        if len(pending)>=bs or (arrive-arrivals[0])>=5_000_000_000 or i==count-1:
                            bstart=time.perf_counter_ns()
                            batch=collector.collect(pending)
                            build_ns+=time.perf_counter_ns()-bstart
                            if collector.policy.anchor:
                                ta=time.perf_counter_ns()
                                receipts.append(ledger.anchor(batch))
                                anchor_ns += time.perf_counter_ns()-ta
                            confirmed=time.perf_counter_ns()
                            delays.extend((confirmed-at)/1e6 for at in arrivals)
                            tverify=time.perf_counter_ns()
                            verdict=verify_batch(batch,ledger,policy=collector.policy,previous=None if batch.manifest['batch_number']==1 else prev_manifest)
                            verify_ns+=time.perf_counter_ns()-tverify
                            if verdict.status!='ACCEPT':
                                raise AssertionError(f'E4 honest stream rejected: {verdict}')
                            prev_manifest=batch.manifest
                            pending=[];arrivals=[]
                    delays.sort()
                    rows.append(_row('E4',method,trial,ledger,batch_size=requested_bs,effective_batch_size=bs,
                        event_rate=rate,events=count,build_ns_per_event=build_ns/count,
                        verify_ns_per_event=verify_ns/count,anchor_ns_per_event=anchor_ns/count,
                        measured_e2e_anchor_delay_median_ms=statistics.median(delays),
                        measured_e2e_anchor_delay_p95_ms=delays[min(count-1,int(.95*(count-1)))],
                        transactions=len(receipts),physical_pacing=True,chain_latency_measured=ledger.backend=='anvil-evm',
                        chain_reset_before_method=bool(_ANVIL_SNAPSHOT) if options.backend=='anvil' else True,method_order=methods.index(method)))
    return rows


def recovery(options: Options) -> list[dict]:
    rows = []
    for trial in range(options.trials):
        l,c,batches,_,_,_ = _make(options,'P1',options.seed+trial,options.event_count,options.batch_size)
        last_digest = batches[-1].manifest_digest
        old_public = l.identity(c.collector_id,1)['public_key']
        before = verify_batch(batches[-1],l,policy=c.policy,previous=batches[-2].manifest if len(batches)>1 else None)
        t0 = time.perf_counter_ns()
        rev_receipt = l.revoke(c.collector_id,1)
        fresh = generate_events(options.batch_size,options.seed+trial+1,c.collector_id,1)
        for i,ev in enumerate(fresh):
            ev['collector_monotonic_ns'] = options.event_count+i+1
        attempt = c.collect(fresh)
        blocked = False
        try:
            l.anchor(attempt)
        except (ProtocolError,ValueError):
            blocked = True
        sk2,pk2 = keypair()
        l.register(c.collector_id,2,pk2,recovery=last_digest,policy_name="P1")
        c2 = Collector(c.collector_id,2,sk2)
        ev2 = generate_events(min(options.batch_size,options.event_count),options.seed+trial+2,c.collector_id,2)
        new_batch = c2.collect(ev2)
        l.anchor(new_batch)
        new_verdict = verify_batch(new_batch,l,policy=c2.policy)
        old_after = verify_batch(batches[-1],l,policy=c.policy,previous=batches[-2].manifest if len(batches)>1 else None)
        rows.append(_row('E5','P1',trial,l,revocation_block=rev_receipt['block_number'],
            old_key=old_public,late_submission_rejected=int(blocked),
            new_epoch_accepted=int(new_verdict.status=='ACCEPT'),
            historical_anchor_still_valid=int(old_after.status=='ACCEPT'),
            before_verdict=before.status,recovery_time_ns=time.perf_counter_ns()-t0))
    return rows


def residual(options: Options) -> list[dict]:
    rows=[]
    for trial in range(options.trials):
        l,c,bs,_,_,_ = _make(options,'P1',options.seed+trial,options.event_count,options.batch_size)
        fake = generate_events(options.batch_size,options.seed+trial+982,c.collector_id,c.epoch)
        for i,ev in enumerate(fake):
            ev['collector_monotonic_ns'] = options.event_count+i+1
            ev['payload']['process'] = '/usr/bin/fabricated-event'
        forged = c.collect(fake)
        l.anchor(forged)
        verdict = verify_batch(forged,l,policy=c.policy,previous=bs[-1].manifest)
        rows.append(_row('E6','P1',trial,l,attack='AT9',scenario='active-key-fabricated-log',
                         verdict=verdict.status,cryptographic_accept=int(verdict.status=='ACCEPT'),
                         ground_truth='synthetically fabricated by adversary holding legitimate key'))
        # AT5: *legitimate* signed manifest timestamp shifted, not unsigned archive mutation.
        l2,c2,old,_,_,_ = _make(options,'P1',options.seed+trial+3,options.batch_size,options.batch_size)
        shifted = generate_events(options.batch_size,options.seed+trial+4,c2.collector_id,c2.epoch)
        for i,ev in enumerate(shifted):
            ev['collector_monotonic_ns'] = options.batch_size+i+1
        candidate = c2.collect(shifted, wall_time='2001-01-01T00:00:00.000Z')
        l2.anchor(candidate)
        skew_verdict=verify_batch(candidate,l2,policy=c2.policy,previous=old[-1].manifest)
        rows.append(_row('E6','P1',trial,l2,attack='AT5',scenario='valid-signature-implausible-clock',
                         verdict=skew_verdict.status,cryptographic_accept=int(skew_verdict.status=='ACCEPT'),
                         ground_truth='signed wall-clock skew'))
        l3,c3,old3,_,_,_= _make(options,'A5',options.seed+trial+3,options.batch_size,options.batch_size)
        skew_events=generate_events(options.batch_size,options.seed+trial+4,c3.collector_id,c3.epoch)
        for i,ev in enumerate(skew_events):
            ev['collector_monotonic_ns']=options.batch_size+i+1
        skewed=c3.collect(skew_events,wall_time='2001-01-01T00:00:00.000Z')
        l3.anchor(skewed)
        a5=verify_batch(skewed,l3,policy=c3.policy,previous=old3[-1].manifest)
        rows.append(_row('E6','A5',trial,l3,attack='AT5',scenario='timestamp-validation-ablated',
                         verdict=a5.status,cryptographic_accept=int(a5.status=='ACCEPT'),
                         ground_truth='signed clock skew under disabled timestamp check'))
    return rows


def stability(options: Options) -> list[dict]:
    """Every memory/CPU trial runs in a fresh process; RSS is not cumulative."""
    import subprocess
    import sys
    rows=[]
    for trial in range(max(options.trials,3)):
        for method in ('P1','B1'):
            params = {'method': method, 'trial': trial, 'count': min(options.event_count,250),
                      'batch_size': options.batch_size, 'seed': options.seed+trial,
                      'base_timestamp': options.base_timestamp or utc_now(), 'backend': options.backend,
                      'rpc': options.rpc, 'contract_address': options.contract_address, 'abi_path': options.abi_path}
            cmd=[sys.executable,'-m','pabla.stability_worker',json.dumps(params)]
            proc=subprocess.run(cmd,capture_output=True,text=True,timeout=300,check=False)
            if proc.returncode:
                raise RuntimeError(f'E7 child process failed: {proc.stderr[-1000:]}')
            measurements=json.loads(proc.stdout)
            rows.append(_row('E7',method,trial,type('Backend',(),{'backend': 'anvil-evm' if options.backend=='anvil' else 'in-memory-test-only'})(),
                             **measurements,measurement_type='isolated-process'))
    return rows


def ct_history_comparison(options: Options) -> list[dict]:
    """E8: cross-check signed RFC 6962-style append-only consistency evidence.

    Uses identical canonical event bytes for both methods. CT history-tree
    implementation is a transparent *reference*, not optimized service code.
    Runtime data are reported but are not used to assert production speedups.
    """
    import copy
    from .ct_baseline import CTBaseline, leaf as ct_leaf, root as ct_root, inclusion_proof, verify_inclusion, consistency_proof, verify_consistency
    from .protocol import canonical, digest
    rows=[]
    for trial in range(options.trials):
        count=min(options.event_count, 1000)
        l,c,bs,receipt,build_ns,verify_ns = _make(options,'P1', options.seed+trial,count,
                                                    min(options.batch_size,count))
        events=[ev for b in bs for ev in b.events]
        correct=verify_complete_history(bs,l,policy=c.policy,collector_id=c.collector_id,epoch=c.epoch)
        rows.append(_row('E8','P1',trial,l,events=count,scenario='benchmark',
                         all_valid=int(all(v.status=='ACCEPT' for v in correct)),
                         verification_ns=verify_ns,construction_ns=build_ns,
                         construction_ns_per_event=build_ns/count,
                         verification_ns_per_event=verify_ns/count,
                         trust_model='registered collector and ledger anchored batches',
                         input_fingerprint=digest_events(events)))
        ct=CTBaseline(c.private_key)
        tb=time.perf_counter_ns()
        old=None; comparisons=[]; last_checkpoint=None
        for offset in range(0,len(events),min(options.batch_size,count)):
            subset=events[offset:offset+min(options.batch_size,count)]
            for event in subset:
                ct.append(event)
            current=ct.checkpoint()
            if old:
                proof=consistency_proof(ct.hashes,old['size'])
                comparisons.append((old,current,proof))
            old=current
            last_checkpoint=current
        constructed_ns=time.perf_counter_ns()-tb
        tv=time.perf_counter_ns()
        all_valid=ct.verify_checkpoint(last_checkpoint,ct.public_key)
        all_valid=all_valid and all(
            ct.verify_checkpoint(old,ct.public_key) and
            verify_consistency(old['size'],now['size'],
                               bytes.fromhex(old['root']),bytes.fromhex(now['root']),proof)
            for old,now,proof in comparisons)
        audit_index=len(events)//2
        inclusion=inclusion_proof(ct.hashes,audit_index)
        all_valid=all_valid and verify_inclusion(ct.hashes[audit_index],audit_index,len(ct.hashes),
                                                 inclusion,bytes.fromhex(last_checkpoint['root']))
        altered=copy.deepcopy(events[audit_index])
        altered['payload']['pid']+=1
        detects_tamper=not verify_inclusion(ct_leaf(canonical(altered)),audit_index,len(events),inclusion,
                                           bytes.fromhex(last_checkpoint['root']))
        verification_ns=time.perf_counter_ns()-tv
        rows.append(_row('E8','CT_HISTORY_TREE_REFERENCE',trial,l,events=count,scenario='benchmark',
                         all_valid=int(all_valid),detects_postcommit_tamper=int(detects_tamper),
                         consistency_comparisons=len(comparisons),
                         proof_bytes=sum(len(pp)*32 for _,_,pp in comparisons),
                         construction_ns=constructed_ns,verification_ns=verification_ns,
                         construction_ns_per_event=constructed_ns/count,
                         verification_ns_per_event=verification_ns/count,
                         verification_ns_per_inclusion_proof=verification_ns,
                         trust_model='signed transparency-tree checkpoints, no ledger anchoring',
                         input_fingerprint=digest_events(events),
                         performance_claim='reference implementation, not optimized or production throughput'))
        # Matched-trust reference: anchor the signed CT checkpoint root via the
        # same local contract, using an opaque CT-root commitment. The CT signature
        # and append-only verification remain independent of PABLA's verifier.
        ctledger=ledger_for(options)
        ct_id=f'ct-e8-{time.time_ns()}-{trial}' if options.backend=='anvil' else f'ct-e8-{trial}'
        ctledger.register(ct_id,1,ct.public_key,policy_name='B4')
        mh=digest('PABLA-CT-ANCHOR-v1',canonical(last_checkpoint))
        anchor_obj=Batch({'collector_id':ct_id,'epoch':1,'batch_number':1,'method':'B4',
                          'first_sequence':1,'last_sequence':count,
                          'merkle_root':last_checkpoint['root'],'last_chain':'00'*32,
                          'previous_manifest_hash':'00'*32},last_checkpoint['signature'],[],mh,[])
        anchor_receipt=ctledger.anchor(anchor_obj)
        rows.append(_row('E8','CT_ANCHORED',trial,ctledger,events=count,scenario='benchmark',
            all_valid=int(all_valid),construction_ns_per_event=constructed_ns/count,
            verification_ns_per_event=verification_ns/count,
            transactions=1,gas_used=anchor_receipt.get('gas_used'),
            trust_model='signed CT checkpoint independently anchored on identical contract',
            input_fingerprint=digest_events(events)))
        for attack in ('AT1','AT2','AT3','AT4'):
            for model in ('naive','adaptive-stolen-key'):
                # Identical event mutations for the compared methods.
                altered=copy.deepcopy(events)
                if attack=='AT1': altered[0]['payload']['pid']+=10
                elif attack=='AT2': altered.pop(len(altered)//2)
                elif attack=='AT3': altered[0],altered[-1]=altered[-1],altered[0]
                elif attack=='AT4': altered.insert(1,copy.deepcopy(altered[0]))
                candidate=CTBaseline(ct.signing_key)
                for ev in altered: candidate.append(ev)
                forged_cp=candidate.checkpoint()
                # Naive attacker supplies unchanged signed checkpoint, not new signature.
                proposed=last_checkpoint if model=='naive' else forged_cp
                archive_consistent=(proposed['size']==len(altered) and proposed['root']==ct_root(candidate.hashes).hex())
                signature_valid=CTBaseline.verify_checkpoint(proposed,ct.public_key)
                anchor_consistent=proposed['root']==last_checkpoint['root'] and proposed['size']==count
                for ct_method in ('CT_HISTORY_TREE_REFERENCE','CT_ANCHORED'):
                    detected=not (archive_consistent and signature_valid and (ct_method!='CT_ANCHORED' or anchor_consistent))
                    rows.append(_row('E8',ct_method,trial,ctledger if ct_method=='CT_ANCHORED' else l,
                        events=count,scenario='attack',attack=attack,attacker_model=model,
                        detected=int(detected),verdict='REJECT' if detected else 'ACCEPT',
                        trust_model='anchored CT root' if ct_method=='CT_ANCHORED' else 'offchain static-key CT'))
                p1mut=attack_batch(bs[0],attack) if model=='naive' else adaptive_attack_batch(bs[0],attack,c.policy)
                if model!='naive':
                    p1mut.signature=sign(c.private_key,p1mut.manifest_digest)
                pv=verify_batch(p1mut,l,policy=c.policy)
                rows.append(_row('E8','P1',trial,l,events=count,scenario='attack',attack=attack,
                    attacker_model=model,detected=int(_record_status(pv)),verdict=pv.status,
                    trust_model='registered collector and anchored batch'))
    return rows

def digest_events(events: list[dict]) -> str:
    from .protocol import digest, canonical
    import hashlib
    h=hashlib.sha256()
    for ev in events:
        encoded=canonical(ev)
        h.update(len(encoded).to_bytes(8,'big'))
        h.update(encoded)
    return h.hexdigest()


def fi_compromise(options: Options) -> list[dict]:
    """E9: compare previously signed unanchored periods AFTER key theft.

    Static signatures and anchors BOTH protect earlier anchored history, so
    the precise differential is period-key erasure for an unanchored signed
    archive. Without independent custody, these archives can still vanish.
    """
    from .protocol import verify_pending_batch, verify_batch, public_hex
    from .keyschedule import EvolvingSigner, private_from_seed
    from .workloads import rebuild_untrusted
    from .ct_baseline import CTBaseline
    rows=[]
    n=max(2,min(options.batch_size,24))
    for trial in range(options.trials):
        for method in ('FI','FI-noerase','FI-nochain','P1','B4'):
            ledger=ledger_for(options)
            collector_id=f'e9-{method}-{trial}-{time.time_ns()}' if options.backend=='anvil' else f'e9-{method}-{trial}'
            sk,pk=keypair()
            policy=Policy.for_name(method)
            evolving=None
            if policy.forward_integrity:
                evolving=EvolvingSigner.create(count=8)
                evolving.retain_old_for_ablation=method=='FI-noerase'
                ledger.register_fi(collector_id,1,evolving.root,evolving.count,policy_name=method)
            else:
                ledger.register(collector_id,1,pk,policy_name=method)
            c=Collector(collector_id,1,sk,policy,evolving=evolving)
            stream=generate_events(3*n,options.seed+trial,collector_id,1,timestamp=options.base_timestamp or utc_now())
            b1=c.collect(stream[:n]); ledger.anchor(b1)
            b2=c.collect(stream[n:2*n])  # signed, pending, NOT YET anchored
            current_seed=evolving.compromised_current_seed_for_test() if evolving else None
            prior_seed=(evolving.historical_seeds.get(2) if method=='FI-noerase' else None) if evolving else None
            naive=copy.deepcopy(b2)
            naive.events[0]['payload']['pid']+=351
            nv=verify_pending_batch(naive,ledger,policy=policy,previous=b1.manifest)
            rows.append(_row('E9',method,trial,ledger,
                attack='REWRITE_PREVIOUS_SIGNED_PENDING_PERIOD',
                attacker_model='naive-archive-mutation',accepted=int(nv.status=='ACCEPT_WITH_WARNING'),
                verdict=nv.status,anomalies=';'.join(nv.anomalies),period=2))
            forged=copy.deepcopy(b2)
            forged.events[0]['payload']['pid']+=351
            forged=rebuild_untrusted(forged,policy)
            attacker_sk=(private_from_seed(prior_seed or current_seed) if evolving else sk)
            forged.signature=sign(attacker_sk,forged.manifest_digest)
            result=verify_pending_batch(forged,ledger,policy=policy,previous=b1.manifest)
            rows.append(_row('E9',method,trial,ledger,attack='REWRITE_PREVIOUS_SIGNED_PENDING_PERIOD',
                 attacker_model='stolen-current-key',accepted=int(result.status=='ACCEPT_WITH_WARNING'),
                 verdict=result.status,anomalies=';'.join(result.anomalies),period=2,
                 claim='previously signed but not independently anchored',trust_model='registered signer and schedule'))
            anchored=copy.deepcopy(b1)
            anchored.events[0]['payload']['pid']+=278
            anchored=rebuild_untrusted(anchored,policy)
            # Any active-key compromise still cannot alter immutable anchor.
            anchored.signature=sign(attacker_sk,anchored.manifest_digest)
            v=verify_batch(anchored,ledger,policy=policy)
            rows.append(_row('E9',method,trial,ledger,attack='REWRITE_ALREADY_ANCHORED',
                attacker_model='stolen-current-key',accepted=int(v.status=='ACCEPT'),verdict=v.status,
                anomalies=';'.join(v.anomalies),period=1,
                claim='all models must reject anchored substitutions'))
            if policy.forward_integrity:
                # Attacker cannot relabel the stolen future/current key as past.
                stale=copy.deepcopy(b2)
                stale.manifest['period']=1
                stale.manifest_digest=manifest_hash(stale.manifest)
                stale.signature=sign(attacker_sk,stale.manifest_digest)
                rejected=verify_pending_batch(stale,ledger,policy=policy,previous=b1.manifest)
                rows.append(_row('E9',method,trial,ledger,attack='EARLIER_PERIOD_WITH_STOLEN_KEY',
                    attacker_model='adaptive-stolen-key',accepted=int(rejected.status=='ACCEPT_WITH_WARNING'),
                    verdict=rejected.status,anomalies=';'.join(rejected.anomalies),period=1))
                # A collector thief can use CURRENT key to sign fabricated
                # future-period content. FI does not solve semantic truth.
                ledger.anchor(b2)
                fabricated=copy.deepcopy(stream[2*n:])
                fabricated[0]['payload']['process']='fabricated-after-compromise'
                b3=c.collect(fabricated)
                ledger.anchor(b3)
                v3=verify_batch(b3,ledger,policy=policy,previous=b2.manifest)
                rows.append(_row('E9',method,trial,ledger,attack='FABRICATE_WITH_CURRENT_KEY',
                    attacker_model='adaptive-stolen-key',accepted=int(v3.status=='ACCEPT'),
                    verdict=v3.status,anomalies=';'.join(v3.anomalies),period=3,
                    ground_truth='semantically fabricated, cryptographically valid'))
            # Anchored-history attack set: every construction with a trustworthy
            # immutable anchor must reject deletion, splice and reordering.
            # This is NOT presented as an FI-only advantage.
            if not policy.forward_integrity:
                ledger.anchor(b2)
                b3=c.collect(stream[2*n:]);ledger.anchor(b3)
            # Explicit back-fill submission after the on-chain period has advanced.
            try:
                ledger.anchor(b2)
                backfill_rejected=False
            except ProtocolError:
                backfill_rejected=True
            rows.append(_row('E9',method,trial,ledger,attack='BACKFILL_OLD_PERIOD',
                attacker_model='adaptive-stolen-key',accepted=int(not backfill_rejected),
                verdict='REJECT_SUBMISSION' if backfill_rejected else 'ACCEPT_SUBMISSION'))
            history=[b1,b2,b3]
            for attack_name in ('TRUNCATE_ANCHORED_HISTORY','SPLICE_ANCHORED_BATCHES','REORDER_ANCHORED_BATCHES'):
                edited=copy.deepcopy(history)
                if attack_name=='TRUNCATE_ANCHORED_HISTORY':
                    edited.pop()
                elif attack_name=='SPLICE_ANCHORED_BATCHES':
                    edited[1].events[-1],edited[2].events[0]=edited[2].events[0],edited[1].events[-1]
                    edited[1]=rebuild_untrusted(edited[1],policy)
                    edited[2]=rebuild_untrusted(edited[2],policy)
                    if not policy.forward_integrity:
                        for changed in edited[1:]: changed.signature=sign(sk,changed.manifest_digest)
                else:
                    edited[1],edited[2]=edited[2],edited[1]
                verdicts=verify_complete_history(edited,ledger,policy=policy,
                    collector_id=collector_id,epoch=1)
                bad=next((v for v in verdicts if v.status.startswith('REJECT_')),verdicts[-1])
                rows.append(_row('E9',method,trial,ledger,attack=attack_name,
                    attacker_model='adaptive-stolen-key',accepted=int(not any(
                        v.status.startswith('REJECT_') for v in verdicts)),verdict=bad.status,
                    anomalies=';'.join(bad.anomalies),trust_model='immutable ledger head'))
            # The stolen current key can equivocate within the pending window.
            # Both archives pass independently, but at most one can be anchored.
            upcoming=[]
            stolen=evolving.compromised_current_seed_for_test() if evolving else None
            for variant in (0,1):
                if policy.forward_integrity:
                    clone_signer=EvolvingSigner(bytearray(stolen),evolving.start_period,
                        evolving.count,evolving.current_period,evolving.public_keys,
                        evolving.leaves,evolving.root)
                    clone=Collector(collector_id,1,sk,policy,
                        next_sequence=c.next_sequence,next_batch=c.next_batch,
                        last_chain=c.last_chain,last_manifest=c.last_manifest,
                        evolving=clone_signer)
                else:
                    clone=Collector(collector_id,1,sk,policy,
                        next_sequence=c.next_sequence,next_batch=c.next_batch,
                        last_chain=c.last_chain,last_manifest=c.last_manifest)
                future=generate_events(n,options.seed+trial+variant+200,collector_id,1,
                    timestamp=options.base_timestamp or utc_now())
                for idx,ev in enumerate(future):
                    ev['collector_monotonic_ns']=3*n+idx+1
                    ev['payload']['pid']+=variant
                upcoming.append(clone.collect(future))
            equivocal=[verify_pending_batch(x,ledger,policy=policy,previous=b3.manifest) for x in upcoming]
            rows.append(_row('E9',method,trial,ledger,attack='EQUIVOCATE_PENDING_WINDOW',
                attacker_model='adaptive-current-key',accepted=int(all(
                    v.status=='ACCEPT_WITH_WARNING' for v in equivocal)),
                verdict='ACCEPT_BOTH_PENDING' if all(v.status=='ACCEPT_WITH_WARNING' for v in equivocal) else 'REJECT',
                period=c.next_batch,ground_truth='two mutually inconsistent authenticated pending histories'))
        # CT-style unanchored checkpoints: a compromised STATIC key can sign a
        # new checkpoint for rewritten logs. Anchored roots reject the rewrite.
        for anchored in (False,True):
            sk,pk=keypair()
            ct=CTBaseline(sk)
            events=generate_events(2*n,options.seed+trial,'ct-trial')
            for event in events: ct.append(event)
            honest=ct.checkpoint()
            changed=copy.deepcopy(events)
            changed[0]['payload']['pid']+=12
            attacker=CTBaseline(sk)
            for event in changed: attacker.append(event)
            forged=attacker.checkpoint()
            accepted=ct.verify_checkpoint(forged,ct.public_key) and (
                not anchored or forged['root']==honest['root'])
            rows.append(_row('E9','CT_ANCHORED' if anchored else 'CT_OFFCHAIN',trial,
                type('Backend',(),{'backend':'checkpoint-reference' if not anchored else 'anchored-root-comparison'})(),
                attack='REWRITE_CHECKPOINT_WITH_STOLEN_KEY',attacker_model='adaptive-stolen-key',
                accepted=int(accepted),verdict='ACCEPT' if accepted else 'REJECT_CHECKPOINT',
                trust_model='signed checkpoint + independently anchored root' if anchored else 'signed checkpoint only',
                warning='anchored variant compares recorded root, not measured EVM gas'))
        from .keychain_baseline import issue_chain,verify_chain
        initial,links,_=issue_chain(bytes([trial%256])*32,3)
        rows.append(_row('E9','KEYCHAIN_REFERENCE',trial,
            type('Backend',(),{'backend':'offchain-reference'})(),
            attack='MISSING_TRANSITION',attacker_model='archive-suppression',
            accepted=int(verify_chain(initial,links[:1]+links[2:])),
            verdict='ACCEPT' if verify_chain(initial,links[:1]+links[2:]) else 'REJECT_LINK',
            trust_model='initial signing public key and complete transition archive'))
    return rows


def fi_exposure(options: Options) -> list[dict]:
    """E10: exact event-exposure counts at controlled compromise times."""
    from .anchoring import windows,exposed_events,exposed_interval_ms
    rows=[]
    for trial in range(options.trials):
        rng=random.Random(options.seed+trial)
        count=min(options.event_count,10000)
        rates=(10,100,1000,10000)
        rate=rates[trial%len(rates)]
        # Synthetic burstiness, not measured public traffic.
        arrivals=[];t=0
        for i in range(count):
            t+=rng.choice((0,0,1,max(1,1000//rate),max(1,4000//rate)))
            arrivals.append(t)
        for bound in (50,100,500,1000):
            batches=windows(arrivals,batch_size=options.batch_size,max_dwell_ms=1000,max_exposure_ms=bound)
            compromise=rng.randrange(0,arrivals[-1]+2)
            measured=exposed_events(arrivals,batches,compromise)
            anchor_finish=max((w.confirmed_ms for w in batches if w.confirmed_ms < compromise),default=-1)
            independently_modelled=sum(1 for a in arrivals if anchor_finish<a<=compromise)
            if measured!=independently_modelled: raise AssertionError('E10 exposure model mismatch')
            rows.append(_row('E10','FI',trial,type('Backend',(),{'backend':'synthetic-model'})(),
                event_rate_nominal=rate,events=count,window_max_ms=bound,
                compromise_ms=compromise,observed_exposed_events=measured,
                modelled_exposed_events=independently_modelled,
                exposure_window_ms=exposed_interval_ms(batches,compromise),
                anchors=len(batches),trace_source='seeded synthetic timing'))
    return rows


def fi_frontier(options: Options) -> list[dict]:
    """E11: actual in-memory / EVM anchor calls; gas null unless receipt measured."""
    from .anchoring import windows
    from .keyschedule import EvolvingSigner
    rows=[]
    count=min(options.event_count,10000)
    for trial in range(options.trials):
        rng=random.Random(options.seed+trial+1029)
        arrivals=[];t=0
        for i in range(count):
            t+=rng.choice((0,1,3,10,50))
            arrivals.append(t)
        for bound in (50,200,1000):
            for mode in ('fixed','adaptive'):
                batches=windows(arrivals,batch_size=min(options.batch_size,count),max_dwell_ms=1000,
                                max_exposure_ms=bound,mode=mode,fixed_interval_ms=bound if mode=='fixed' else None)
                ledger=ledger_for(options)
                collector_id=f'frontier-{trial}-{bound}-{mode}-{time.time_ns()}' if options.backend=='anvil' else f'frontier-{trial}-{bound}-{mode}'
                sk,pk=keypair()
                schedule=EvolvingSigner.create(count=min(10000,len(batches)+1))
                ledger.register_fi(collector_id,1,schedule.root,schedule.count)
                collector=Collector(collector_id,1,sk,Policy.for_name('FI'),evolving=schedule)
                data=generate_events(count,options.seed+trial,collector_id,1,timestamp=options.base_timestamp or utc_now())
                receipt_gas=[];built_ns=0;anchored_ns=0
                for w in batches:
                    started=time.perf_counter_ns()
                    batch=collector.collect(data[w.first_index:w.last_index+1])
                    built_ns+=time.perf_counter_ns()-started
                    started=time.perf_counter_ns()
                    rec=ledger.anchor(batch)
                    anchored_ns+=time.perf_counter_ns()-started
                    if 'gas_used' in rec:receipt_gas.append(rec['gas_used'])
                max_delay=max(w.max_wait_ms for w in batches)
                rows.append(_row('E11','FI',trial,ledger,mode=mode,events=count,bound_ms=bound,
                    anchors=len(batches),anchor_calls_per_event=len(batches)/count,
                    observed_max_wait_ms=max_delay,
                    violates_bound=int(max_delay>bound),
                    construction_ns_per_event=built_ns/count,anchor_ns_per_event=anchored_ns/count,
                    gas_per_event=sum(receipt_gas)/count if len(receipt_gas)==len(batches) else None,
                    gas_source='measured Anvil receipt' if receipt_gas else 'unavailable on in-memory test double'))
    return rows


def fi_public_replay(options: Options) -> list[dict]:
    """E12 only reports real source observations when the dataset is supplied."""
    from .datasets import replay_times
    from .anchoring import windows
    if not options.dataset_path:
        return [_row('E12','FI',0,type('Backend',(),{'backend':'not-run'})(),
                     status='SKIPPED_NO_PUBLIC_DATASET',events=None,source=None,
                     explanation='Supply --dataset-path with independently obtained LANL CSV/gz/bz2')]
    arrivals,sizes,checksum=replay_times(options.dataset_path,max_events=min(options.event_count,100000))
    rows=[]
    for bound in (1000,5000,10000):
        w=windows(arrivals,batch_size=options.batch_size,max_dwell_ms=5000,max_exposure_ms=bound)
        rows.append(_row('E12','FI',0,type('Backend',(),{'backend':'trace-replay-model'})(),
            status='EXECUTED',events=len(arrivals),source=options.dataset_path,
            source_sha256=checksum,source_bytes=sum(sizes),window_max_ms=bound,
            anchors=len(w),max_wait_ms=max(x.max_wait_ms for x in w),
            note='arrival-time replay only; no EVM gas unless separately run'))
    return rows


def save_rows(run: Path, name: str, rows: list[dict]) -> None:
    if not rows:
        return
    dest = run/'results'/'raw'/f'{name}.csv'
    keys = list(dict.fromkeys(k for row in rows for k in row))
    with dest.open('w',newline='',encoding='utf8') as f:
        writer=csv.DictWriter(f,fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)
    write_jsonl(run/'results'/'raw'/f'{name}.jsonl',rows)
    try:
        import pandas as pd
        pd.DataFrame(rows).to_parquet(run/'results'/'raw'/f'{name}.parquet',index=False)
    except ImportError:
        # Parquet is optional at execution time; do not fake a Parquet file.
        pass


def run_all(run: Path, options: Options) -> dict[str, list[dict]]:
    if not options.base_timestamp:
        options.base_timestamp = utc_now()
    config = vars(options).copy()
    if options.backend not in ('memory','anvil'):
        raise ValueError('unknown backend')
    environment=manifest_metadata(config,'anvil-evm' if options.backend=='anvil' else 'in-memory-test-only')
    if options.backend=='anvil':
        from .ledger import AnvilLedger
        info=AnvilLedger(options.rpc,options.contract_address,options.abi_path)
        environment['evm_client_version']=info.web3.client_version
        environment['evm_chain_id']=int(info.web3.eth.chain_id)
    write_json(run/'environment.json',environment)
    init_chain_snapshot(options)
    suite={}
    for title,fn in (('e1_integrity',integrity),('e2_continuity',continuity),
                     ('e3_overhead',overhead),('e4_tradeoff',tradeoff),
                     ('e5_recovery',recovery),('e6_residual_risk',residual),
                     ('e7_stability',stability),('e8_ct_history_comparison',ct_history_comparison),
                     ('e9_key_compromise',fi_compromise),('e10_exposure',fi_exposure),
                     ('e11_cost_frontier',fi_frontier),('e12_public_replay',fi_public_replay)):
        t0=time.perf_counter_ns()
        try:
            rows=fn(options)
            suite[title]=rows
            save_rows(run,title,rows)
            status={'status':'ok','rows':len(rows),'elapsed_s':(time.perf_counter_ns()-t0)/1e9}
        except Exception as exc:
            status={'status':'failed','error':f'{type(exc).__name__}: {exc}',
                    'elapsed_s':(time.perf_counter_ns()-t0)/1e9}
            write_json(run/'results'/f'{title}_status.json',status)
            raise
        write_json(run/'results'/f'{title}_status.json',status)
    return suite
