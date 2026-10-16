"""PABLA experiment suite: modular, executable measurements."""
from __future__ import annotations
import copy, csv, json, math, os, random, resource, statistics, time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from ..ledger import InMemoryLedger
from ..protocol import Collector, Policy, ProtocolError, Batch, keypair, manifest_hash, sign, utc_now, verify_batch, verify_history, verify_complete_history
from ..storage import RunIndex, archive_size, manifest_metadata, save_batch, write_json, write_jsonl
from ..workloads import attack_batch, adaptive_attack_batch, adaptive_reissue_history, generate_events

METHODS = ('P1', 'B1', 'B2', 'B3', 'B4', 'A1', 'A2', 'A3', 'A4', 'A5')
ATTACKS = ('AT1', 'AT2', 'AT3', 'AT4', 'AT5', 'AT6', 'AT7', 'AT8', 'AT9', 'AT10')
_ANVIL_SNAPSHOT: dict[str, Any] = {}

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


def init_chain_snapshot(options: Options) -> None:
    """Take a stable post-deployment (and post-smoke) Anvil state snapshot.

    Snapshot/revert is an experimental reset, not Ethereum transaction finality.
    """
    global _ANVIL_SNAPSHOT
    if options.backend != 'anvil':
        _ANVIL_SNAPSHOT = {}
        return
    from ..ledger import AnvilLedger
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
        from ..ledger import AnvilLedger
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
        from ..keyschedule import EvolvingSigner
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


__all__ = ['copy', 'csv', 'json', 'math', 'os', 'random', 'resource', 'statistics', 'time', 'dataclass', 'Path', 'Any', 'InMemoryLedger', 'Collector', 'Policy', 'ProtocolError', 'Batch', 'keypair', 'manifest_hash', 'sign', 'utc_now', 'verify_batch', 'verify_history', 'verify_complete_history', 'RunIndex', 'archive_size', 'manifest_metadata', 'save_batch', 'write_json', 'write_jsonl', 'attack_batch', 'adaptive_attack_batch', 'adaptive_reissue_history', 'generate_events', 'METHODS', 'ATTACKS', '_ANVIL_SNAPSHOT', 'Options', 'init_chain_snapshot', 'ledger_for', '_make', '_row', '_record_status']
