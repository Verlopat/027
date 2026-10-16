"""Isolated subprocess entrypoint for per-trial RSS/CPU measurements."""
from __future__ import annotations
import json
import resource
import sys
import time
from .experiments import Options, _make

def main() -> None:
    settings=json.loads(sys.argv[1])
    options=Options(backend=settings['backend'],rpc=settings['rpc'],
                    contract_address=settings['contract_address'],abi_path=settings['abi_path'],
                    batch_size=settings['batch_size'],event_count=settings['count'],
                    seed=settings['seed'],base_timestamp=settings['base_timestamp'])
    snapshot=None
    if options.backend=='anvil':
        from .ledger import AnvilLedger
        ledger=AnvilLedger(options.rpc,options.contract_address,options.abi_path)
        snapshot=ledger.web3.provider.make_request('evm_snapshot',[]).get('result')
        if not snapshot:
            raise RuntimeError('E7 Anvil snapshot failed')
    start=resource.getrusage(resource.RUSAGE_SELF)
    t0=time.perf_counter_ns()
    ledger, collector, batches, receipts, build_ns, verify_ns=_make(
        options, settings['method'], settings['seed'],settings['count'],settings['batch_size'])
    end=resource.getrusage(resource.RUSAGE_SELF)
    elapsed=time.perf_counter_ns()-t0
    if snapshot is not None:
        if ledger.web3.provider.make_request('evm_revert',[snapshot]).get('result') is not True:
            raise RuntimeError('E7 Anvil snapshot restore failed')
    print(json.dumps({'elapsed_ns':elapsed,'build_ns':build_ns,
          'anchor_ns':ledger.measurement_anchor_ns,'verify_ns':verify_ns,
          'user_cpu_s':end.ru_utime-start.ru_utime,'system_cpu_s':end.ru_stime-start.ru_stime,
          'max_rss_kb':end.ru_maxrss,'units':'KiB (Linux ru_maxrss)'}))

if __name__ == '__main__':
    main()
