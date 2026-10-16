"""Modular experiments E1-E12, with backwards compatible public API."""
from __future__ import annotations
from .common import *
from .e1_e8 import integrity, continuity, overhead, tradeoff, recovery, residual, stability, ct_history_comparison
from .e9_fi import digest_events, fi_compromise
from .e10_e12 import fi_exposure, fi_frontier, fi_public_replay

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
        from ..ledger import AnvilLedger
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

