"""Reproducible v2 smoke run; only actual local executions are recorded.

Use --gas-csv with a user-provided public gas-price trace. Missing real data,
Solidity compilation and full campaigns are marked not-run, never simulated.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,os,platform,random,sys,tempfile,time
from pathlib import Path
from .crypto import sha,secret_for_state,sign_digest,FSState
from .schedule import Schedule
from .checkpoint import Checkpoint,Sealed
from .collector import Collector
from .ledger import MemoryLedger
from .verifier import verify_full
from .witness import Witness
from .tree import log_leaf,consistency_proof
from .scheduling import optimal_anchor_times,online_greedy,online_reservation,valid_schedule
from .evidence import EquivocationProof
from .windows import EventTimes,predict
from .attacks import sampled_window_probe
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def unique_run(base:Path)->Path:
    base.mkdir(parents=True,exist_ok=True)
    i=1
    while True:
        p=base/f'v2test{i}'
        try:p.mkdir();return p
        except FileExistsError:i+=1

def atomic_json(path:Path,doc)->None:
    with path.open('w',encoding='utf8') as f:json.dump(doc,f,indent=2,sort_keys=True,default=str)

def execute(run:Path,*,seed:int,events:int,gas_csv:str='')->dict:
    if not 1<=events<=100_000:raise ValueError('smoke supports 1..100000 events')
    rng=random.Random(seed)
    schedule_seed=sha(f'LOCAL-TEST-SEED-{seed}'.encode())
    schedule=Schedule.setup(schedule_seed,height=4)
    collector_id=sha(b'pabla-v2-smoke-collector')
    collector=Collector(run/'collector.sqlite',collector_id,1,schedule.public,schedule_seed)
    witness=Witness(run/'witness.sqlite',schedule.public,Ed25519PrivateKey.generate())
    ledger=MemoryLedger();ledger.register(collector_id,1,schedule.public)
    sample=[];t0=time.perf_counter_ns()
    for i in range(events):
        ev={'event_id':str(i),'arrival_ms':i*10,'type':rng.choice(('ssh','process','dns','flow')),
            'severity':rng.randrange(5),'payload':{'bytes':rng.randrange(500,2500)}}
        collector.append(ev)
    cp1=collector.seal(1000)
    result1=witness.submit(cp1,wall_ms=1001)
    ledger.anchor(cp1)
    current_seed=collector._signer.snapshot_for_tests() # attack harness only
    for i in range(events//2):
        collector.append({'event_id':f'follow-{i}','type':'dns','payload':{'bytes':rng.randrange(300,600)}})
    cp2=collector.seal(2000)
    records=collector.export_events();seals=collector.export_seals()
    ct=consistency_proof([log_leaf(x) for x in records],cp1.checkpoint.size)
    result2=witness.submit(cp2,ct,wall_ms=2001)
    ledger.anchor(cp2)
    verified=verify_full(records,seals,schedule.public,collector=collector_id,epoch=1,
                         anchors=ledger.anchors(collector_id,1))
    assert result1[0]=='COSIGNED' and result2[0]=='COSIGNED' and verified.accepted()
    # Build an adaptive same-period fork using exactly the period-2 stolen seed.
    cp=cp2.checkpoint
    counterfeit=Checkpoint(cp.collector,cp.epoch,cp.period,cp.size,sha(b'counterfeit-root'),
                           cp.prev,cp.wall_ms,cp.schedule_root)
    forged=Sealed(counterfeit,sign_digest(secret_for_state(current_seed),counterfeit.digest()),cp2.key_proof)
    forged_view=[cp1,forged]
    forged_verdict=verify_full(records,forged_view,schedule.public,collector=collector_id,
                               epoch=1,anchors=ledger.anchors(collector_id,1))
    witness_status,proof=witness.submit(forged,ct,wall_ms=2002)
    assert witness_status=='EQUIVOCATION' and proof is not None and proof.valid(schedule.public)
    assert not forged_verdict.accepted()
    fraud_accepted=ledger.prove_equivocation(proof)
    elapsed=time.perf_counter_ns()-t0
    prices=[rng.randint(1,100) for _ in range(90)] # labelled SYNTHETIC, not public gas
    source='synthetic'
    input_digest=None
    if gas_csv:
        data=Path(gas_csv).read_bytes();input_digest=hashlib.sha256(data).hexdigest()
        parsed=[]
        with Path(gas_csv).open(newline='',encoding='utf8') as f:
            for line in csv.DictReader(f):parsed.append(float(line['price']))
        if not parsed:raise ValueError('empty gas CSV')
        prices=parsed;source='external-user-provided'
    deadline=7
    optimum,times=optimal_anchor_times(prices,deadline)
    greedy=online_greedy(prices,deadline)
    reservation=online_reservation(prices,deadline,min(prices),max(prices))
    assert valid_schedule(times,len(prices),deadline)
    assert valid_schedule(greedy,len(prices),deadline)
    assert valid_schedule(reservation,len(prices),deadline)
    cases=[EventTimes(str(i),i*10,1000,1001,1002) for i in range(events)]
    model=predict(cases,500)
    # X3 controlled probe: adversary mutates evidence and calls the real verifier
    # on each sampled compromise time; analytic predictions remain independent.
    sample_size=min(events,32)
    attack_events=records[:sample_size]
    arrival_times=[i*10 for i in range(sample_size)]
    seal_at=max(arrival_times)+10
    witness_at=seal_at+25
    anchor_at=seal_at+60
    samples=sorted(set([0,seal_at-1,seal_at,witness_at,anchor_at] +
                       [rng.randrange(anchor_at+20) for _ in range(24)]))
    actual=sampled_window_probe(Schedule.setup(schedule_seed,height=4),attack_events,
                      arrival_times,seal_at,witness_at,anchor_at,samples)
    window_rows=[]
    for outcome in actual:
        t=outcome['time_ms']
        pred=predict([EventTimes(str(i),a,seal_at,witness_at,anchor_at)
                      for i,a in enumerate(arrival_times)],t)
        window_rows.append({**outcome,'modification_predicted':pred.modification,
                             'silent_predicted':pred.silent_suppression,
                             'unprovable_predicted':pred.unprovable_suppression,
                             'measurement_type':'simulated-compromise-with-real-verifier',
                             'backend':'memory-test-double'})
    with (run/'x03_windows.csv').open('w',newline='',encoding='utf8') as f:
        writer=csv.DictWriter(f,fieldnames=list(window_rows[0]));writer.writeheader();writer.writerows(window_rows)
    violations=sum(1 for r in window_rows if r['modification_measured']>r['modification_predicted'] or
        r['silent_measured']>r['silent_predicted'] or r['unprovable_measured']>r['unprovable_predicted'])
    report={
        'backend':'memory-test-double', 'events':len(records),'signed_periods':len(seals),
        'honest_verification':verified.status,'adaptive_fork_verification':forged_verdict.status,
        'witness_equivocation':witness_status,'fraud_proof_valid':fraud_accepted,
        'crypto_and_execution_elapsed_ns':elapsed,
        'window_model_example':model.__dict__,
        'x03_probes':len(window_rows),'x03_bound_violations':violations,
        'x03_file':'x03_windows.csv',
        'scheduling':{'price_source':source,'input_sha256':input_digest,'deadline_slots':deadline,
                      'price_slots':len(prices),'offline_cost':optimum,'offline_slots':times,
                      'greedy_cost':sum(prices[t] for t in greedy),
                      'reservation_cost':sum(prices[t] for t in reservation)},
        'not_run':['live_evm_gas','external_journald_baseline','tessera_baseline',
                   'two_machine_replication','full_x01_x12_campaign','independent_formal_review']}
    atomic_json(run/'report.json',report)
    from .envcapture import capture
    atomic_json(run/'environment.json',dict(capture(),seed=seed,source='local-reference-execution'))
    witness.close();collector.close()
    return report

def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description='PABLA-v2 reference execution')
    p.add_argument('--output',default='output');p.add_argument('--seed',type=int,default=74912)
    p.add_argument('--events',type=int,default=32);p.add_argument('--gas-csv',default='')
    args=p.parse_args(argv)
    run=unique_run(Path(args.output))
    try:
        result=execute(run,seed=args.seed,events=args.events,gas_csv=args.gas_csv)
        print(json.dumps({'directory':str(run),'status':'ok','results':result},indent=2))
        return 0
    except Exception as exc:
        atomic_json(run/'failure.json',{'error':f'{type(exc).__name__}: {exc}'})
        raise
if __name__=='__main__':raise SystemExit(main())
