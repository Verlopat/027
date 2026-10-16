"""E10_E12 experiments."""
from __future__ import annotations
from .common import *

def fi_exposure(options: Options) -> list[dict]:
    """E10: exact event-exposure counts at controlled compromise times."""
    from ..anchoring import windows,exposed_events,exposed_interval_ms
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
    from ..anchoring import windows
    from ..keyschedule import EvolvingSigner
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
    from ..datasets import replay_times
    from ..anchoring import windows
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



def measured_compromise(options: Options, *, method: str, trial: int, bound_ms: int,
                         relay_delay_ms: int, anchor_confirmation_ms: int = 80) -> dict:
    """Run signing, ledger anchoring, relay delivery and attack verification.

    Synthetic clock controls when operations become eligible, not the local
    blockchain's actual confirmation latency. Counts are determined by actual
    verifier outcomes and relay custody, with a separately calculated model.
    """
    from dataclasses import replace
    from ..relay import WitnessRelay
    from ..anchoring import windows
    from ..workloads import rebuild_untrusted
    from ..keyschedule import EvolvingSigner, private_from_seed
    count=min(options.event_count,500)
    rng=random.Random(options.seed+trial+bound_ms)
    arrivals=[];now=0
    for _ in range(count):
        now+=rng.choice((1,1,2,7,15,30))
        arrivals.append(now)
    batch_size=min(max(2,options.batch_size),count)
    schedule=windows(arrivals,batch_size=batch_size,max_dwell_ms=bound_ms,max_exposure_ms=bound_ms)
    # Sample at deterministic random compromise times. Include an open window.
    theft_ms=rng.randint(0,arrivals[-1]+bound_ms)
    ledger=ledger_for(options)
    source=(f'measure-{trial}-{bound_ms}-{relay_delay_ms}-{method}-{time.time_ns()}'
            if options.backend=='anvil' else f'measure-{trial}-{bound_ms}-{relay_delay_ms}-{method}')
    sk,pk=keypair();policy=Policy.for_name(method)
    signer=None
    if policy.forward_integrity:
        signer=EvolvingSigner.create(count=max(2,len(schedule)+1))
        signer.retain_old_for_ablation=method=='FI-noerase'
        ledger.register_fi(source,1,signer.root,signer.count,policy_name=method)
    else:
        ledger.register(source,1,pk,policy_name=method)
    c=Collector(source,1,sk,policy,evolving=signer)
    data=generate_events(count,options.seed+trial,source,1,timestamp=options.base_timestamp or utc_now())
    witness=WitnessRelay(delivery_delay_ms=relay_delay_ms)
    signed=[];anchored=[]
    for w in schedule:
        issued_ms=w.confirmed_ms  # idealized signature/flush timestamp
        if issued_ms>theft_ms:
            break
        b=c.collect(data[w.first_index:w.last_index+1])
        witness.emit(b,emitted_ms=issued_ms)
        signed.append((w,b))
        if issued_ms+anchor_confirmation_ms<=theft_ms:
            ledger.anchor(b)
            anchored.append((w,b))
    witness.deliver(theft_ms)
    signed_events=sum(w.count for w,_ in signed)
    occurred=sum(t<=theft_ms for t in arrivals)
    unsigned_events=max(0,occurred-signed_events)
    modification_measured=unsigned_events
    suppression_measured=unsigned_events
    pending_events=0
    accepted_forged_pending=0
    resig_allowed=method in ('P1','B4','FI-noerase')
    anchored_count=len(anchored)
    for i,(w,honest) in enumerate(signed):
        if i<anchored_count:continue
        pending_events+=w.count
        delivered=witness.held(source,1,honest.manifest['batch_number']) is not None
        rewritten=copy.deepcopy(honest)
        rewritten.events[0]['payload']['pid']+=30000
        rewritten=rebuild_untrusted(rewritten,policy)
        if policy.forward_integrity:
            old=signer.historical_seeds.get(honest.manifest['period']) if method=='FI-noerase' else None
            attacker=private_from_seed(old or signer.compromised_current_seed_for_test())
        else:
            attacker=sk
        rewritten.signature=sign(attacker,rewritten.manifest_digest)
        previous=signed[i-1][1].manifest if i else None
        v=verify_batch(rewritten,ledger,policy=replace(policy,anchor=False),previous=previous)
        forged_valid=v.status in ('ACCEPT','ACCEPT_WITH_WARNING')
        accepted_forged_pending+=int(forged_valid)
        if forged_valid and not delivered:
            modification_measured+=w.count
        if not delivered:
            suppression_measured+=w.count
    # The model uses only independently recorded custody, issue times, and
    # whether an attacker holds the relevant *period* key. It does not use
    # the verifier's decision or measured counts.
    predicted_mod=unsigned_events+sum(w.count for w,b in signed[anchored_count:]
        if resig_allowed and witness.held(source,1,b.manifest['batch_number']) is None)
    predicted_suppress=unsigned_events+sum(w.count for w,b in signed[anchored_count:]
        if witness.held(source,1,b.manifest['batch_number']) is None)
    # Check anchored honest history via the real verifier before reporting.
    archived=[b for w,b in anchored]
    vv=verify_complete_history(archived,ledger,policy=policy,collector_id=source,epoch=1)
    if any(v.status.startswith('REJECT_') for v in vv):
        raise AssertionError(f'valid anchored history unexpectedly failed: {vv}')
    return _row('E10',method,trial,ledger,window_max_ms=bound_ms,
        relay_delay_ms=relay_delay_ms,anchor_confirmation_model_ms=anchor_confirmation_ms,
        compromise_ms=theft_ms,observed_events=occurred,signed_events=signed_events,
        anchored_events=sum(w.count for w,_ in anchored),pending_events=pending_events,
        modification_exposed_measured=modification_measured,
        suppression_exposed_measured=suppression_measured,
        modification_exposed_model=predicted_mod,
        suppression_exposed_model=predicted_suppress,
        forged_pending_verifier_accepts=accepted_forged_pending,
        witness_receipts=len(witness._receipts),
        measurement='real collector/relay/verifier with synthetic operation times',
        simulation_caveat='not a measured EVM confirmation-time distribution')


_old_fi_exposure=fi_exposure

def fi_exposure(options: Options) -> list[dict]:
    """E10 primary rows now originate from actual verifier attack trials."""
    rows=[]
    for trial in range(options.trials):
        for method in ('FI','FI-noerase','P1'):
            for bound in (50,200,1000):
                # Three relay latencies give distinct custody windows.
                for delay in (0,100):
                    result=measured_compromise(options,method=method,trial=trial,
                                               bound_ms=bound,relay_delay_ms=delay)
                    if result['modification_exposed_measured']!=result['modification_exposed_model'] or result['suppression_exposed_measured']!=result['suppression_exposed_model']:
                        raise AssertionError('measured E10 exposure disagrees with independent custody model')
                    rows.append(result)
    return rows
