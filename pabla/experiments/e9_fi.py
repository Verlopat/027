"""E9_FI experiments."""
from __future__ import annotations
from .common import *

def digest_events(events: list[dict]) -> str:
    from ..protocol import digest, canonical
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
    from ..protocol import verify_pending_batch, verify_batch, public_hex
    from ..keyschedule import EvolvingSigner, private_from_seed
    from ..workloads import rebuild_untrusted
    from ..ct_baseline import CTBaseline
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
        from ..keychain_baseline import issue_chain,verify_chain
        initial,links,_=issue_chain(bytes([trial%256])*32,3)
        rows.append(_row('E9','KEYCHAIN_REFERENCE',trial,
            type('Backend',(),{'backend':'offchain-reference'})(),
            attack='MISSING_TRANSITION',attacker_model='archive-suppression',
            accepted=int(verify_chain(initial,links[:1]+links[2:])),
            verdict='ACCEPT' if verify_chain(initial,links[:1]+links[2:]) else 'REJECT_LINK',
            trust_model='initial signing public key and complete transition archive'))
    return rows



def anchor_race_forged_pending(options: Options, method: str, trial: int,
                               relay_delay_ms: int) -> list[dict]:
    """E9 ANCHOR_RACE_FORGED_PENDING, with independent relay evidence.

    Adversary owns the collector submission credential as a worst-case explicit
    assumption. The Solidity contract does not verify Ed25519, so it may
    immutably anchor a cryptographically INVALID forged FI manifest (DoS).
    The verifier must reject the FI forged artifact; a displaced honest relay
    copy will fail anchor matching, even though its signature was authentic.
    """
    from ..keyschedule import EvolvingSigner, private_from_seed
    from ..workloads import rebuild_untrusted
    from ..relay import WitnessRelay
    n=max(2,min(options.batch_size,24))
    ledger=ledger_for(options)
    collector_id=(f'race-{method}-{trial}-{relay_delay_ms}-{time.time_ns()}' if options.backend=='anvil'
                  else f'race-{method}-{trial}-{relay_delay_ms}')
    signing_key,pk=keypair()
    policy=Policy.for_name(method)
    signer=None
    if policy.forward_integrity:
        signer=EvolvingSigner.create(count=8)
        signer.retain_old_for_ablation=(method=='FI-noerase')
        ledger.register_fi(collector_id,1,signer.root,signer.count,policy_name=method)
    else:
        ledger.register(collector_id,1,pk,policy_name=method)
    collector=Collector(collector_id,1,signing_key,policy,evolving=signer)
    stream=generate_events(2*n,options.seed+trial,collector_id,1,timestamp=options.base_timestamp or utc_now())
    first=collector.collect(stream[:n]);ledger.anchor(first)
    honest=collector.collect(stream[n:])
    relay=WitnessRelay(delivery_delay_ms=relay_delay_ms)
    relay.emit(honest,emitted_ms=100)
    relay.deliver(110)  # theft/anchor race at 110 ms
    witnessed_before=relay.held(collector_id,1,2) is not None
    preflight=relay.verify_held(collector_id,1,2,ledger=ledger,policy=policy,previous=first.manifest)
    forged=copy.deepcopy(honest)
    forged.events[0]['payload']['pid']+=8921
    forged=rebuild_untrusted(forged,policy)
    if policy.forward_integrity:
        # Theft after period 2 was signed reveals period-3 seed. With no
        # erasure the thief ALSO retrieves period-2 seed.
        seed=signer.historical_seeds.get(2) if method=='FI-noerase' else None
        attacker_key=private_from_seed(seed or signer.compromised_current_seed_for_test())
    else:
        attacker_key=signing_key
    forged.signature=sign(attacker_key,forged.manifest_digest)
    assert (forged.manifest_digest,forged.signature)!=(honest.manifest_digest,honest.signature)
    ledger.anchor(forged)  # the contract commits hashes, not Ed25519 signatures
    relay.deliver(100+relay_delay_ms)
    witnessed_after=relay.held(collector_id,1,2)
    fv=verify_complete_history([first,forged],ledger,policy=policy,collector_id=collector_id,epoch=1)
    hv=verify_complete_history([first,witnessed_after or honest],ledger,policy=policy,collector_id=collector_id,epoch=1)
    forged_valid=all(v.status in ('ACCEPT','ACCEPT_WITH_WARNING') for v in fv)
    honest_valid=all(v.status in ('ACCEPT','ACCEPT_WITH_WARNING') for v in hv)
    def _last_failure(vs):
        return next((v for v in vs if v.status.startswith('REJECT_')),vs[-1])
    f=_last_failure(fv);h=_last_failure(hv)
    common=dict(attack='ANCHOR_RACE_FORGED_PENDING',attacker_model='adaptive-stolen-key',
                relay_delay_ms=relay_delay_ms,relay_delivered_before_theft=int(witnessed_before),
                witness_pending_preflight=preflight.status if preflight else 'NOT_DELIVERED',
                forged_anchor_committed=1,
                contract_ed25519_validation=False,
                trust_model='collector can submit commitments; signature verified off-chain')
    return [
        _row('E9',method,trial,ledger,**common,copy='forged',accepted=int(forged_valid),
             verdict=f.status,anomalies=';'.join(f.anomalies)),
        _row('E9',method,trial,ledger,**common,copy='honest-relay',accepted=int(honest_valid),
             verdict=h.status,anomalies=';'.join(h.anomalies),
             availability_failure=int(not honest_valid))]


def anchor_race_trials(options: Options) -> list[dict]:
    """Separate attack family, with no shared attacker state across methods."""
    return [row for trial in range(options.trials)
            for method in ('P1','B4','FI','FI-noerase','FI-nochain')
            for delay in (0,20,100)
            for row in anchor_race_forged_pending(options,method,trial,delay)]


_old_fi_compromise=fi_compromise

def fi_compromise(options: Options) -> list[dict]:
    return _old_fi_compromise(options)+anchor_race_trials(options)


def protected_anchor_race(options: Options, trial: int, relay_delay_ms: int) -> list[dict]:
    """E9 witness-protected FI, with a collector/submitter-compromise attempt.

    Attackers can possess collector Ed25519 key material and the normal EVM
    submitter credential, but NOT the independently administered witness EVM
    account or relay signing key. The attack must fail at *submission*, leaving
    the anchor slot free. Once the legitimate copy arrives it can be anchored.
    """
    from ..relay import WitnessRelay
    from ..keyschedule import EvolvingSigner, private_from_seed
    from ..workloads import rebuild_untrusted
    n=max(2,min(options.batch_size,24))
    ledger=ledger_for(options)
    collector_id=(f'protected-race-{trial}-{relay_delay_ms}-{time.time_ns()}'
                  if options.backend=='anvil' else f'protected-race-{trial}-{relay_delay_ms}')
    sk,_=keypair()
    policy=Policy.for_name('FI')
    schedule=EvolvingSigner.create(count=8)
    relay=WitnessRelay(delivery_delay_ms=relay_delay_ms)
    ledger.register_fi(collector_id,1,schedule.root,schedule.count,
                       policy_name='FI',witness_public_key=relay.public_key)
    collector=Collector(collector_id,1,sk,policy,evolving=schedule)
    ev=generate_events(2*n,options.seed+trial,collector_id,1,timestamp=options.base_timestamp or utc_now())
    first=collector.collect(ev[:n])
    relay.emit(first,emitted_ms=0)
    relay.deliver(relay_delay_ms)
    relay.anchor_held(collector_id,1,1,ledger=ledger,policy=policy,previous=None)
    honest=collector.collect(ev[n:])
    relay.emit(honest,emitted_ms=100)
    relay.deliver(110)
    in_custody_at_attack=relay.held(collector_id,1,2) is not None
    forged=copy.deepcopy(honest)
    forged.events[0]['payload']['pid']+=8921
    forged=rebuild_untrusted(forged,policy)
    thief=private_from_seed(schedule.compromised_current_seed_for_test())
    forged.signature=sign(thief,forged.manifest_digest)
    try:
        ledger.anchor(forged)  # attacker controls collector EVM submitter, NOT witness
    except ProtocolError as exc:
        submit_status='REJECT_SUBMISSION'
        submit_reason=str(exc)
    else:
        raise AssertionError('compromised collector filled a witness-protected FI anchor slot')
    # The honest relay must be able to finish after its configured delay;
    # reporting that it is absent earlier is latency, not irreversible loss.
    relay.deliver(100+relay_delay_ms)
    receipt=relay.anchor_held(collector_id,1,2,ledger=ledger,
                              policy=policy,previous=first.manifest)
    honest_results=verify_complete_history([first,honest],ledger,policy=policy,
                                             collector_id=collector_id,epoch=1)
    forged_results=verify_complete_history([first,forged],ledger,policy=policy,
                                             collector_id=collector_id,epoch=1)
    honest_ok=all(x.status=='ACCEPT' for x in honest_results)
    forged_ok=all(x.status=='ACCEPT' for x in forged_results)
    if not honest_ok or forged_ok:
        raise AssertionError('witness-protected race did not preserve honest custody')
    common=dict(attack='ANCHOR_RACE_FORGED_PENDING',attacker_model='collector-and-submitter-compromise',
                relay_delay_ms=relay_delay_ms,
                relay_delivered_before_theft=int(in_custody_at_attack),
                forged_anchor_committed=0,trust_model='independent witness EVM submitter + validated relay custody',
                witness_protection=True,independent_witness_compromised=False,
                honest_anchor_block=receipt['block_number'],
                submit_reason=submit_reason)
    return [_row('E9','FI+WITNESS',trial,ledger,**common,copy='forged',accepted=0,
                 verdict=submit_status,availability_failure=0),
            _row('E9','FI+WITNESS',trial,ledger,**common,copy='honest-relay',accepted=1,
                 verdict=honest_results[-1].status,availability_failure=0)]


_legacy_anchor_race_trials=anchor_race_trials

def anchor_race_trials(options: Options) -> list[dict]:
    rows=_legacy_anchor_race_trials(options)
    for trial in range(options.trials):
        for delay in (0,20,100):
            rows.extend(protected_anchor_race(options,trial,delay))
    return rows
