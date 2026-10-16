"""Quantitative summaries based exclusively on executed, labelled trials."""
from __future__ import annotations
import csv
import math
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any
from .storage import write_json


def exact_ci(k: int, n: int, alpha: float = .05) -> tuple[float,float]:
    if n == 0:
        return (float('nan'),float('nan'))
    from scipy.stats import beta
    return (0.0 if k==0 else float(beta.ppf(alpha/2,k,n-k+1)),
            1.0 if k==n else float(beta.ppf(1-alpha/2,k+1,n-k)))


def mcnemar_p(a: list[int], b: list[int]) -> float:
    from scipy.stats import binomtest
    if len(a) != len(b):
        raise ValueError('paired observations required')
    n10 = sum(x==1 and y==0 for x,y in zip(a,b))
    n01 = sum(x==0 and y==1 for x,y in zip(a,b))
    return float(binomtest(min(n10,n01),n10+n01,p=.5).pvalue) if n10+n01 else 1.0


def holm(pvalues: list[float]) -> list[float]:
    ordered = sorted(range(len(pvalues)),key=lambda i:pvalues[i])
    corrected=[0.0]*len(pvalues)
    running=0.0
    for rank,i in enumerate(ordered):
        running=max(running,min(1.0,(len(pvalues)-rank)*pvalues[i]))
        corrected[i]=running
    return corrected


def bootstrap_median_ci(values: list[float], seed: int = 1729, repetitions: int = 2000) -> tuple[float,float]:
    import random
    if not values:
        return (float('nan'),float('nan'))
    rng=random.Random(seed)
    medians=sorted(statistics.median(rng.choices(values,k=len(values))) for _ in range(repetitions))
    return (medians[int(.025*repetitions)],medians[int(.975*repetitions)-1])


def aggregate(suite: dict[str,list[dict]], run: Path) -> dict:
    groups=defaultdict(list)
    for exp in ('e1_integrity','e2_continuity'):
        for row in suite.get(exp,[]):
            groups[(exp,row['method'],row['attack'],row.get('attacker_model','unspecified'))].append(row)
    detection=[]
    for (experiment,method,attack,model), rows in sorted(groups.items()):
        k=sum(int(row['detected']) for row in rows)
        detection.append({'experiment':experiment,'method':method,'attack':attack,'attacker_model':model,
                          'cases':len(rows),'detected':k,'coverage':k/len(rows),
                          'inference':'deterministic observed test cases, no binomial CI or p-value',
                          'is_valid_case':attack=='NONE'})
    e9 = [r for r in suite.get('e9_key_compromise',[]) if r.get('attack')]
    e10 = suite.get('e10_exposure',[])
    e11 = suite.get('e11_cost_frontier',[])
    e12 = suite.get('e12_public_replay',[])
    summary={'detection':detection,'timings':{},'paired_tests':[],
             'fi_attack_matrix':e9,'fi_exposure':e10,'fi_cost_frontier':e11,
             'public_replay':e12}
    _write_table(run/'results'/'derived'/'fi_security_matrix.csv',e9)
    _write_table(run/'results'/'derived'/'fi_exposure.csv',e10)
    _write_table(run/'results'/'derived'/'fi_cost_frontier.csv',e11)
    for exp in ('e3_overhead','e4_tradeoff','e7_stability','e8_ct_history_comparison','e11_cost_frontier'):
        values=defaultdict(list)
        for row in suite.get(exp,[]):
            for key in ('build_ns_per_event','verify_ns_per_event','construction_ns_per_event','verification_ns_per_event','anchor_ns_per_event','gas_per_event','elapsed_ns','tx_per_event'):
                if isinstance(row.get(key),(int,float)):
                    values[(row['method'],key)].append(row[key])
        for (method,key),sample in values.items():
            lo,hi=bootstrap_median_ci(sample)
            summary['timings'][f'{exp}/{method}/{key}']={'n':len(sample),
                'median':statistics.median(sample), 'mean':statistics.mean(sample),
                'std':statistics.stdev(sample) if len(sample)>1 else None,'ci95_median':[lo,hi],
                'cv':statistics.stdev(sample)/statistics.mean(sample) if len(sample)>1 and statistics.mean(sample)!=0 else None}
    # Security outcomes are deterministic conditional on an input; treating random
    # payload seeds as independent Bernoulli experiments is pseudoreplication.
    # Do not publish McNemar p-values/Clopper-Pearson intervals on those rows.
    summary['paired_tests'] = []
    write_json(run/'results'/'derived'/'summary.json',summary)
    _write_table(run/'results'/'derived'/'detection.csv',detection)
    # No significance test for deterministic attack classifications.
    return summary


def _write_table(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    with path.open('w', newline='',encoding='utf8') as f:
        writer=csv.DictWriter(f,fieldnames=list(dict.fromkeys(k for row in rows for k in row)))
        writer.writeheader()
        writer.writerows(rows)


def figures(run: Path, summary: dict) -> list[str]:
    # Vector plots correspond to actual rows, including the memory backend label.
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    outputs=[]
    rows=[r for r in summary['detection'] if r['method'] in ('P1','B1','B2','B3','B4') and r['attack']!='NONE' and r['attacker_model']=='adaptive']
    if rows:
        fig,ax=plt.subplots(figsize=(12,5))
        attack_labels=sorted({r['attack'] for r in rows})
        methods=('P1','B1','B2','B3','B4')
        width=.16
        for j,method in enumerate(methods):
            selected={(r['attack'],r['method']):r for r in rows}
            x=[i+(j-2)*width for i in range(len(attack_labels))]
            vals=[selected.get((a,method),{}).get('coverage',float('nan')) for a in attack_labels]
            ax.bar(x,vals,width,label=method)
        ax.set_xticks(range(len(attack_labels)),attack_labels)
        ax.set_ylim(0,1.05)
        ax.set_ylabel('Observed anomaly detection proportion')
        ax.legend(ncol=5)
        ax.set_title('Executed synthetic attack trials (not population detection guarantee)')
        fig.tight_layout()
        for ext in ('svg','pdf'):
            output=run/'figures'/f'F1_detection.{ext}'
            fig.savefig(output)
            outputs.append(str(output))
        plt.close(fig)
    ticks=[];values=[]
    for key,row in sorted(summary['timings'].items()):
        if key.startswith('e3_overhead/') and key.endswith('/tx_per_event'):
            ticks.append(key.split('/')[1]);values.append(row['median'])
    if ticks:
        fig,ax=plt.subplots(figsize=(7,4))
        ax.bar(ticks,values)
        ax.set_ylabel('Recorded anchor calls / event')
        ax.set_title('E3 transaction calls (see backend label in raw CSV)')
        fig.tight_layout()
        for ext in ('svg','pdf'):
            output=run/'figures'/f'F2_anchors.{ext}';fig.savefig(output);outputs.append(str(output))
        plt.close(fig)
    fi=summary.get('fi_attack_matrix',[])
    attack='REWRITE_PREVIOUS_SIGNED_PENDING_PERIOD'
    selected=[r for r in fi if r.get('attack')==attack and r.get('attacker_model')=='stolen-current-key']
    if selected:
        groups=defaultdict(list)
        for r in selected:groups[r['method']].append(int(r['accepted']))
        labels=sorted(groups)
        fractions=[statistics.mean(groups[m]) for m in labels]
        fig,ax=plt.subplots(figsize=(9,4))
        ax.bar(labels,fractions)
        ax.set_ylim(0,1.05)
        ax.set_ylabel('Accepted forged pending archives / executed cases')
        ax.set_title('E9 previously signed, unanchored period after key theft')
        fig.tight_layout()
        for ext in ('svg','pdf'):
            output=run/'figures'/f'F9_forward_integrity.{ext}'
            fig.savefig(output);outputs.append(str(output))
        plt.close(fig)
    exposure=summary.get('fi_exposure',[])
    if exposure:
        fig,ax=plt.subplots(figsize=(7,5))
        for method in sorted(set(r['method'] for r in exposure)):
            sample=[r for r in exposure if r['method']==method]
            ax.scatter([r['modification_exposed_model'] for r in sample],
                       [r['modification_exposed_measured'] for r in sample],label=method)
        mx=max([r['modification_exposed_model'] for r in exposure]+[1])
        ax.plot([0,mx],[0,mx],linestyle='--')
        ax.set_xlabel('Independent custody/key model: modifiable events')
        ax.set_ylabel('Executed attacker/verifier: modifiable events')
        ax.set_title('E10 measured modification exposure vs independent model')
        ax.legend()
        fig.tight_layout()
        for ext in ('svg','pdf'):
            output=run/'figures'/f'F10_exposure.{ext}'
            fig.savefig(output);outputs.append(str(output))
        plt.close(fig)
        fig,ax=plt.subplots(figsize=(7,5))
        for method in sorted(set(r['method'] for r in exposure)):
            sample=[r for r in exposure if r['method']==method]
            ax.scatter([r['suppression_exposed_model'] for r in sample],
                       [r['suppression_exposed_measured'] for r in sample],label=method)
        mx=max([r['suppression_exposed_model'] for r in exposure]+[1])
        ax.plot([0,mx],[0,mx],linestyle='--')
        ax.set_xlabel('Independent custody model: suppressible events')
        ax.set_ylabel('Executed relay/ledger: suppressible events')
        ax.set_title('E10 suppression exposure, unanchored and un-witnessed')
        ax.legend()
        fig.tight_layout()
        for ext in ('svg','pdf'):
            output=run/'figures'/f'F10_suppression.{ext}'
            fig.savefig(output);outputs.append(str(output))
        plt.close(fig)
    race=[r for r in fi if r.get('attack')=='ANCHOR_RACE_FORGED_PENDING' and r.get('copy')=='forged']
    if race:
        groups=defaultdict(list)
        for r in race:groups[r['method']].append(int(r['accepted']))
        fig,ax=plt.subplots(figsize=(8,4))
        ax.bar(sorted(groups),[statistics.mean(groups[m]) for m in sorted(groups)])
        ax.set_ylim(0,1.05)
        ax.set_ylabel('Forged batches accepted / exercised races')
        ax.set_title('E9 anchor race: accepted *forgery* (not availability)')
        fig.tight_layout()
        for ext in ('svg','pdf'):
            output=run/'figures'/f'F9_anchor_race.{ext}'
            fig.savefig(output);outputs.append(str(output))
        plt.close(fig)
    frontier=summary.get('fi_cost_frontier',[])
    if frontier:
        # Transaction calls are measured in both adapters. EVM gas is shown
        # only when every plotted row contains an actual gas receipt.
        has_gas=all(isinstance(r.get('gas_per_event'),(int,float)) for r in frontier)
        y='gas_per_event' if has_gas else 'anchor_calls_per_event'
        fig,ax=plt.subplots(figsize=(7,5))
        for mode in sorted({r['mode'] for r in frontier}):
            series=[r for r in frontier if r['mode']==mode]
            ax.scatter([r['observed_max_wait_ms'] for r in series],
                       [r[y] for r in series],label=mode)
        ax.set_xlabel('Maximum simulated event-to-anchor wait (ms)')
        ax.set_ylabel('Measured gas per event' if has_gas else 'Executed anchor calls per event (not gas)')
        ax.set_title('E11 measured cost characterization (no optimization claim)')
        ax.legend()
        fig.tight_layout()
        for ext in ('svg','pdf'):
            output=run/'figures'/f'F11_cost_frontier.{ext}'
            fig.savefig(output);outputs.append(str(output))
        plt.close(fig)
    return outputs
