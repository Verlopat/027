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
            groups[(exp,row['method'],row['attack'])].append(row)
    detection=[]
    for (experiment,method,attack), rows in sorted(groups.items()):
        k=sum(int(row['detected']) for row in rows)
        low,high=exact_ci(k,len(rows))
        detection.append({'experiment':experiment,'method':method,'attack':attack,'n':len(rows),
                          'detected':k,'coverage':k/len(rows),'ci95_low':low,'ci95_high':high,
                          'is_valid_case':attack=='NONE'})
    summary={'detection':detection,'timings':{},'paired_tests':[]}
    for exp in ('e3_overhead','e4_tradeoff','e7_stability'):
        values=defaultdict(list)
        for row in suite.get(exp,[]):
            for key in ('build_ns_per_event','verify_ns_per_event','elapsed_ns','tx_per_event'):
                if isinstance(row.get(key),(int,float)):
                    values[(row['method'],key)].append(row[key])
        for (method,key),sample in values.items():
            lo,hi=bootstrap_median_ci(sample)
            summary['timings'][f'{exp}/{method}/{key}']={'n':len(sample),
                'median':statistics.median(sample), 'mean':statistics.mean(sample),
                'std':statistics.stdev(sample) if len(sample)>1 else None,'ci95_median':[lo,hi],
                'cv':statistics.stdev(sample)/statistics.mean(sample) if len(sample)>1 and statistics.mean(sample)!=0 else None}
    for exp in ('e1_integrity','e2_continuity'):
        exp_rows=suite.get(exp,[])
        attacks=sorted({r['attack'] for r in exp_rows if r['attack']!='NONE'})
        for attack in attacks:
            p1={r['trial']:r['detected'] for r in exp_rows if r['method']=='P1' and r['attack']==attack}
            for baseline in ('B1','B2','B3','B4'):
                b={r['trial']:r['detected'] for r in exp_rows if r['method']==baseline and r['attack']==attack}
                common=sorted(set(p1)&set(b))
                if common:
                    summary['paired_tests'].append({'experiment':exp,'attack':attack,'method':'P1','baseline':baseline,
                        'n_pairs':len(common),'p':mcnemar_p([p1[i] for i in common],[b[i] for i in common])})
    adjusted=holm([r['p'] for r in summary['paired_tests']])
    for row,p in zip(summary['paired_tests'],adjusted):
        row['holm_p']=p
    write_json(run/'results'/'derived'/'summary.json',summary)
    _write_table(run/'results'/'derived'/'detection.csv',detection)
    _write_table(run/'results'/'derived'/'paired_comparisons.csv',summary['paired_tests'])
    return summary


def _write_table(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    with path.open('w', newline='',encoding='utf8') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def figures(run: Path, summary: dict) -> list[str]:
    # Vector plots correspond to actual rows, including the memory backend label.
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    outputs=[]
    rows=[r for r in summary['detection'] if r['method'] in ('P1','B1','B2','B3','B4') and r['attack']!='NONE']
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
    return outputs
