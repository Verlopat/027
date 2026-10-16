"""Reproducible and honest campaign runner; unsupported experiments are NOT RUN.

Every cell executes in a fresh subprocess with separate output, exact command,
stdout/stderr, environment capture, and a deterministic config digest.
"""
from __future__ import annotations
import argparse,hashlib,json,os,secrets,shutil,subprocess,sys,time
from datetime import datetime,timezone
from pathlib import Path
from pabla.v2.envcapture import capture

SUPPORTED={'v2-smoke','python-tests','crypto-microbenchmark','witness-messages','wal-fault-tests'}

def _write(path:Path,data):
    path.write_text(json.dumps(data,sort_keys=True,indent=2,default=str))

def run_cell(cell:dict,dest:Path,root:Path)->dict:
    dest.mkdir(parents=True,exist_ok=False)
    config=json.dumps(cell,sort_keys=True,separators=(',',':')).encode()
    _write(dest/'config.json',cell)
    _write(dest/'env.json',capture(root))
    name=cell.get('runner')
    if name not in SUPPORTED:
        doc={'status':'not_run','reason':f'runner {name!r} is unavailable or requires external data/tools',
             'config_sha256':hashlib.sha256(config).hexdigest()}
        _write(dest/'status.json',doc)
        return doc
    commands={
        'v2-smoke':[sys.executable,'-m','pabla.v2.runner','--events',str(cell.get('events',8)),'--output',str(dest/'output')],
        'python-tests':[sys.executable,'-m','pytest','-q','tests/v2'],
        'crypto-microbenchmark':[sys.executable,'scripts/bench_crypto.py','--runs',str(cell.get('runs',5)),'--output',str(dest/'crypto.csv')],
        'witness-messages':[sys.executable,'scripts/x04_witness_cost.py','--output',str(dest/'witness.csv')],
        'wal-fault-tests':[sys.executable,'-m','pytest','-q','tests/v2/crash/test_fault_injection.py'],
    }
    cmd=commands[name];start=time.monotonic_ns()
    env=os.environ.copy();env['PYTHONPATH']=str(root)+os.pathsep+env.get('PYTHONPATH','')
    try:
        result=subprocess.run(cmd,env=env,cwd=root,capture_output=True,text=True,timeout=int(cell.get('timeout_s',300)))
        status='ok' if result.returncode==0 else 'failed';stderr=result.stderr;stdout=result.stdout;code=result.returncode
    except subprocess.TimeoutExpired as exc:
        status='failed';stderr=f'TIMEOUT: {exc}';stdout='';code=None
    (dest/'stdout.log').write_text(stdout)
    (dest/'stderr.log').write_text(stderr)
    doc={'status':status,'return_code':code,'command':cmd,'elapsed_ns':time.monotonic_ns()-start,
         'config_sha256':hashlib.sha256(config).hexdigest(),'measurement_type':'actual-subprocess-execution'}
    _write(dest/'status.json',doc)
    return doc

def main(argv=None)->int:
    p=argparse.ArgumentParser()
    p.add_argument('--plan',default='experiments/plan_smoke.json')
    p.add_argument('--output',default='results')
    p.add_argument('--allow-dirty',action='store_true')
    p.add_argument('--resume',default='')
    args=p.parse_args(argv)
    root=Path(__file__).resolve().parents[2]
    plan=json.loads(Path(args.plan).read_text())
    if not isinstance(plan.get('cells'),list):raise ValueError('invalid plan, cells[] required')
    manifest=capture(root)
    if not args.allow_dirty and manifest['git_dirty'] is not False:
        raise RuntimeError('clean, tracked Git checkout required; pass --allow-dirty and record exception')
    import random
    order=list(range(len(plan['cells'])))
    random.Random(plan.get('shuffle_seed',0)).shuffle(order)
    base=Path(args.resume) if args.resume else Path(args.output)/('campaign-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+secrets.token_hex(4))
    base.mkdir(parents=True,exist_ok=bool(args.resume))
    _write(base/'plan.json',plan)
    _write(base/'environment.json',dict(manifest,allow_dirty=args.allow_dirty,shuffle_order=order))
    summary={}
    for idx in order:
        cell=plan['cells'][idx]
        label=f'{idx:03d}-{cell.get("id","unnamed")}'
        dest=base/label
        if dest.exists():
            existing=json.loads((dest/'status.json').read_text()) if (dest/'status.json').exists() else None
            if existing and existing.get('status')=='ok':
                summary[label]='skipped_completed';continue
            raise RuntimeError(f'cell already exists with incomplete state: {dest}; never overwrite')
        summary[label]=run_cell(cell,dest,root)['status']
    _write(base/'summary.json',summary)
    print(json.dumps({'directory':str(base),'summary':summary},indent=2))
    return 1 if 'failed' in summary.values() else 0
if __name__=='__main__':raise SystemExit(main())
