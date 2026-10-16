"""Actual per-operation crypto microbenchmark, no synthetic measurements."""
from __future__ import annotations
import argparse,csv,json,statistics,time
from pathlib import Path
from pabla.v2.backends import ReferenceBackend,NativeBackend
from pabla.v2.crypto import sha
from pabla.v2.envcapture import capture

def main(argv=None):
    ap=argparse.ArgumentParser();ap.add_argument('--output',default='output/crypto.csv');ap.add_argument('--runs',type=int,default=31)
    args=ap.parse_args(argv)
    if args.runs<5:raise ValueError('at least 5 runs required')
    backends=[ReferenceBackend()]
    try:backends.append(NativeBackend())
    except ImportError:pass
    d=sha(b'pabla-crypto-benchmark');rows=[]
    for b in backends:
        operations=(('address',lambda:b.address(1)),('sign',lambda:b.sign_digest(1,d)),('recover',lambda:b.recover_address(d,b.sign_digest(1,d))))
        for operation,func in operations:
            func();measure=[]
            for _ in range(args.runs):
                start=time.perf_counter_ns();func();measure.append(time.perf_counter_ns()-start)
            rows.append({'backend':b.name,'operation':operation,'median_ns':statistics.median(measure),
                        'min_ns':min(measure),'max_ns':max(measure),'runs':args.runs,'measurement_type':'execution'})
    dest=Path(args.output);dest.parent.mkdir(parents=True,exist_ok=True)
    with dest.open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    dest.with_suffix('.environment.json').write_text(json.dumps(capture(),indent=2))
    print(json.dumps({'rows':len(rows),'output':str(dest),'native_available':len(backends)>1}))
if __name__=='__main__':main()
