"""CPU-only synthetic streaming verification benchmark, actual timed code."""
from __future__ import annotations
import argparse,json,time,tracemalloc,resource,sys
from pathlib import Path
from pabla.v2.schedule import Schedule
from pabla.v2.tree import CompactRange
from pabla.v2.crypto import sha,secret_for_state,sign_digest
from pabla.v2.checkpoint import Checkpoint,Sealed
from pabla.v2.streaming import verify_stream
from pabla.v2.envcapture import capture

def items(count):
    for i in range(count):
        yield i.to_bytes(8,'big')

def main():
    p=argparse.ArgumentParser();p.add_argument('--events',type=int,default=100_000);p.add_argument('--output',default='output/stream-benchmark.json');a=p.parse_args()
    if not 1<=a.events<=10_000_000:raise ValueError('1 <= events <= 10 million')
    seed=sha(b'pabla-stream-benchmark-not-a-secret');sch=Schedule.setup(seed,2)
    root=CompactRange();build=time.perf_counter_ns()
    for item in items(a.events):root.append(item)
    build_ns=time.perf_counter_ns()-build
    cp=Checkpoint(b'C'*32,1,1,a.events,root.root(),b'\x00'*32,100,sch.public.root)
    sig=sign_digest(secret_for_state(seed),cp.digest())
    artifact=Sealed(cp,sig,tuple(sch.public.proof(1)))
    tracemalloc.start();t0=time.perf_counter_ns()
    verdict=verify_stream(items(a.events),[artifact],sch.public,collector=b'C'*32,epoch=1)
    elapsed=time.perf_counter_ns()-t0
    peak=tracemalloc.get_traced_memory()[1];tracemalloc.stop()
    if not verdict.accepted():raise RuntimeError('benchmark verification failed')
    data={'status':'ok','backend':'cpu-python-reference','measurement_type':'actual-execution',
          'data_source':'synthetic-consecutive-uint64','events':a.events,'build_ns':build_ns,
          'verify_ns':elapsed,'verify_peak_python_allocated_bytes':peak,
          'process_peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss if sys.platform.startswith('linux') else None,'notes':'tracemalloc is not process RSS; OS RSS must be measured separately',
          'environment':capture()}
    dest=Path(a.output);dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(data,indent=2,sort_keys=True))
    print(json.dumps({'events':a.events,'verify_ns':elapsed,'peak_traced_bytes':peak}))
if __name__=='__main__':main()
