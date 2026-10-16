"""Actual witness-cosigning message and serialized byte counts."""
from __future__ import annotations
import argparse,csv,json,tempfile
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pabla.v2.schedule import Schedule
from pabla.v2.collector import Collector
from pabla.v2.witness import Witness
from pabla.v2.witness_set import WitnessSet
from pabla.v2.envcapture import capture

def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument('--output',default='output/witness-cost.csv');args=p.parse_args(argv)
    results=[]
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)
        sch=Schedule.setup(b'K'*32,height=2)
        collector=Collector(root/'c.db',b'C'*32,1,sch.public,b'K'*32)
        collector.append({'id':1});sealed=collector.seal(100)
        for k in (1,3,5):
            witnesses={str(i):Witness(root/f'w-{k}-{i}.db',sch.public,Ed25519PrivateKey.generate()) for i in range(k)}
            try:
                ws=WitnessSet(witnesses,(k//2)+1,max_corrupt=0)
                received=ws.submit_all(sealed,wall_ms=101)
                cert=received.certificate
                if cert is None:raise RuntimeError('honest quorum failed')
                results.append({'witness_count':k,'quorum':ws.quorum,'messages':len(received.statuses),
                                'certificate_bytes':len(json.dumps(cert.to_dict(),sort_keys=True).encode()),
                                'status':'measured','backend':'local-witness-process'})
            finally:
                for w in witnesses.values():w.close()
        collector.close()
    dest=Path(args.output);dest.parent.mkdir(parents=True,exist_ok=True)
    with dest.open('w',newline='') as fp:
        w=csv.DictWriter(fp,fieldnames=list(results[0]));w.writeheader();w.writerows(results)
    dest.with_suffix('.environment.json').write_text(json.dumps(capture(),indent=2))
    print(json.dumps({'output':str(dest),'rows':len(results)}))
if __name__=='__main__':main()
