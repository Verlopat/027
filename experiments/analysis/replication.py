"""Compare two independently produced result bundles without asserting equality of noise."""
from __future__ import annotations
import argparse,hashlib,json,tarfile
from pathlib import Path

def entries(tar_path:str)->dict[str,str]:
    values={}
    with tarfile.open(tar_path,'r:*') as archive:
        for info in archive.getmembers():
            if not info.isfile() or info.name.startswith('/') or '..' in Path(info.name).parts:
                raise ValueError('unsafe replication archive member')
            content=archive.extractfile(info).read()
            if info.name.endswith('.json') and 'environment' not in info.name:
                values[info.name]=hashlib.sha256(content).hexdigest()
    return values

def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument('first');p.add_argument('second');a=p.parse_args(argv)
    x=entries(a.first);y=entries(a.second)
    shared=set(x)&set(y)
    print(json.dumps({'compared':len(shared),'matching_files':sum(x[k]==y[k] for k in shared),
                      'missing_in_second':sorted(set(x)-set(y)),
                      'missing_in_first':sorted(set(y)-set(x)),
                      'nonmatching':sorted(k for k in shared if x[k]!=y[k])},indent=2))
if __name__=='__main__':main()
