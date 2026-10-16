"""Package actual campaign artifacts with hashes, without fabricating data."""
from __future__ import annotations
import argparse,hashlib,io,json,tarfile
from pathlib import Path

def make_release(campaign:Path,dest:Path)->dict:
    if not (campaign/'summary.json').is_file():raise ValueError('missing campaign summary')
    if dest.resolve().is_relative_to(campaign.resolve()):raise ValueError('output archive must be outside campaign directory')
    files=sorted(x for x in campaign.rglob('*') if x.is_file())
    index={str(x.relative_to(campaign)):hashlib.sha256(x.read_bytes()).hexdigest() for x in files}
    dest.parent.mkdir(parents=True,exist_ok=True)
    with tarfile.open(dest,'w:gz') as z:
        for x in files:z.add(x,arcname='campaign/'+str(x.relative_to(campaign)),recursive=False)
        data=json.dumps(index,sort_keys=True,indent=2).encode()
        info=tarfile.TarInfo('SHA256SUMS.json');info.size=len(data)
        z.addfile(info,io.BytesIO(data))
    # Independently read back EVERY member of the written tarball.
    with tarfile.open(dest,'r:gz') as z:
        recovered=json.loads(z.extractfile('SHA256SUMS.json').read())
        if recovered!=index:raise AssertionError('archive metadata differs')
        for rel,digest in index.items():
            if hashlib.sha256(z.extractfile('campaign/'+rel).read()).hexdigest()!=digest:
                raise AssertionError(f'archive corrupted: {rel}')
    return {'status':'ok','archive':str(dest),'files':len(index),
            'sha256':hashlib.sha256(dest.read_bytes()).hexdigest()}

def main():
    p=argparse.ArgumentParser();p.add_argument('campaign');p.add_argument('output');a=p.parse_args()
    print(json.dumps(make_release(Path(a.campaign),Path(a.output)),indent=2))
if __name__=='__main__':main()
