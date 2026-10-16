"""Opt-in official LANL dataset fetch; avoids embedding/copying research data.

Usage: python scripts/download_lanl.py --subset redteam --output data/lanl-redteam.txt.gz
       python scripts/download_lanl.py --subset dns --output data/lanl-dns.txt.gz

WARNING: DNS is approximately 177 MB compressed; auth is 7.2 GB.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import urllib.request
from pathlib import Path

URL_BASE='https://csr.lanl.gov/data/cyber1/'
FILES={'redteam':'redteam.txt.gz','dns':'dns.txt.gz','auth':'auth.txt.gz','proc':'proc.txt.gz'}

def fetch(subset: str, destination: Path) -> dict:
    if subset not in FILES: raise ValueError('unrecognized LANL data subset')
    if destination.exists(): raise FileExistsError('refusing to overwrite source dataset')
    destination.parent.mkdir(parents=True,exist_ok=True)
    address=URL_BASE+FILES[subset]
    pending=destination.with_suffix(destination.suffix+'.part')
    hashed=hashlib.sha256();size=0
    try:
        with urllib.request.urlopen(address,timeout=45) as response,pending.open('xb') as stream:
            while chunk:=response.read(1024*1024):
                stream.write(chunk);hashed.update(chunk);size+=len(chunk)
        pending.replace(destination)
    finally:
        if pending.exists():pending.unlink()
    output={'dataset':'LANL comprehensive cyber-security events', 'subset':subset,'source':address,
            'sha256':hashed.hexdigest(),'bytes':size,'path':str(destination)}
    destination.with_suffix(destination.suffix+'.provenance.json').write_text(json.dumps(output,indent=2)+'\n')
    return output

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--subset',choices=FILES,default='redteam')
    p.add_argument('--output',type=Path,default=Path('data/lanl-redteam.txt.gz'))
    args=p.parse_args();print(json.dumps(fetch(args.subset,args.output),indent=2))
