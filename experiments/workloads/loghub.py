"""Verified, streaming real-log ingestion. Never substitutes generated events."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime,timezone
import argparse,hashlib,json,re
from pathlib import Path
from typing import Iterator

@dataclass(frozen=True)
class Trace:
    name:str
    source:str
    sha256:str
    path:Path
    format:str='iso8601'
    def events(self)->Iterator[tuple[int,bytes]]:
        """Yield timestamp milliseconds and original newline-excluded byte content."""
        with self.path.open('rb') as fp:
            for number,line in enumerate(fp,1):
                payload=line.rstrip(b'\r\n')
                if not payload:continue
                if self.format=='iso8601':
                    try:
                        match=re.search(rb'\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)',payload)
                        if not match:raise ValueError('no timezone-aware ISO8601 timestamp')
                        timestamp=match.group().decode().replace(' ','T').replace('Z','+00:00')
                        t=datetime.fromisoformat(timestamp)
                        if t.tzinfo is None:raise ValueError('ambiguous timezone')
                        arrival_ms=int(t.timestamp()*1000)
                    except Exception as e:
                        raise ValueError(f'{self.name} line {number}: invalid timestamp: {e}') from e
                elif self.format=='millis-first':
                    try:arrival_ms=int(payload.split(None,1)[0])
                    except Exception as e:raise ValueError(f'{self.name} line {number}: no millisecond timestamp') from e
                    if arrival_ms<0:raise ValueError('negative timestamp')
                else:raise ValueError('unsupported dataset timestamp format')
                yield arrival_ms,payload

def verified_trace(name:str,path:str|Path,expected_sha256:str,source:str,fmt:str='iso8601')->Trace:
    p=Path(path)
    if not expected_sha256 or len(expected_sha256)!=64:raise ValueError('SHA256 required; no unauthenticated datasets')
    digest=hashlib.sha256(p.read_bytes()).hexdigest()
    if digest.lower()!=expected_sha256.lower():raise ValueError(f'{name}: SHA-256 mismatch')
    return Trace(name,source,digest,p,fmt)

def load_manifest(file:str|Path)->list[Trace]:
    doc=json.loads(Path(file).read_text())
    return [verified_trace(item['name'],item['path'],item['sha256'],item['source'],item.get('format','iso8601')) for item in doc['datasets']]

def main():
    parser=argparse.ArgumentParser(description='Validate local real security log traces')
    parser.add_argument('--manifest',required=True)
    a=parser.parse_args();rows=[]
    for t in load_manifest(a.manifest):
        first=None;last=None;count=0;bytes_total=0
        for when,payload in t.events():
            count+=1;bytes_total+=len(payload)
            first=when if first is None else min(first,when)
            last=when if last is None else max(last,when)
        rows.append({'name':t.name,'sha256':t.sha256,'source':t.source,'events':count,
                     'bytes':bytes_total,'first_ms':first,'last_ms':last,'measurement_type':'actual-input'})
    print(json.dumps(rows,indent=2))
if __name__=='__main__':main()
