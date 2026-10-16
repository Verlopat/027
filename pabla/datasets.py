"""Streaming, source-preserving LANL time/size replay with checksum provenance.

Official LANL comprehensive cyber-events: https://csr.lanl.gov/data/cyber1/
The real dataset must be obtained separately. No fabricated 'real' trace is used.
"""
from __future__ import annotations
import bz2
import gzip
import hashlib
from pathlib import Path
from typing import Iterator


def replay_times(path: str|Path, *, max_events: int = 100_000) -> tuple[list[int], list[int], str]:
    """Read LANL event rows where first comma-separated field is relative seconds.

    Preserves size in source bytes and converts seconds to milliseconds.
    Supports plain UTF-8 and gzip/bz2; only first max_events are retained.
    SHA256 covers original complete source file (including compressed bytes).
    """
    p=Path(path)
    if not p.is_file(): raise FileNotFoundError(f'dataset unavailable: {p}')
    checksum=hashlib.sha256()
    with p.open('rb') as f:
        while block:=f.read(1024*1024):
            checksum.update(block)
    opener=gzip.open if p.suffix=='.gz' else bz2.open if p.suffix=='.bz2' else open
    times=[];sizes=[]
    with opener(p,'rt',encoding='utf-8') as stream:
        for line in stream:
            if not line.strip(): continue
            first=line.split(',',1)[0]
            try:
                epoch_seconds=int(first)
            except ValueError as exc:
                raise ValueError('expected LANL relative-second numeric first column') from exc
            if epoch_seconds < 0: raise ValueError('negative time')
            if times and epoch_seconds*1000 < times[-1]:
                raise ValueError('unsorted timestamp in LANL input')
            times.append(epoch_seconds*1000)
            sizes.append(len(line.encode('utf-8')))
            if len(times)>=max_events: break
    if not times: raise ValueError('empty dataset')
    zero=times[0]
    return [t-zero for t in times],sizes,checksum.hexdigest()
