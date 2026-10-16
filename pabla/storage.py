"""Crash-resistant immutable per-run artifact and metrics storage."""
from __future__ import annotations
import hashlib
import json
import os
import platform
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Iterable
from .protocol import canonical, Batch


def new_run(root: str | Path = 'output') -> Path:
    folder = Path(root)
    folder.mkdir(parents=True, exist_ok=True)
    for number in range(1, 1_000_000):
        run = folder / f'test{number}'
        try:
            run.mkdir()
            for d in ('artifacts', 'results/raw', 'results/derived', 'figures', 'logs'):
                (run / d).mkdir(parents=True, exist_ok=True)
            return run
        except FileExistsError:
            continue
    raise RuntimeError('exhausted run ID range')


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = canonical(value) + b'\n'
    temporary = path.with_name(path.name + f'.tmp-{os.getpid()}')
    with temporary.open('xb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    temporary.replace(path)


def write_jsonl(path: Path, rows: Iterable[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f'.tmp-{os.getpid()}')
    with temporary.open('xb') as f:
        for row in rows:
            f.write(canonical(row) + b'\n')
        f.flush()
        os.fsync(f.fileno())
    temporary.replace(path)


def save_batch(run: Path, batch: Batch, receipt: dict | None = None) -> Path:
    m = batch.manifest
    dest = run / 'artifacts' / f'{m["collector_id"]}-e{m["epoch"]}-b{m["batch_number"]}.json'
    data = batch.export()
    data['receipt'] = receipt
    write_json(dest, data)
    return dest


def manifest_metadata(config: dict, backend: str) -> dict:
    model = platform.processor()
    cpuinfo = Path('/proc/cpuinfo')
    if cpuinfo.is_file():
        for entry in cpuinfo.read_text(errors='replace').splitlines():
            if entry.startswith('model name') and ':' in entry:
                model = entry.split(':', 1)[1].strip()
                break
    governor_path = Path('/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor')
    governor = governor_path.read_text().strip() if governor_path.is_file() else None
    return {'config':config, 'config_sha256':hashlib.sha256(canonical(config)).hexdigest(),
            'backend':backend, 'python':sys.version, 'os':platform.platform(),
            'processor':model, 'governor':governor, 'created_unix':time.time()}


class RunIndex:
    def __init__(self, run: Path) -> None:
        self.db = sqlite3.connect(run / 'artifact_index.sqlite', timeout=60)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS batches (
            collector_id TEXT NOT NULL, epoch INTEGER NOT NULL, batch_number INTEGER NOT NULL,
            manifest_hash TEXT NOT NULL, artifact_path TEXT NOT NULL, backend TEXT NOT NULL,
            PRIMARY KEY(collector_id,epoch,batch_number));
          CREATE TABLE IF NOT EXISTS measurements (
            method TEXT NOT NULL, experiment TEXT NOT NULL, trial INTEGER NOT NULL,
            metric TEXT NOT NULL, value REAL, units TEXT NOT NULL, status TEXT NOT NULL);
        ''')
        self.db.commit()
    def add_batch(self, batch: Batch, path: Path, backend: str) -> None:
        m = batch.manifest
        with self.db:
            self.db.execute('INSERT INTO batches VALUES(?,?,?,?,?,?)',
                (m['collector_id'],m['epoch'],m['batch_number'],batch.manifest_digest,str(path),backend))
    def add_measurements(self, rows: Iterable[tuple]) -> None:
        with self.db:
            self.db.executemany('INSERT INTO measurements VALUES(?,?,?,?,?,?,?)',rows)
    def close(self) -> None:
        self.db.close()


def archive_size(run: Path) -> int:
    return sum(f.stat().st_size for f in (run/'artifacts').rglob('*') if f.is_file())
