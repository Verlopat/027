"""Best-effort reproducibility manifest; unavailable tools are recorded as null."""
from __future__ import annotations
import hashlib
import importlib.metadata
import os
from pathlib import Path
import platform
import subprocess
import sys


def _run(*args: str) -> str | None:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=5, check=False)
        return r.stdout.strip() if r.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def capture(root: str | Path | None = None) -> dict:
    root = Path(root or Path(__file__).resolve().parents[2]).resolve()
    lock = root / 'uv.lock'
    cpu = None
    cpuinfo = Path('/proc/cpuinfo')
    if cpuinfo.is_file():
        for line in cpuinfo.read_text(errors='replace').splitlines():
            if line.startswith('model name'):
                cpu = line.partition(':')[2].strip()
                break
    gov = Path('/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor')
    rev = _run('git', '-C', str(root), 'rev-parse', 'HEAD')
    dirty = _run('git', '-C', str(root), 'status', '--porcelain')
    return {
        'git_sha': rev, 'git_dirty': None if dirty is None else bool(dirty),
        'lock_sha256': hashlib.sha256(lock.read_bytes()).hexdigest() if lock.is_file() else None,
        'python': sys.version, 'platform': platform.platform(),
        'kernel': platform.release(), 'cpu_model': cpu,
        'cpu_governor': gov.read_text().strip() if gov.is_file() else None,
        'tool_versions': {k: _run(k, '--version') for k in ('forge', 'anvil', 'docker', 'uv')},
        'crypto_backend': os.getenv('PABLA_CRYPTO_BACKEND', 'auto'),
        'packages': {k: _package_version(k) for k in ('cryptography','pytest','hypothesis','coincurve')},
    }


def _package_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None
