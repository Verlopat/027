"""Capability gate for the REAL systemd journald FSS baseline.

No direct write to the host's system journal is attempted. Use a dedicated,
reviewed systemd container/VM to avoid changing operational logging config.
"""
from __future__ import annotations
import os,shutil,subprocess
from baselines.common.adapter import MissingBaseline

def available()->tuple[bool,str]:
    if not shutil.which('journalctl') or not shutil.which('systemd-cat'):
        return False,'journalctl or systemd-cat executable missing'
    if not os.path.exists('/run/systemd/journal/socket'):
        return False,'no isolated running journald socket; use a dedicated systemd VM/container'
    if not os.getenv('PABLA_ALLOW_SYSTEMD_FSS'):
        return False,'PABLA_ALLOW_SYSTEMD_FSS not enabled for isolated baseline environment'
    return True,'prerequisites present; driver still requires audited isolated setup'

def baseline():
    _,reason=available()
    return MissingBaseline('systemd-journald-fss',reason or 'not integrated')
