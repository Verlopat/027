"""Tessera integration availability, not the internal CT reference baseline."""
from __future__ import annotations
import shutil
from baselines.common.adapter import MissingBaseline

def baseline():
    reason='Tessera and a pinned independent witness are not installed/integrated'
    return MissingBaseline('trillian-tessera-with-witness',reason)
