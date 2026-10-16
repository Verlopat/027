"""Explicitly report whether memory-erasure examination is supported.

Never print raw key bytes. On hosts with gcore and ptrace capability, an
external audited harness should be used to scan process dumps. This script
is a capability gate rather than an unverified claim of secure erasure.
"""
from __future__ import annotations
import json,shutil,sys
from pabla.v2.envcapture import capture

def main():
    state={'experiment':'X10c','status':'not_run','erasure_guarantee':'not_established',
           'erased_seeds_found':None,'reason':'An audited isolated process-dump scanner is not implemented',
           'gcore_available':bool(shutil.which('gcore')),'platform':sys.platform,
           'environment':capture()}
    print(json.dumps(state,sort_keys=True))
if __name__=='__main__':main()
