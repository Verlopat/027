"""Opt-in driver for a REAL systemd-journald FSS installation.

Only run inside a separately provisioned systemd VM/container. The driver
NEVER creates or rotates FSS keys on its own and never assumes journal
availability amounts to verified forward integrity.
"""
from __future__ import annotations
import base64,os,shutil,subprocess
from pathlib import Path
from baselines.common.adapter import BaselineResult,MissingBaseline

class JournaldFSS:
    name='systemd-journald-fss'
    def __init__(self,journal_directory:str,verification_key:str):
        self.directory=Path(journal_directory)
        self.key=verification_key
        if not self.directory.is_dir() or not self.key:
            raise ValueError('need isolated journal directory and externally saved FSS verification key')
        self._total=0
    def ingest(self,events)->BaselineResult:
        count=0
        for event in events:
            if not isinstance(event,bytes):raise ValueError('event must be bytes')
            # systemd-cat splits newline-delimited messages; ASCII base64
            # provides unambiguous reconstruction for arbitrary event bytes.
            line=base64.b64encode(event)+b'\n'
            p=subprocess.run(['systemd-cat','--identifier=pabla-bj-fss'],input=line,
                             capture_output=True,timeout=30,check=False)
            if p.returncode:
                return BaselineResult('error',self.name,reason=p.stderr.decode(errors='replace'))
            count+=1
        self._total+=count
        return BaselineResult('ok',self.name,verified_events=count)
    def verify(self)->BaselineResult:
        p=subprocess.run(['journalctl','--directory',str(self.directory),'--verify',
                          '--verify-key='+self.key],capture_output=True,timeout=180,check=False)
        # This is journald's *real* FSS verifier; stdout/stderr need archiving
        # by the experiment harness, not converting to a fabricated metric.
        if p.returncode:
            return BaselineResult('reject',self.name,
                                  reason=(p.stdout+p.stderr).decode(errors='replace'))
        return BaselineResult('accept',self.name,
                              reason=(p.stdout+p.stderr).decode(errors='replace'),
                              verified_events=self._total)
    def compromise(self,at_ms:int)->BaselineResult:
        return BaselineResult('not_run',self.name,
                reason='isolated filesystem/key snapshot required at the specified timestamp')
    def cost(self)->dict:
        return {'status':'not_measured','gas':None,'events':self._total}

def available()->tuple[bool,str]:
    if not shutil.which('journalctl') or not shutil.which('systemd-cat'):
        return False,'journalctl or systemd-cat missing'
    if not os.getenv('PABLA_ISOLATED_SYSTEMD') or not os.getenv('PABLA_ALLOW_SYSTEMD_FSS'):
        return False,'explicit isolation and opt-in flags required'
    if not os.path.exists('/run/systemd/journal/socket'):
        return False,'no isolated running journald socket'
    if not os.getenv('PABLA_FSS_VERIFY_KEY') or not os.getenv('PABLA_FSS_JOURNAL_DIRECTORY'):
        return False,'FSS verification key and dedicated journal directory required'
    return True,'isolated FSS environment configured'

def baseline():
    ok,reason=available()
    return JournaldFSS(os.environ['PABLA_FSS_JOURNAL_DIRECTORY'],
                       os.environ['PABLA_FSS_VERIFY_KEY']) if ok else MissingBaseline('systemd-journald-fss',reason)
