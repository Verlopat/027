"""Fail-closed external Tessera personality adapter; no mock crypto verdicts.

Tessera is a Go library, NOT a standalone transparency-log protocol or a
self-verifying HTTP endpoint. A separately deployed pinned POSIX personality,
witness policy and a trusted checkpoint verifier are prerequisites.
"""
from __future__ import annotations
import os,shlex,subprocess,tempfile
from pathlib import Path
from urllib.request import Request,urlopen
from baselines.common.adapter import BaselineResult,MissingBaseline

class TesseraExternal:
    name='tessera-external-with-witness'
    def __init__(self,write_url:str,checkpoint_url:str,verify_command:str):
        if not write_url.startswith(('http://127.0.0.1:','http://localhost:','https://')):
            raise ValueError('local or https write endpoint required')
        if not checkpoint_url.startswith(('http://127.0.0.1:','http://localhost:','https://')):
            raise ValueError('local or https checkpoint endpoint required')
        if not verify_command.strip():raise ValueError('external verifier mandatory')
        self.write_url=write_url;self.checkpoint_url=checkpoint_url
        self.verify_command=verify_command;self.ingested=0
    def ingest(self,events)->BaselineResult:
        for ev in events:
            if not isinstance(ev,bytes):raise ValueError('raw leaf bytes required')
            request=Request(self.write_url,data=ev,method='POST',
                            headers={'Content-Type':'application/data'})
            with urlopen(request,timeout=20) as response:
                if response.status not in (200,201,202):
                    return BaselineResult('error',self.name,reason=f'HTTP {response.status}')
                response.read(1024) # drain only small response
            self.ingested+=1
        return BaselineResult('ok',self.name,verified_events=self.ingested)
    def verify(self)->BaselineResult:
        with urlopen(self.checkpoint_url,timeout=20) as response:
            checkpoint=response.read(65536)
        if not checkpoint:return BaselineResult('error',self.name,reason='empty checkpoint')
        # Command MUST verify the log AND witness signature against pinned
        # keys/consistency proof. The command is user configured and audited.
        with tempfile.TemporaryDirectory(prefix='pabla-tessera-') as tmp:
            path=Path(tmp)/'checkpoint';path.write_bytes(checkpoint)
            argv=[arg.replace('{checkpoint}',str(path)) for arg in shlex.split(self.verify_command)]
            if all('{checkpoint}' not in arg for arg in shlex.split(self.verify_command)):
                return BaselineResult('not_run',self.name,
                    reason='verifier must contain {checkpoint} argument')
            proc=subprocess.run(argv,capture_output=True,timeout=60,check=False)
        status='accept' if proc.returncode==0 else 'reject'
        return BaselineResult(status,self.name,reason=(proc.stdout+proc.stderr).decode(errors='replace'),
                              verified_events=self.ingested if status=='accept' else None)
    def compromise(self,at_ms:int)->BaselineResult:
        return BaselineResult('not_run',self.name,reason='external log-key and storage snapshot not configured')
    def cost(self)->dict:
        return {'status':'not_measured','gas':None,'ingested':self.ingested}

def baseline():
    fields=[os.getenv('PABLA_TESSERA_ADD_URL'),os.getenv('PABLA_TESSERA_CHECKPOINT_URL'),
            os.getenv('PABLA_TESSERA_VERIFY_CMD')]
    if not all(fields):
        return MissingBaseline('trillian-tessera-with-witness',
            'external personality, witness policy and pinned verification command not configured')
    return TesseraExternal(*fields)
