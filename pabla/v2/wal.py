"""SQLite-backed crash recovery reference.

Uses FULL synchronous commits. Durable intent precedes signing and the signed
checkpoint plus next secret are committed in one transaction. SQLite is NOT a
secret-erasing store: old pages, journals, backups and swap can retain keys.
Production forward secrecy needs a separately validated hardened key store.
"""
from __future__ import annotations
import json
import sqlite3
from pathlib import Path
from .checkpoint import Checkpoint,Sealed

class PersistentLog:
    def __init__(self,path:str|Path,public_root:bytes,initial_seed:bytes):
        self.path=Path(path);self.path.parent.mkdir(parents=True,exist_ok=True)
        self.db=sqlite3.connect(self.path,isolation_level=None)
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA journal_mode=DELETE')
        self.db.execute('PRAGMA secure_delete=ON')
        self.db.execute('CREATE TABLE IF NOT EXISTS events (idx INTEGER PRIMARY KEY, event BLOB NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS sealed (period INTEGER PRIMARY KEY, artifact TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), root BLOB, seed BLOB, period INTEGER, prev BLOB)')
        self.db.execute('CREATE TABLE IF NOT EXISTS intent (period INTEGER PRIMARY KEY, payload TEXT NOT NULL)')
        if self.db.execute('SELECT id FROM state WHERE id=1').fetchone() is None:
            self.db.execute('INSERT INTO state VALUES(1,?,?,?,?)',(public_root,initial_seed,1,b'\x00'*32))
        state=self.state()
        if state[0]!=public_root:raise ValueError('unexpected schedule root')
    def close(self)->None:self.db.close()
    def state(self):return self.db.execute('SELECT root,seed,period,prev FROM state WHERE id=1').fetchone()
    def events(self)->list[bytes]:return [v[0] for v in self.db.execute('SELECT event FROM events ORDER BY idx')]
    def append(self,event:bytes)->int:
        if self.db.execute('SELECT 1 FROM intent LIMIT 1').fetchone():raise ValueError('unresolved seal intent')
        with self.db:
            index=self.db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
            self.db.execute('INSERT INTO events(idx,event) VALUES(?,?)',(index,event))
        return index
    def pending_intent(self):
        row=self.db.execute('SELECT period,payload FROM intent ORDER BY period LIMIT 1').fetchone()
        return (row[0],Checkpoint.from_dict(json.loads(row[1]))) if row else None
    def begin_seal(self,cp:Checkpoint)->None:
        with self.db:
            state=self.state()
            if cp.period!=state[2]:raise ValueError('stale seal period')
            self.db.execute('INSERT INTO intent(period,payload) VALUES(?,?)',
                            (cp.period,json.dumps(cp.to_dict(),sort_keys=True)))
    def complete_seal(self,sealed:Sealed,next_seed:bytes)->None:
        cp=sealed.checkpoint
        with self.db:
            state=self.state(); intent=self.pending_intent()
            if not intent or intent[0]!=cp.period or intent[1]!=cp or state[2]!=cp.period:
                raise ValueError('intent does not match persisted state')
            self.db.execute('INSERT INTO sealed(period,artifact) VALUES(?,?)',
                            (cp.period,json.dumps(sealed.to_dict(),sort_keys=True)))
            self.db.execute('UPDATE state SET seed=?,period=?,prev=? WHERE id=1',
                            (next_seed,cp.period+1,cp.digest()))
            self.db.execute('DELETE FROM intent WHERE period=?',(cp.period,))
    def sealed(self)->list[Sealed]:
        return [Sealed.from_dict(json.loads(s)) for (s,) in self.db.execute('SELECT artifact FROM sealed ORDER BY period')]
