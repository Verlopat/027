"""Key-custody providers. Neither storage provider guarantees secure erasure."""
from __future__ import annotations
import os
from pathlib import Path
import sqlite3
import tempfile
from typing import Protocol

class SeedStore(Protocol):
    def load(self) -> bytes: ...
    def replace(self, new: bytes) -> None: ...
    def erase_old(self) -> None: ...

class FileSeedStore:
    """Best-effort 0600 file replacement; old SSD/journal blocks may remain."""
    def __init__(self,path:str|Path):self.path=Path(path)
    def load(self)->bytes:
        value=self.path.read_bytes()
        if len(value)!=32:raise ValueError('invalid 32-byte seed')
        return value
    def replace(self,new:bytes)->None:
        if not isinstance(new,bytes) or len(new)!=32:raise ValueError('invalid seed')
        self.path.parent.mkdir(parents=True,exist_ok=True)
        fd,tmp=tempfile.mkstemp(prefix='.seed-',dir=self.path.parent)
        try:
            with os.fdopen(fd,'wb') as stream:
                stream.write(new);stream.flush();os.fsync(stream.fileno())
            os.chmod(tmp,0o600)
            os.replace(tmp,self.path)
            dirfd=os.open(self.path.parent,os.O_RDONLY)
            try:os.fsync(dirfd)
            finally:os.close(dirfd)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    def erase_old(self)->None:
        # This API is intentionally not called secure erasure.
        return None

class SqliteSeedStore:
    """Non-erasing SQLite wrapper for reference/test use, not hardened custody."""
    def __init__(self,conn:sqlite3.Connection):self.db=conn
    def load(self)->bytes:
        row=self.db.execute('SELECT seed FROM state WHERE id=1').fetchone()
        if not row or not isinstance(row[0],bytes) or len(row[0])!=32:raise ValueError('invalid state seed')
        return row[0]
    def replace(self,new:bytes)->None:
        if not isinstance(new,bytes) or len(new)!=32:raise ValueError('invalid seed')
        with self.db:self.db.execute('UPDATE state SET seed=? WHERE id=1',(new,))
    def erase_old(self)->None:return None
