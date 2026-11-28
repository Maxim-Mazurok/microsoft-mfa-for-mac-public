"""Durable opaque replay claims, fixed redacted outcomes, exclusive service ownership."""
from pathlib import Path
import fcntl
import hashlib
import os
import sqlite3
import stat
import time


class StateError(ValueError):
    pass


class StateStore:
    def __init__(self, directory, *, synthetic=False):
        os.umask(0o077)
        self.directory = Path(directory).absolute()
        self.directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        # Refuse symlinked storage; each existing ancestor must be owned by root/current user.
        for path in (self.directory, *self.directory.parents):
            s = path.lstat()
            if not stat.S_ISDIR(s.st_mode) or s.st_uid not in (0, os.getuid()):
                raise StateError("unsafe_state_directory")
        s = self.directory.stat()
        if s.st_uid != os.getuid() or s.st_mode & 0o077:
            raise StateError("private_state_directory_required")
        self.lock = os.open(self.directory / "service.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self.lock)
            raise StateError("service_already_running") from None
        path = self.directory / "state.sqlite3"
        if path.exists() or path.is_symlink():
            s = path.lstat()
            if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o077:
                self.close(); raise StateError("unsafe_state_file")
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.executescript("CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT);"
                             "CREATE TABLE IF NOT EXISTS claims(digest TEXT PRIMARY KEY,at REAL,result TEXT);"
                             "CREATE TABLE IF NOT EXISTS history(at REAL,result TEXT);")
        expected = "synthetic" if synthetic else "live"
        mode = self.db.execute("SELECT value FROM metadata WHERE key='mode'").fetchone()
        if mode and mode[0] != expected:
            self.close(); raise StateError("synthetic_state_must_be_isolated")
        self.db.execute("INSERT OR IGNORE INTO metadata VALUES('mode',?)", (expected,)); self.db.commit()

    @staticmethod
    def digest(account_scope, guid):
        return hashlib.sha256((account_scope + "\0" + guid).encode()).hexdigest()

    def consumed(self, digest):
        return self.db.execute("SELECT 1 FROM claims WHERE digest=?", (digest,)).fetchone() is not None

    def claim(self, digest):
        try:
            self.db.execute("INSERT INTO claims VALUES(?,?,'unknown')", (digest, time.time()))
            self.db.commit()
            return True
        except sqlite3.IntegrityError:
            self.db.rollback(); return False

    def outcome(self, digest, result):
        allowed = {"accepted", "rejected", "unknown", "synthetic_accepted", "verification_cancelled"}
        if result not in allowed: raise StateError("invalid_history_result")
        with self.db:
            self.db.execute("UPDATE claims SET result=? WHERE digest=?", (result, digest))
            self.db.execute("INSERT INTO history VALUES(?,?)", (time.time(), result))
            self.db.execute("DELETE FROM history WHERE rowid NOT IN (SELECT rowid FROM history ORDER BY rowid DESC LIMIT 50)")

    def history(self):
        return [{"at": at, "result": result} for at, result in self.db.execute("SELECT at,result FROM history ORDER BY rowid DESC LIMIT 10")]

    def close(self):
        if hasattr(self, "db"): self.db.close(); del self.db
        if getattr(self, "lock", None) is not None:
            os.close(self.lock); self.lock = None
