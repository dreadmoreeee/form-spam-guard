"""Nonce stores for single-use (replay-safe) tokens."""

from __future__ import annotations

import sqlite3
import threading
from abc import ABC, abstractmethod
from typing import Dict


class NonceStore(ABC):
    """Remembers nonces until they expire.

    ``add_if_new`` must be atomic: of two concurrent calls with the same
    nonce, exactly one returns True.
    """

    @abstractmethod
    def add_if_new(self, nonce: str, expires_at: float, now: float) -> bool:
        """Record ``nonce``. Return False if it is already recorded and unexpired."""

    @abstractmethod
    def cleanup(self, now: float) -> int:
        """Delete expired nonces. Return how many were removed."""


class InMemoryStore(NonceStore):
    """Thread-safe, per-process store. Expired entries are purged as you go."""

    def __init__(self, purge_every: float = 60.0) -> None:
        self._seen: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._purge_every = purge_every
        self._next_purge = 0.0

    def add_if_new(self, nonce: str, expires_at: float, now: float) -> bool:
        with self._lock:
            if now >= self._next_purge:
                self._purge(now)
                self._next_purge = now + self._purge_every
            current = self._seen.get(nonce)
            if current is not None and current > now:
                return False
            self._seen[nonce] = expires_at
            return True

    def cleanup(self, now: float) -> int:
        with self._lock:
            return self._purge(now)

    def _purge(self, now: float) -> int:
        dead = [n for n, exp in self._seen.items() if exp <= now]
        for n in dead:
            del self._seen[n]
        return len(dead)

    def __len__(self) -> int:
        with self._lock:
            return len(self._seen)


class SQLiteStore(NonceStore):
    """Store backed by a SQLite file, shared by several processes on one host."""

    def __init__(self, path: str, purge_every: float = 300.0) -> None:
        self._path = str(path)
        self._lock = threading.Lock()
        self._purge_every = purge_every
        self._next_purge = 0.0
        self._db = sqlite3.connect(self._path, timeout=10.0, check_same_thread=False)
        with self._lock, self._db:
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS nonces ("
                "nonce TEXT PRIMARY KEY, expires_at REAL NOT NULL)"
            )
            self._db.execute(
                "CREATE INDEX IF NOT EXISTS nonces_expires ON nonces (expires_at)"
            )

    def add_if_new(self, nonce: str, expires_at: float, now: float) -> bool:
        with self._lock:
            with self._db:
                if now >= self._next_purge:
                    self._db.execute("DELETE FROM nonces WHERE expires_at <= ?", (now,))
                    self._next_purge = now + self._purge_every
                # An expired row with the same nonce must not block a new use.
                self._db.execute(
                    "DELETE FROM nonces WHERE nonce = ? AND expires_at <= ?", (nonce, now)
                )
                cur = self._db.execute(
                    "INSERT OR IGNORE INTO nonces (nonce, expires_at) VALUES (?, ?)",
                    (nonce, expires_at),
                )
                return cur.rowcount == 1

    def cleanup(self, now: float) -> int:
        with self._lock, self._db:
            cur = self._db.execute("DELETE FROM nonces WHERE expires_at <= ?", (now,))
            return cur.rowcount

    def __len__(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM nonces").fetchone()[0]

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def __enter__(self) -> "SQLiteStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
