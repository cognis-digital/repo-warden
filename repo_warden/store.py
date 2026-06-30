"""SQLite-backed store for scoped tokens and device-flow requests.

Tokens are bound to a set of scopes and a repo *namespace* (a glob over
`owner/repo`). Only a salted BLAKE2b hash of each token is stored, so a leak of
the database doesn't leak usable credentials, and revocation is immediate.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Optional

VALID_SCOPES = {"repo:read", "repo:write", "branch:push", "branch:admin", "repo:admin"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    label      TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    scopes     TEXT NOT NULL,
    namespace  TEXT NOT NULL DEFAULT '*',
    created_at REAL NOT NULL,
    revoked_at REAL,
    expires_at REAL                            -- null = never expires
);

CREATE TABLE IF NOT EXISTS device_requests (
    device_code     TEXT PRIMARY KEY,
    user_code       TEXT NOT NULL UNIQUE,
    client_id       TEXT NOT NULL,
    scopes          TEXT NOT NULL,
    namespace       TEXT NOT NULL DEFAULT '*',
    status          TEXT NOT NULL,           -- pending | approved | denied | expired
    subject         TEXT,
    created_at      REAL NOT NULL,
    expires_at      REAL NOT NULL,
    interval        INTEGER NOT NULL,
    last_poll       REAL,
    token_id        INTEGER,
    delivered_token TEXT                      -- held until first successful poll
);
"""


def _hash(token: str) -> str:
    return hashlib.blake2b(token.encode("utf-8"), digest_size=32).hexdigest()


@dataclass(frozen=True)
class TokenInfo:
    id: int
    label: str
    scopes: frozenset[str]
    namespace: str
    created_at: float
    revoked_at: Optional[float]
    expires_at: Optional[float] = None

    @property
    def active(self) -> bool:
        """Not revoked. (Use is_active(now) to also account for expiry.)"""
        return self.revoked_at is None

    def is_expired(self, now: Optional[float] = None) -> bool:
        if self.expires_at is None:
            return False
        now = time.time() if now is None else now
        return now >= self.expires_at

    def is_active(self, now: Optional[float] = None) -> bool:
        """Live right now: neither revoked nor past its expiry."""
        return self.active and not self.is_expired(now)

    def covers(self, repo: str) -> bool:
        """Does this token's namespace glob include the given owner/repo?"""
        return fnmatch(repo, self.namespace)

    def as_dict(self) -> dict:
        d = {"id": self.id, "label": self.label, "scopes": sorted(self.scopes),
             "namespace": self.namespace, "active": self.is_active()}
        if self.expires_at is not None:
            d["expires_at"] = self.expires_at
        return d


class Store:
    def __init__(self, db_path: str = ":memory:"):
        self.conn = sqlite3.connect(db_path)
        self.conn.executescript(SCHEMA)
        self._migrate()
        self.conn.commit()

    def _migrate(self) -> None:
        """Add columns introduced after a DB was first created (idempotent)."""
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(tokens)")}
        if "expires_at" not in cols:
            self.conn.execute("ALTER TABLE tokens ADD COLUMN expires_at REAL")

    def close(self) -> None:
        self.conn.close()

    # ---- tokens ----------------------------------------------------------
    def issue_token(self, label: str, scopes: set[str], namespace: str = "*",
                    *, expires_in: Optional[float] = None,
                    now: Optional[float] = None) -> tuple[str, TokenInfo]:
        """Mint a token. `expires_in` (seconds, optional) makes it short-lived;
        the default of None keeps the original "never expires" behaviour."""
        if not label or not label.strip():
            raise ValueError("token label is required")
        if not namespace or not namespace.strip():
            raise ValueError("namespace is required (use '*' for all repos)")
        scopes = set(scopes)
        if not scopes:
            raise ValueError("at least one scope is required")
        bad = scopes - VALID_SCOPES
        if bad:
            raise ValueError(f"unknown scopes: {sorted(bad)}")
        if expires_in is not None and expires_in <= 0:
            raise ValueError("expires_in must be positive (seconds), or None")
        token = "rw_" + secrets.token_urlsafe(32)
        created = time.time() if now is None else now
        expires_at = None if expires_in is None else created + expires_in
        cur = self.conn.execute(
            "INSERT INTO tokens(label, token_hash, scopes, namespace, created_at, expires_at) "
            "VALUES(?,?,?,?,?,?)",
            (label, _hash(token), ",".join(sorted(scopes)), namespace, created, expires_at),
        )
        self.conn.commit()
        info = TokenInfo(int(cur.lastrowid), label, frozenset(scopes), namespace,
                         created, None, expires_at)
        return token, info

    def authenticate(self, token: str, *, now: Optional[float] = None) -> Optional[TokenInfo]:
        if not token:
            return None
        row = self.conn.execute(
            "SELECT id, label, scopes, namespace, created_at, revoked_at, expires_at "
            "FROM tokens WHERE token_hash=?",
            (_hash(token),),
        ).fetchone()
        if not row or row[5] is not None:        # missing or revoked
            return None
        info = TokenInfo(row[0], row[1], frozenset(row[2].split(",")), row[3],
                         row[4], None, row[6])
        if info.is_expired(now):                  # past its lifetime -> fail closed
            return None
        return info

    def revoke_token(self, token_id: int) -> bool:
        cur = self.conn.execute(
            "UPDATE tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL",
            (time.time(), token_id),
        )
        self.conn.commit()
        return cur.rowcount > 0

    def list_tokens(self) -> list[TokenInfo]:
        rows = self.conn.execute(
            "SELECT id, label, scopes, namespace, created_at, revoked_at, expires_at "
            "FROM tokens ORDER BY id"
        ).fetchall()
        return [TokenInfo(r[0], r[1], frozenset(r[2].split(",")), r[3], r[4], r[5], r[6])
                for r in rows]
