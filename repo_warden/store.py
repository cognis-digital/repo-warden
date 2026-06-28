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
    revoked_at REAL
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

    @property
    def active(self) -> bool:
        return self.revoked_at is None

    def covers(self, repo: str) -> bool:
        """Does this token's namespace glob include the given owner/repo?"""
        return fnmatch(repo, self.namespace)

    def as_dict(self) -> dict:
        return {"id": self.id, "label": self.label, "scopes": sorted(self.scopes),
                "namespace": self.namespace, "active": self.active}


class Store:
    def __init__(self, db_path: str = ":memory:"):
        self.conn = sqlite3.connect(db_path)
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # ---- tokens ----------------------------------------------------------
    def issue_token(self, label: str, scopes: set[str], namespace: str = "*",
                    *, now: Optional[float] = None) -> tuple[str, TokenInfo]:
        bad = scopes - VALID_SCOPES
        if bad:
            raise ValueError(f"unknown scopes: {sorted(bad)}")
        token = "rw_" + secrets.token_urlsafe(32)
        created = time.time() if now is None else now
        cur = self.conn.execute(
            "INSERT INTO tokens(label, token_hash, scopes, namespace, created_at) "
            "VALUES(?,?,?,?,?)",
            (label, _hash(token), ",".join(sorted(scopes)), namespace, created),
        )
        self.conn.commit()
        info = TokenInfo(int(cur.lastrowid), label, frozenset(scopes), namespace, created, None)
        return token, info

    def authenticate(self, token: str) -> Optional[TokenInfo]:
        row = self.conn.execute(
            "SELECT id, label, scopes, namespace, created_at, revoked_at FROM tokens "
            "WHERE token_hash=?",
            (_hash(token),),
        ).fetchone()
        if not row or row[5] is not None:
            return None
        return TokenInfo(row[0], row[1], frozenset(row[2].split(",")), row[3], row[4], None)

    def revoke_token(self, token_id: int) -> bool:
        cur = self.conn.execute(
            "UPDATE tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL",
            (time.time(), token_id),
        )
        self.conn.commit()
        return cur.rowcount > 0

    def list_tokens(self) -> list[TokenInfo]:
        rows = self.conn.execute(
            "SELECT id, label, scopes, namespace, created_at, revoked_at FROM tokens ORDER BY id"
        ).fetchall()
        return [TokenInfo(r[0], r[1], frozenset(r[2].split(",")), r[3], r[4], r[5]) for r in rows]
