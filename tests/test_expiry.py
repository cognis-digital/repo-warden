"""Token expiry (short-lived credentials).

`issue_token(..., expires_in=N)` mints a token that fails closed once N seconds
have elapsed, with no revocation call needed. The default (expires_in=None)
keeps the original never-expires behaviour, so the public API is unchanged for
existing callers.
"""
import pytest

from repo_warden.store import Store
from repo_warden.warden import Action, Warden


def test_default_token_never_expires():
    s = Store()
    _, info = s.issue_token("bot", {"repo:read"}, now=1000)
    assert info.expires_at is None
    assert info.is_expired(now=10**12) is False
    assert info.is_active(now=10**12) is True


def test_token_authenticates_before_expiry():
    s = Store()
    token, info = s.issue_token("ephemeral", {"repo:read"}, expires_in=600, now=1000)
    assert info.expires_at == 1600
    assert s.authenticate(token, now=1500) is not None


def test_token_fails_closed_after_expiry():
    s = Store()
    token, _ = s.issue_token("ephemeral", {"repo:read"}, expires_in=600, now=1000)
    assert s.authenticate(token, now=1601) is None


def test_expiry_boundary_is_inclusive():
    # at exactly expires_at the token is considered expired (now >= expires_at)
    s = Store()
    token, _ = s.issue_token("ephemeral", {"repo:read"}, expires_in=600, now=1000)
    assert s.authenticate(token, now=1599) is not None
    assert s.authenticate(token, now=1600) is None


def test_negative_or_zero_expires_in_rejected():
    s = Store()
    with pytest.raises(ValueError):
        s.issue_token("bot", {"repo:read"}, expires_in=0)
    with pytest.raises(ValueError):
        s.issue_token("bot", {"repo:read"}, expires_in=-5)


def test_is_active_combines_revocation_and_expiry():
    s = Store()
    _, info = s.issue_token("bot", {"repo:read"}, expires_in=600, now=1000)
    assert info.is_active(now=1200) is True
    assert info.is_active(now=2000) is False   # expired
    assert info.active is True                  # .active alone ignores expiry


def test_as_dict_reports_expiry_and_active():
    s = Store()
    _, info = s.issue_token("bot", {"repo:read"}, expires_in=600, now=1000)
    d = info.as_dict()
    assert "expires_at" in d and d["expires_at"] == 1600
    # never-expiring token omits the field
    _, info2 = s.issue_token("perm", {"repo:read"})
    assert "expires_at" not in info2.as_dict()


def test_warden_denies_expired_token():
    # the warden uses real wall-clock time; mint a token that is already expired
    s = Store()
    token, _ = s.issue_token("ephemeral", {"repo:write"}, "acme/*",
                             expires_in=1, now=0)   # expired ages ago
    w = Warden(s)
    d = w.authorize(token, Action("push", "acme/api", "feature/x"))
    assert not d.allowed and d.rule == "auth"


def test_warden_allows_live_token():
    s = Store()
    # expires_in far in the future relative to wall clock
    token, _ = s.issue_token("ephemeral", {"repo:write"}, "acme/*",
                             expires_in=10**9)
    w = Warden(s)
    assert w.authorize(token, Action("push", "acme/api", "feature/x")).allowed


def test_expiry_persists_to_disk(tmp_path):
    db = str(tmp_path / "warden.db")
    s = Store(db)
    token, _ = s.issue_token("ephemeral", {"repo:read"}, expires_in=600, now=1000)
    s.close()
    s2 = Store(db)
    assert s2.authenticate(token, now=1500) is not None
    assert s2.authenticate(token, now=1700) is None
    s2.close()


def test_migration_adds_column_to_old_db(tmp_path):
    # simulate a pre-expiry database: create the table without expires_at
    import sqlite3
    db = str(tmp_path / "old.db")
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT, "
        "token_hash TEXT UNIQUE, scopes TEXT, namespace TEXT, created_at REAL, revoked_at REAL)")
    conn.commit()
    conn.close()

    # opening through Store must migrate it and then accept expiring tokens
    s = Store(db)
    cols = {r[1] for r in s.conn.execute("PRAGMA table_info(tokens)")}
    assert "expires_at" in cols
    token, _ = s.issue_token("bot", {"repo:read"}, expires_in=600, now=1000)
    assert s.authenticate(token, now=1200) is not None
    assert s.authenticate(token, now=2000) is None
    s.close()
