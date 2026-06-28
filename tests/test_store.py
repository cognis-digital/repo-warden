import pytest

from repo_warden.store import Store


def test_issue_and_authenticate():
    s = Store()
    token, info = s.issue_token("bot", {"repo:read"}, "acme/*")
    assert token.startswith("rw_")
    auth = s.authenticate(token)
    assert auth is not None
    assert auth.scopes == frozenset({"repo:read"})
    assert auth.namespace == "acme/*"


def test_namespace_glob_coverage():
    _, info = Store().issue_token("bot", {"repo:read"}, "acme/*")
    assert info.covers("acme/api")
    assert info.covers("acme/web")
    assert not info.covers("other/secrets")


def test_revoke_blocks_auth():
    s = Store()
    token, info = s.issue_token("bot", {"repo:read"})
    assert s.authenticate(token) is not None
    assert s.revoke_token(info.id) is True
    assert s.authenticate(token) is None
    assert s.revoke_token(info.id) is False


def test_unknown_scope_rejected():
    with pytest.raises(ValueError):
        Store().issue_token("bot", {"repo:god-mode"})


def test_only_hash_stored():
    s = Store()
    token, _ = s.issue_token("bot", {"repo:read"})
    row = s.conn.execute("SELECT token_hash FROM tokens").fetchone()
    assert token not in row[0]
    assert len(row[0]) == 64
