import pytest

from repo_warden.store import Store, TokenInfo, VALID_SCOPES, _hash


# ---------------------------------------------------------------- happy path

def test_issue_and_authenticate():
    s = Store()
    token, info = s.issue_token("bot", {"repo:read"}, "acme/*")
    assert token.startswith("rw_")
    auth = s.authenticate(token)
    assert auth is not None
    assert auth.scopes == frozenset({"repo:read"})
    assert auth.namespace == "acme/*"


def test_issue_multiple_scopes_roundtrips_sorted():
    s = Store()
    token, info = s.issue_token("bot", {"repo:write", "branch:admin"})
    auth = s.authenticate(token)
    assert auth.scopes == frozenset({"repo:write", "branch:admin"})


def test_default_namespace_is_global():
    _, info = Store().issue_token("bot", {"repo:read"})
    assert info.namespace == "*"
    assert info.covers("anyone/anything")


# ---------------------------------------------------------------- namespaces

def test_namespace_glob_coverage():
    _, info = Store().issue_token("bot", {"repo:read"}, "acme/*")
    assert info.covers("acme/api")
    assert info.covers("acme/web")
    assert not info.covers("other/secrets")


def test_namespace_single_repo_exact():
    _, info = Store().issue_token("bot", {"repo:read"}, "acme/api")
    assert info.covers("acme/api")
    assert not info.covers("acme/apiv2")
    assert not info.covers("acme/web")


def test_namespace_question_mark_glob():
    _, info = Store().issue_token("bot", {"repo:read"}, "acme/ap?")
    assert info.covers("acme/api")
    assert not info.covers("acme/apiv2")


# ---------------------------------------------------------------- revocation

def test_revoke_blocks_auth():
    s = Store()
    token, info = s.issue_token("bot", {"repo:read"})
    assert s.authenticate(token) is not None
    assert s.revoke_token(info.id) is True
    assert s.authenticate(token) is None
    assert s.revoke_token(info.id) is False


def test_revoke_unknown_id_is_false():
    s = Store()
    assert s.revoke_token(999999) is False


def test_revoke_only_targets_that_token():
    s = Store()
    t1, i1 = s.issue_token("a", {"repo:read"})
    t2, i2 = s.issue_token("b", {"repo:read"})
    s.revoke_token(i1.id)
    assert s.authenticate(t1) is None
    assert s.authenticate(t2) is not None


def test_listed_revoked_token_is_inactive():
    s = Store()
    _, info = s.issue_token("bot", {"repo:read"})
    s.revoke_token(info.id)
    listed = {t.id: t for t in s.list_tokens()}
    assert listed[info.id].active is False
    assert listed[info.id].revoked_at is not None


# ---------------------------------------------------------------- validation / error paths

def test_unknown_scope_rejected():
    with pytest.raises(ValueError):
        Store().issue_token("bot", {"repo:god-mode"})


def test_mixed_valid_and_invalid_scopes_rejected_atomically():
    s = Store()
    with pytest.raises(ValueError):
        s.issue_token("bot", {"repo:read", "repo:nope"})
    # nothing was written
    assert s.list_tokens() == []


def test_empty_scopes_rejected():
    with pytest.raises(ValueError):
        Store().issue_token("bot", set())


def test_blank_label_rejected():
    with pytest.raises(ValueError):
        Store().issue_token("   ", {"repo:read"})


def test_empty_label_rejected():
    with pytest.raises(ValueError):
        Store().issue_token("", {"repo:read"})


def test_blank_namespace_rejected():
    with pytest.raises(ValueError):
        Store().issue_token("bot", {"repo:read"}, namespace="  ")


def test_authenticate_empty_token_is_none():
    s = Store()
    assert s.authenticate("") is None
    assert s.authenticate(None) is None


def test_authenticate_unknown_token_is_none():
    s = Store()
    s.issue_token("bot", {"repo:read"})
    assert s.authenticate("rw_does-not-exist") is None


# ---------------------------------------------------------------- storage hygiene

def test_only_hash_stored():
    s = Store()
    token, _ = s.issue_token("bot", {"repo:read"})
    row = s.conn.execute("SELECT token_hash FROM tokens").fetchone()
    assert token not in row[0]
    assert len(row[0]) == 64


def test_hash_is_deterministic_and_distinct():
    assert _hash("rw_abc") == _hash("rw_abc")
    assert _hash("rw_abc") != _hash("rw_abd")


def test_tokens_are_unique_across_issues():
    s = Store()
    seen = {s.issue_token(f"t{i}", {"repo:read"})[0] for i in range(50)}
    assert len(seen) == 50


def test_valid_scopes_constant_is_complete():
    assert VALID_SCOPES == {"repo:read", "repo:write", "branch:push",
                            "branch:admin", "repo:admin"}


def test_token_info_as_dict_shape():
    _, info = Store().issue_token("bot", {"repo:read", "repo:write"}, "acme/*")
    d = info.as_dict()
    assert d["label"] == "bot"
    assert d["namespace"] == "acme/*"
    assert d["active"] is True
    assert d["scopes"] == sorted(["repo:read", "repo:write"])


def test_list_tokens_ordered_by_id():
    s = Store()
    for name in ("a", "b", "c"):
        s.issue_token(name, {"repo:read"})
    ids = [t.id for t in s.list_tokens()]
    assert ids == sorted(ids)


def test_list_tokens_empty_store():
    assert Store().list_tokens() == []


# ---------------------------------------------------------------- persistence

def test_persists_to_disk(tmp_path):
    db = str(tmp_path / "warden.db")
    s = Store(db)
    token, info = s.issue_token("bot", {"repo:read"}, "acme/*")
    s.close()

    s2 = Store(db)
    auth = s2.authenticate(token)
    assert auth is not None
    assert auth.label == "bot"
    s2.close()


def test_close_is_idempotent_enough():
    s = Store()
    s.close()
    # a second close on a closed sqlite connection must not crash the caller
    try:
        s.close()
    except Exception:
        pytest.fail("close() raised on an already-closed store")
