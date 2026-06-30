from repo_warden.store import Store
from repo_warden.warden import Action, BranchPolicy, Decision, Warden


def setup(scopes, namespace="acme/*", policy=None):
    store = Store()
    token, _ = store.issue_token("t", set(scopes), namespace)
    return Warden(store, policy), token


# ---------------------------------------------------------------- auth / namespace

def test_invalid_token_denied():
    w, _ = setup({"repo:read"})
    d = w.authorize("rw_bogus", Action("read", "acme/api"))
    assert not d.allowed and d.rule == "auth"


def test_empty_token_denied():
    w, _ = setup({"repo:read"})
    d = w.authorize("", Action("read", "acme/api"))
    assert not d.allowed and d.rule == "auth"


def test_revoked_token_denied():
    store = Store()
    token, info = store.issue_token("t", {"repo:write"}, "acme/*")
    w = Warden(store)
    assert w.authorize(token, Action("push", "acme/api", "dev")).allowed
    store.revoke_token(info.id)
    d = w.authorize(token, Action("push", "acme/api", "dev"))
    assert not d.allowed and d.rule == "auth"


def test_namespace_enforced():
    w, token = setup({"repo:write"}, namespace="acme/*")
    d = w.authorize(token, Action("push", "other/secrets", "dev"))
    assert not d.allowed and d.rule == "namespace"


def test_namespace_checked_before_scope():
    # even a repo:admin token cannot reach outside its namespace
    w, token = setup({"repo:admin"}, namespace="acme/*")
    d = w.authorize(token, Action("read", "other/secret"))
    assert not d.allowed and d.rule == "namespace"


def test_empty_repo_denied():
    w, token = setup({"repo:admin"}, namespace="*")
    d = w.authorize(token, Action("read", ""))
    assert not d.allowed and d.rule == "namespace"


# ---------------------------------------------------------------- read

def test_read_requires_read_scope():
    w, token = setup({"branch:push"})  # push but not read
    d = w.authorize(token, Action("read", "acme/api"))
    assert not d.allowed and d.rule == "read"


def test_read_allowed_with_write_scope():
    w, token = setup({"repo:write"})
    assert w.authorize(token, Action("read", "acme/api")).allowed


def test_read_allowed_with_read_scope():
    w, token = setup({"repo:read"})
    assert w.authorize(token, Action("read", "acme/api")).allowed


# ---------------------------------------------------------------- push

def test_push_to_unprotected_branch():
    w, token = setup({"branch:push"})
    d = w.authorize(token, Action("push", "acme/api", "feature/x"))
    assert d.allowed and d.rule == "push"


def test_push_without_any_push_scope_denied():
    w, token = setup({"repo:read"})
    d = w.authorize(token, Action("push", "acme/api", "feature/x"))
    assert not d.allowed and d.rule == "push"


def test_push_to_protected_requires_admin():
    w, token = setup({"branch:push"})
    d = w.authorize(token, Action("push", "acme/api", "main"))
    assert not d.allowed and d.rule == "protected-branch"

    w2, token2 = setup({"branch:admin"})
    assert w2.authorize(token2, Action("push", "acme/api", "main")).allowed


def test_push_to_release_glob_is_protected():
    w, token = setup({"branch:push"})  # default policy protects release/*
    d = w.authorize(token, Action("push", "acme/api", "release/2026.6"))
    assert not d.allowed and d.rule == "protected-branch"


def test_push_with_no_branch_is_unprotected():
    # branch=None must not be treated as protected
    w, token = setup({"branch:push"})
    d = w.authorize(token, Action("push", "acme/api", None))
    assert d.allowed and d.rule == "push"


# ---------------------------------------------------------------- force-push

def test_force_push_blocked_by_default():
    w2, token2 = setup({"repo:write"})
    d2 = w2.authorize(token2, Action("push", "acme/api", "feature/x", force=True))
    assert not d2.allowed and d2.rule == "force-push"


def test_force_push_allowed_when_policy_permits():
    w, token = setup({"repo:write"}, policy=BranchPolicy(allow_force=True))
    d = w.authorize(token, Action("push", "acme/api", "feature/x", force=True))
    assert d.allowed


def test_admin_bypasses_force_gate():
    # branch:admin may force-push even when policy.allow_force is False
    w, token = setup({"branch:admin"})
    d = w.authorize(token, Action("push", "acme/api", "feature/x", force=True))
    assert d.allowed


def test_protected_check_precedes_force_check():
    # a write-only token force-pushing to main is denied on protection, not force
    w, token = setup({"repo:write"}, policy=BranchPolicy(allow_force=True))
    d = w.authorize(token, Action("push", "acme/api", "main", force=True))
    assert not d.allowed and d.rule == "protected-branch"


# ---------------------------------------------------------------- delete

def test_delete_unprotected_branch_allowed():
    w, token = setup({"branch:push"})
    d = w.authorize(token, Action("delete", "acme/api", "feature/x"))
    assert d.allowed and d.rule == "delete"


def test_delete_protected_branch_requires_admin():
    w, token = setup({"repo:write"})
    d = w.authorize(token, Action("delete", "acme/api", "main"))
    assert not d.allowed and d.rule == "delete-protected"
    w2, token2 = setup({"branch:admin"})
    assert w2.authorize(token2, Action("delete", "acme/api", "main")).allowed


def test_delete_protected_allowed_when_policy_permits():
    w, token = setup({"repo:write"},
                     policy=BranchPolicy(allow_delete_protected=True))
    d = w.authorize(token, Action("delete", "acme/api", "main"))
    assert d.allowed and d.rule == "delete"


def test_delete_without_push_scope_denied():
    w, token = setup({"repo:read"})
    d = w.authorize(token, Action("delete", "acme/api", "feature/x"))
    assert not d.allowed and d.rule == "push"


# ---------------------------------------------------------------- admin / misc

def test_repo_admin_can_do_anything_in_namespace():
    w, token = setup({"repo:admin"})
    assert w.authorize(token, Action("read", "acme/api")).allowed
    assert w.authorize(token, Action("push", "acme/api", "main")).allowed
    assert w.authorize(token, Action("delete", "acme/api", "main")).allowed


def test_unknown_operation_denied():
    w, token = setup({"repo:admin"})
    d = w.authorize(token, Action("rebase", "acme/api", "main"))
    assert not d.allowed and d.rule == "unknown-op"


def test_decision_as_dict_shape():
    d = Decision(True, "push", "")
    assert d.as_dict() == {"allowed": True, "rule": "push", "reason": ""}


# ---------------------------------------------------------------- BranchPolicy

def test_branch_policy_defaults_protect_main_and_master():
    p = BranchPolicy()
    assert p.is_protected("main")
    assert p.is_protected("master")
    assert p.is_protected("release/2026.6")
    assert not p.is_protected("feature/x")


def test_branch_policy_none_branch_not_protected():
    assert BranchPolicy().is_protected(None) is False


def test_branch_policy_custom_globs():
    p = BranchPolicy(protected=["prod/*"])
    assert p.is_protected("prod/eu")
    assert not p.is_protected("main")
