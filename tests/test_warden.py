from repo_warden.store import Store
from repo_warden.warden import Action, BranchPolicy, Warden


def setup(scopes, namespace="acme/*", policy=None):
    store = Store()
    token, _ = store.issue_token("t", set(scopes), namespace)
    return Warden(store, policy), token


def test_invalid_token_denied():
    w, _ = setup({"repo:read"})
    d = w.authorize("rw_bogus", Action("read", "acme/api"))
    assert not d.allowed and d.rule == "auth"


def test_namespace_enforced():
    w, token = setup({"repo:write"}, namespace="acme/*")
    d = w.authorize(token, Action("push", "other/secrets", "dev"))
    assert not d.allowed and d.rule == "namespace"


def test_read_requires_read_scope():
    w, token = setup({"branch:push"})  # push but not read
    d = w.authorize(token, Action("read", "acme/api"))
    assert not d.allowed and d.rule == "read"


def test_push_to_unprotected_branch():
    w, token = setup({"branch:push"})
    d = w.authorize(token, Action("push", "acme/api", "feature/x"))
    assert d.allowed and d.rule == "push"


def test_push_to_protected_requires_admin():
    w, token = setup({"branch:push"})
    d = w.authorize(token, Action("push", "acme/api", "main"))
    assert not d.allowed and d.rule == "protected-branch"

    w2, token2 = setup({"branch:admin"})
    assert w2.authorize(token2, Action("push", "acme/api", "main")).allowed


def test_force_push_blocked_by_default():
    w, token = setup({"branch:admin"})  # admin can push protected...
    d = w.authorize(token, Action("push", "acme/api", "feature/x", force=True))
    # ...but admin also bypasses the force gate; use a write-only token instead
    w2, token2 = setup({"repo:write"})
    d2 = w2.authorize(token2, Action("push", "acme/api", "feature/x", force=True))
    assert not d2.allowed and d2.rule == "force-push"


def test_force_push_allowed_when_policy_permits():
    w, token = setup({"repo:write"}, policy=BranchPolicy(allow_force=True))
    d = w.authorize(token, Action("push", "acme/api", "feature/x", force=True))
    assert d.allowed


def test_delete_protected_branch_requires_admin():
    w, token = setup({"repo:write"})
    d = w.authorize(token, Action("delete", "acme/api", "main"))
    assert not d.allowed and d.rule == "delete-protected"
    w2, token2 = setup({"branch:admin"})
    assert w2.authorize(token2, Action("delete", "acme/api", "main")).allowed


def test_repo_admin_can_do_anything_in_namespace():
    w, token = setup({"repo:admin"})
    assert w.authorize(token, Action("read", "acme/api")).allowed
    assert w.authorize(token, Action("push", "acme/api", "main")).allowed
    assert w.authorize(token, Action("delete", "acme/api", "main")).allowed
