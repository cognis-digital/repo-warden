import pytest

from repo_warden.deviceflow import DeviceFlow, _user_code, DEFAULT_INTERVAL, DEFAULT_LIFETIME
from repo_warden.store import Store
from repo_warden.warden import Action, Warden


def make(interval=5, lifetime=600):
    store = Store()
    return store, DeviceFlow(store, interval=interval, lifetime=lifetime)


# ---------------------------------------------------------------- happy path

def test_full_happy_path():
    store, flow = make()
    start = flow.start_authorization("ci", {"branch:push"}, "acme/*", now=1000)
    assert "-" in start["user_code"]
    assert start["interval"] == 5

    assert flow.poll(start["device_code"], now=1001)["error"] == "authorization_pending"
    assert flow.approve(start["user_code"], "alice", now=1010) is True

    res = flow.poll(start["device_code"], now=1020)
    assert "access_token" in res
    assert res["token_type"] == "Bearer"
    token = res["access_token"]
    assert store.authenticate(token) is not None

    # token is delivered only once
    assert flow.poll(start["device_code"], now=1030).get("error") == "access_denied"


def test_start_authorization_shape():
    store, flow = make()
    start = flow.start_authorization("ci", {"repo:read"}, "acme/*", now=1000)
    assert start["expires_in"] == DEFAULT_LIFETIME
    assert start["interval"] == DEFAULT_INTERVAL
    assert start["verification_uri_complete"].endswith(start["user_code"])
    assert start["device_code"]


def test_delivered_token_carries_scope_and_namespace():
    store, flow = make()
    start = flow.start_authorization("ci", {"branch:push", "repo:read"}, "acme/*", now=1000)
    flow.approve(start["user_code"], "alice", now=1010)
    res = flow.poll(start["device_code"], now=1020)
    assert res["namespace"] == "acme/*"
    assert set(res["scope"].split(",")) == {"branch:push", "repo:read"}


# ---------------------------------------------------------------- slow_down / interval

def test_slow_down_enforced():
    store, flow = make()
    start = flow.start_authorization("ci", {"repo:read"}, now=1000)
    flow.poll(start["device_code"], now=1001)
    assert flow.poll(start["device_code"], now=1002)["error"] == "slow_down"
    assert flow.poll(start["device_code"], now=1010)["error"] == "authorization_pending"


def test_slow_down_does_not_advance_last_poll():
    # a slow_down response must not reset the interval clock
    store, flow = make(interval=5)
    start = flow.start_authorization("ci", {"repo:read"}, now=1000)
    flow.poll(start["device_code"], now=1000)              # last_poll=1000
    flow.poll(start["device_code"], now=1002)              # slow_down
    flow.poll(start["device_code"], now=1003)              # still slow_down
    # only at 1005+ does it clear
    assert flow.poll(start["device_code"], now=1006)["error"] == "authorization_pending"


def test_first_poll_never_slow_down():
    store, flow = make()
    start = flow.start_authorization("ci", {"repo:read"}, now=1000)
    assert flow.poll(start["device_code"], now=1000)["error"] == "authorization_pending"


def test_approved_token_delivered_without_waiting_interval():
    # regression: once approved, the token must be delivered on the very next
    # poll even if it falls inside the slow_down interval of the prior poll.
    store, flow = make(interval=5)
    start = flow.start_authorization("ci", {"repo:read"}, now=1000)
    flow.poll(start["device_code"], now=1000)               # last_poll=1000
    flow.approve(start["user_code"], "alice", now=1001)
    # poll 1s later (well inside the 5s interval) -> token, not slow_down
    res = flow.poll(start["device_code"], now=1002)
    assert "access_token" in res


# ---------------------------------------------------------------- expiry / timeouts

def test_expiry():
    store, flow = make()
    start = flow.start_authorization("ci", {"repo:read"}, now=1000)
    assert flow.poll(start["device_code"], now=2000)["error"] == "expired_token"
    assert flow.approve(start["user_code"], "alice", now=2000) is False


def test_expiry_persists_across_polls():
    # regression: a second poll after expiry must still say expired_token,
    # not invalid_grant
    store, flow = make(lifetime=600)
    start = flow.start_authorization("ci", {"repo:read"}, now=1000)
    assert flow.poll(start["device_code"], now=2000)["error"] == "expired_token"
    assert flow.poll(start["device_code"], now=2100)["error"] == "expired_token"


def test_expiry_exact_boundary_still_valid():
    # at exactly expires_at the request is not yet expired (now > expires_at)
    store, flow = make(lifetime=600)
    start = flow.start_authorization("ci", {"repo:read"}, now=1000)
    assert flow.poll(start["device_code"], now=1600)["error"] == "authorization_pending"
    assert flow.poll(start["device_code"], now=1601)["error"] == "expired_token"


def test_approved_then_expired_before_pickup():
    # operator approves, but the agent never polls in time -> expired
    store, flow = make(lifetime=600)
    start = flow.start_authorization("ci", {"repo:read"}, now=1000)
    assert flow.approve(start["user_code"], "alice", now=1010) is True
    assert flow.poll(start["device_code"], now=2000)["error"] == "expired_token"


# ---------------------------------------------------------------- denial

def test_deny():
    store, flow = make()
    start = flow.start_authorization("ci", {"repo:read"}, now=1000)
    assert flow.deny(start["user_code"]) is True
    assert flow.poll(start["device_code"], now=1001)["error"] == "access_denied"


def test_deny_unknown_user_code_is_false():
    store, flow = make()
    assert flow.deny("ZZZZ-ZZZZ") is False


def test_deny_empty_user_code_is_false():
    store, flow = make()
    assert flow.deny("") is False


def test_cannot_approve_after_deny():
    store, flow = make()
    start = flow.start_authorization("ci", {"repo:read"}, now=1000)
    flow.deny(start["user_code"])
    assert flow.approve(start["user_code"], "alice", now=1001) is False


def test_deny_after_approve_is_noop():
    # deny only acts on pending requests; an approved one is unaffected
    store, flow = make()
    start = flow.start_authorization("ci", {"repo:read"}, now=1000)
    flow.approve(start["user_code"], "alice", now=1010)
    assert flow.deny(start["user_code"]) is False


# ---------------------------------------------------------------- invalid input

def test_invalid_device_code():
    store, flow = make()
    assert flow.poll("nonexistent")["error"] == "invalid_grant"


def test_empty_device_code():
    store, flow = make()
    assert flow.poll("")["error"] == "invalid_grant"


def test_approve_unknown_user_code_is_false():
    store, flow = make()
    assert flow.approve("ZZZZ-ZZZZ", "alice", now=1000) is False


def test_approve_empty_subject_is_false():
    store, flow = make()
    start = flow.start_authorization("ci", {"repo:read"}, now=1000)
    assert flow.approve(start["user_code"], "", now=1001) is False


def test_start_rejects_unknown_scope():
    store, flow = make()
    with pytest.raises(ValueError):
        flow.start_authorization("ci", {"repo:wat"}, now=1000)
    # and no orphan row was created
    assert store.conn.execute("SELECT COUNT(*) FROM device_requests").fetchone()[0] == 0


def test_start_rejects_empty_scopes():
    store, flow = make()
    with pytest.raises(ValueError):
        flow.start_authorization("ci", set(), now=1000)


def test_start_rejects_empty_client_id():
    store, flow = make()
    with pytest.raises(ValueError):
        flow.start_authorization("", {"repo:read"}, now=1000)


# ---------------------------------------------------------------- double approve / scope denial

def test_double_approve_second_is_false():
    store, flow = make()
    start = flow.start_authorization("ci", {"repo:read"}, now=1000)
    assert flow.approve(start["user_code"], "alice", now=1010) is True
    assert flow.approve(start["user_code"], "bob", now=1011) is False


def test_delivered_token_only_has_granted_scope():
    # the device-flow grant cannot escalate beyond the requested scope:
    # a branch:push grant is denied a protected-branch push
    store, flow = make()
    start = flow.start_authorization("agent", {"branch:push"}, "acme/*", now=1000)
    flow.approve(start["user_code"], "alice", now=1010)
    token = flow.poll(start["device_code"], now=1020)["access_token"]

    warden = Warden(store)
    assert warden.authorize(token, Action("push", "acme/api", "feature/x")).allowed
    denied = warden.authorize(token, Action("push", "acme/api", "main"))
    assert not denied.allowed and denied.rule == "protected-branch"


def test_grant_is_namespace_bound():
    store, flow = make()
    start = flow.start_authorization("agent", {"repo:write"}, "acme/*", now=1000)
    flow.approve(start["user_code"], "alice", now=1010)
    token = flow.poll(start["device_code"], now=1020)["access_token"]
    warden = Warden(store)
    out = warden.authorize(token, Action("push", "other/repo", "dev"))
    assert not out.allowed and out.rule == "namespace"


def test_revocation_kills_device_issued_token():
    store, flow = make()
    start = flow.start_authorization("agent", {"repo:write"}, "acme/*", now=1000)
    flow.approve(start["user_code"], "alice", now=1010)
    token = flow.poll(start["device_code"], now=1020)["access_token"]

    # find the token row and revoke it
    info = store.authenticate(token)
    assert info is not None
    assert store.revoke_token(info.id) is True
    assert store.authenticate(token) is None


# ---------------------------------------------------------------- user code format

def test_user_code_format():
    code = _user_code()
    assert len(code) == 9 and code[4] == "-"
    no_vowels = set("AEIOU01")
    assert not (set(code.replace("-", "")) & no_vowels)


def test_user_codes_are_distinct():
    codes = {_user_code() for _ in range(200)}
    assert len(codes) > 190  # overwhelmingly unique
