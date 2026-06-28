from repo_warden.deviceflow import DeviceFlow
from repo_warden.store import Store


def make():
    store = Store()
    return store, DeviceFlow(store, interval=5, lifetime=600)


def test_full_happy_path():
    store, flow = make()
    start = flow.start_authorization("ci", {"branch:push"}, "acme/*", now=1000)
    assert "-" in start["user_code"]
    assert start["interval"] == 5

    # poll before approval -> pending
    assert flow.poll(start["device_code"], now=1001)["error"] == "authorization_pending"

    # operator approves
    assert flow.approve(start["user_code"], "alice", now=1010) is True

    # poll after interval -> get the token, exactly once
    res = flow.poll(start["device_code"], now=1020)
    assert "access_token" in res
    assert res["token_type"] == "Bearer"
    token = res["access_token"]
    assert store.authenticate(token) is not None

    # token is delivered only once
    assert flow.poll(start["device_code"], now=1030).get("error") == "access_denied"


def test_slow_down_enforced():
    store, flow = make()
    start = flow.start_authorization("ci", {"repo:read"}, now=1000)
    flow.poll(start["device_code"], now=1001)              # records last_poll
    # polling again within the interval -> slow_down
    assert flow.poll(start["device_code"], now=1002)["error"] == "slow_down"
    # after the interval -> back to pending
    assert flow.poll(start["device_code"], now=1010)["error"] == "authorization_pending"


def test_expiry():
    store, flow = make()
    start = flow.start_authorization("ci", {"repo:read"}, now=1000)
    assert flow.poll(start["device_code"], now=2000)["error"] == "expired_token"
    # cannot approve an expired request
    assert flow.approve(start["user_code"], "alice", now=2000) is False


def test_deny():
    store, flow = make()
    start = flow.start_authorization("ci", {"repo:read"}, now=1000)
    assert flow.deny(start["user_code"]) is True
    assert flow.poll(start["device_code"], now=1001)["error"] == "access_denied"


def test_invalid_device_code():
    store, flow = make()
    assert flow.poll("nonexistent")["error"] == "invalid_grant"
