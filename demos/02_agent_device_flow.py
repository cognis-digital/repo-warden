"""Scenario 2 - teams handing repo access to AI agents / CI.

A headless agent can't pop a browser, and you don't want to paste a long-lived
secret into its config. The OAuth 2.0 Device Authorization Grant (RFC 8628) is
the right shape: the agent asks for access, shows a short code, and *polls*
while a human approves that code out of band. This plays both sides of that
conversation against the real DeviceFlow — including the RFC error codes.
"""
from _common import Action, DeviceFlow, Warden, fresh_store, rule, show


def main() -> None:
    store = fresh_store()
    rule("AGENT DEVICE FLOW  -  RFC 8628, scoped to one repo, approved out of band")

    flow = DeviceFlow(store)
    t = 1000.0  # deterministic clock so the demo is reproducible

    # 1) Agent starts authorization for a narrow grant.
    start = flow.start_authorization("coding-agent", {"branch:push"}, namespace="acme/*", now=t)
    print(f"\n1) agent: device start  -> user_code={start['user_code']}  "
          f"verify_at={start['verification_uri']}  interval={start['interval']}s")
    device_code = start["device_code"]

    # 2) Agent polls before approval -> RFC 'authorization_pending'.
    t += 1
    print(f"2) agent: poll          -> {flow.poll(device_code, now=t)['error']}")

    # 3) Agent polls again too soon -> RFC 'slow_down' (interval not elapsed).
    t += 1
    print(f"3) agent: poll (too soon) -> {flow.poll(device_code, now=t)['error']}")

    # 4) A human approves the short code out of band.
    t += 5
    ok = flow.approve(start["user_code"], subject="alice@acme", now=t)
    print(f"4) human: approve {start['user_code']} as alice@acme -> {ok}")

    # 5) Agent polls after the interval and receives the token exactly once.
    t += 6
    grant = flow.poll(device_code, now=t)
    token = grant["access_token"]
    print(f"5) agent: poll          -> token={token[:9]}...  scope={grant['scope']}  "
          f"namespace={grant['namespace']}")

    # 6) The delivered token is real: it authorizes a push to a feature branch.
    warden = Warden(store)
    print("\n   The agent now holds a scoped, revocable credential:")
    for a in [Action("push", "acme/api", "feature/x"),   # in scope  -> allow
              Action("push", "acme/api", "main")]:        # protected -> deny
        show(warden.authorize(token, a), a)

    print("\nThe token was delivered once and is bound to acme/* + branch:push — nothing more.")
    store.close()


if __name__ == "__main__":
    main()
