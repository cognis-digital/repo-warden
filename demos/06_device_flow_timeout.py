"""Scenario 6 - SRE / on-call.

The unhappy device-flow path: nobody approves the code in time. RFC 8628 says
the request *expires*, and a well-behaved coordinator must keep saying
`expired_token` on every subsequent poll — not start lying with `invalid_grant`.
This demo walks a request straight past its lifetime and shows the agent's poll
loop terminating cleanly instead of spinning forever.
"""
from _common import DeviceFlow, fresh_store, rule


def main() -> None:
    store = fresh_store()
    rule("DEVICE FLOW TIMEOUT  -  the request nobody approved in time")

    flow = DeviceFlow(store, lifetime=600, interval=5)
    t = 1000.0
    start = flow.start_authorization("ci-runner", {"branch:push"}, "acme/*", now=t)
    print(f"\nagent: device start -> user_code={start['user_code']}  "
          f"expires_in={start['expires_in']}s")

    # The agent polls patiently while no human approves.
    for dt in (1, 120, 300, 599):
        r = flow.poll(start["device_code"], now=t + dt)
        print(f"  +{dt:>4}s  poll -> {r.get('error')}")

    # Past the lifetime: expired, and it stays expired (the regression we guard).
    print("\n  --- lifetime elapses, still no approval ---")
    for dt in (601, 700, 9000):
        r = flow.poll(start["device_code"], now=t + dt)
        print(f"  +{dt:>4}s  poll -> {r.get('error')}")

    # Approving an expired request is refused.
    ok = flow.approve(start["user_code"], "alice", now=t + 9000)
    print(f"\noperator: approve after expiry -> {ok}  (too late; mint a new code)")
    print("\nThe agent's poll loop sees a stable terminal state and exits, "
          "instead of hanging.")
    store.close()


if __name__ == "__main__":
    main()
