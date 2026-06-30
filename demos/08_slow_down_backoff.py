"""Scenario 8 - client implementers.

RFC 8628 §3.5: a client that polls faster than the advertised `interval` gets
`slow_down` and must back off. This demo drives a too-eager poll loop, shows the
coordinator emitting `slow_down`, and then a well-behaved loop that waits the
interval and gets a clean `authorization_pending` -> token.
"""
from _common import DeviceFlow, fresh_store, rule


def main() -> None:
    store = fresh_store()
    rule("SLOW DOWN BACKOFF  -  the coordinator throttles an over-eager client")

    flow = DeviceFlow(store, interval=5)
    t = 3000.0
    start = flow.start_authorization("eager-cli", {"repo:read"}, "acme/*", now=t)
    interval = start["interval"]
    print(f"\nadvertised interval: {interval}s\n")

    print("impatient client (polls every 1s):")
    last = None
    for dt in (0, 1, 2, 3):
        r = flow.poll(start["device_code"], now=t + dt)
        print(f"  +{dt}s -> {r['error']}")
        last = r["error"]
    assert last == "slow_down"

    print("\nwell-behaved client (waits the interval, then approval lands):")
    flow.approve(start["user_code"], "alice", now=t + 4)
    r = flow.poll(start["device_code"], now=t + interval + 1)
    print(f"  +{interval + 1}s -> {'access_token' if 'access_token' in r else r.get('error')}")
    print("\nRespecting `interval` is the difference between a token and a 429-storm.")
    store.close()


if __name__ == "__main__":
    main()
