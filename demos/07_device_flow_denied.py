"""Scenario 7 - approver vetting an unexpected request.

Not every device-flow request should be approved. An operator who sees a code
they didn't initiate denies it — and the agent must receive `access_denied`,
never a token. This demo shows an operator denying a request, the agent learning
it was rejected, and that a denied code can't later be salvaged by an approve.
"""
from _common import DeviceFlow, fresh_store, rule


def main() -> None:
    store = fresh_store()
    rule("DEVICE FLOW DENIED  -  operator rejects a request they didn't expect")

    flow = DeviceFlow(store)
    t = 2000.0
    start = flow.start_authorization("unknown-agent", {"repo:admin"}, "*", now=t)
    print(f"\nagent: device start -> user_code={start['user_code']}  "
          f"scopes asked: repo:admin on '*'  (broad! worth a second look)")

    print(f"agent: poll -> {flow.poll(start['device_code'], now=t + 1)['error']}")

    denied = flow.deny(start["user_code"])
    print(f"\noperator: this isn't mine -> deny({start['user_code']}) -> {denied}")

    print(f"\nagent: poll -> {flow.poll(start['device_code'], now=t + 6)['error']}  "
          "(no token issued)")

    # A denied request cannot be rescued by a late approval.
    late = flow.approve(start["user_code"], "alice", now=t + 7)
    print(f"operator: approve after deny -> {late}  (denial is final)")

    issued = store.list_tokens()
    print(f"\nTokens issued by this request: {len(issued)}  -> a denial mints nothing.")
    store.close()


if __name__ == "__main__":
    main()
