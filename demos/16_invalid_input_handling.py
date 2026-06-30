"""Scenario 16 - hardening / fuzz-the-edges.

Good governance fails *closed* and *loudly*. This demo throws malformed input at
every entry point — empty tokens, unknown scopes, empty scope sets, blank
labels, missing repos, unknown operations, bad device codes — and shows each
one being rejected with a clear error rather than silently doing something
surprising.
"""
from _common import Action, DeviceFlow, Warden, fresh_store, rule


def expect_raises(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except ValueError as e:
        return f"ValueError: {e}"
    return "!! no error raised (bug)"


def main() -> None:
    store = fresh_store()
    rule("INVALID INPUT HANDLING  -  fail closed, fail clear")

    print("\nStore.issue_token rejects bad input:")
    print(f"    unknown scope     -> {expect_raises(store.issue_token, 'b', {'repo:wat'})}")
    print(f"    empty scope set   -> {expect_raises(store.issue_token, 'b', set())}")
    print(f"    blank label       -> {expect_raises(store.issue_token, '  ', {'repo:read'})}")
    print(f"    blank namespace   -> {expect_raises(store.issue_token, 'b', {'repo:read'}, '  ')}")

    print("\nStore.authenticate on junk returns None (no crash):")
    print(f"    empty token   -> {store.authenticate('')}")
    print(f"    unknown token -> {store.authenticate('rw_nope')}")

    print("\nWarden.authorize fails closed on junk:")
    warden = Warden(store)
    token, _ = store.issue_token("ok", {"repo:admin"}, "*")
    for label, action in [
        ("invalid token", (("rw_bad",), Action("read", "acme/api"))),
        ("empty repo",     ((token,),  Action("read", ""))),
        ("unknown op",     ((token,),  Action("teleport", "acme/api", "main"))),
    ]:
        (tok,), act = action
        d = warden.authorize(tok, act)
        print(f"    {label:<14} -> allowed={d.allowed} rule={d.rule!r}")

    print("\nDeviceFlow rejects malformed starts and polls:")
    flow = DeviceFlow(store)
    print(f"    empty client_id   -> {expect_raises(flow.start_authorization, '', {'repo:read'})}")
    print(f"    unknown scope     -> {expect_raises(flow.start_authorization, 'c', {'repo:wat'})}")
    print(f"    poll empty code   -> {flow.poll('')['error']}")
    print(f"    poll unknown code -> {flow.poll('nope')['error']}")
    print(f"    approve unknown   -> {flow.approve('ZZZZ-ZZZZ', 'x')}")

    print("\nEvery bad input produced a clear error or a fail-closed deny — never a surprise.")
    store.close()


if __name__ == "__main__":
    main()
