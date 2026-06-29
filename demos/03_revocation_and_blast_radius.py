"""Scenario 3 - security.

The question after an incident is "kill that access — now". repo-warden stores
only a salted hash of each token and revocation is immediate, so a leaked or
suspect credential stops working on the next operation across every repo in its
namespace. This demo issues a token, proves it works, revokes it, and shows the
blast radius collapse to zero.
"""
from _common import Action, Warden, fresh_store, rule, show


def main() -> None:
    store = fresh_store()
    rule("REVOCATION & BLAST RADIUS  -  kill a credential the moment it's suspect")

    warden = Warden(store)
    token, info = store.issue_token("contractor-laptop", {"repo:write"}, namespace="acme/*")
    print(f"\nIssued token id={info.id} '{info.label}' scopes={sorted(info.scopes)} "
          f"namespace='{info.namespace}'")
    print("(only a BLAKE2b hash is stored — a DB leak does not leak a usable token)\n")

    probes = [Action("read", "acme/api"),
              Action("push", "acme/api", "feature/x"),
              Action("push", "acme/web", "develop")]

    print("BEFORE revocation — the contractor token works across the namespace:")
    for a in probes:
        show(warden.authorize(token, a), a)

    revoked = store.revoke_token(info.id)
    print(f"\n>>> incident: store.revoke_token({info.id}) -> {revoked}\n")

    print("AFTER revocation — every operation fails closed, immediately:")
    for a in probes:
        show(warden.authorize(token, a), a)

    active = [t.label for t in store.list_tokens() if t.active]
    print(f"\nActive tokens remaining: {active or '(none)'}")
    print("No host migration, no key rotation across services — one row, one revoke.")
    store.close()


if __name__ == "__main__":
    main()
