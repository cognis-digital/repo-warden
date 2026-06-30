"""Scenario 13 - operations / audit.

A credential's whole life in one view: issue, authenticate, list (active), use,
revoke, list again (inactive), and confirm the revoked token authenticates to
nothing. This is the inventory an operator reasons about during an audit — what
exists, what's live, and what got killed.
"""
from _common import Action, Warden, fresh_store, rule, show


def dump(store) -> None:
    for t in store.list_tokens():
        state = "active " if t.active else "REVOKED"
        print(f"    id={t.id} [{state}] '{t.label}' {sorted(t.scopes)} ns={t.namespace}")


def main() -> None:
    store = fresh_store()
    rule("TOKEN LIFECYCLE  -  issue, use, revoke, audit")

    warden = Warden(store)
    print("\n1) issue two tokens:")
    bot, bot_info = store.issue_token("ci-bot", {"branch:push"}, "acme/*")
    ro, _ = store.issue_token("dashboard", {"repo:read"}, "acme/*")
    dump(store)

    print("\n2) both authenticate, and the bot can push a feature branch:")
    print(f"    authenticate(ci-bot)   -> {store.authenticate(bot) is not None}")
    print(f"    authenticate(dashboard)-> {store.authenticate(ro) is not None}")
    a = Action("push", "acme/api", "feature/x")
    show(warden.authorize(bot, a), a)

    print(f"\n3) incident: revoke ci-bot (id={bot_info.id}):")
    print(f"    revoke_token({bot_info.id}) -> {store.revoke_token(bot_info.id)}")
    dump(store)

    print("\n4) the revoked token now authenticates to nothing:")
    print(f"    authenticate(ci-bot) -> {store.authenticate(bot)}")
    show(warden.authorize(bot, a), a)

    print(f"\n5) re-revoking is a safe no-op -> {store.revoke_token(bot_info.id)}")
    print("\nThe audit answers: what exists, what's live, what's dead — from one table.")
    store.close()


if __name__ == "__main__":
    main()
