"""Scenario 10 - history-rewrite governance.

Force-pushes rewrite history; most teams want them off by default and only on
under an explicit policy or for branch admins. This demo runs the same
force-push under three regimes: default (off), policy `allow_force=True`, and a
branch:admin token that bypasses the gate — and shows the rule tag each time.
"""
from _common import Action, BranchPolicy, Warden, fresh_store, rule, show


def main() -> None:
    store = fresh_store()
    rule("FORCE-PUSH POLICY  -  who may rewrite history, and under what rule")

    force = Action("push", "acme/api", "feature/x", force=True)

    print("\n1) default policy (allow_force=False), repo:write token:")
    w = Warden(store, BranchPolicy(allow_force=False))
    tok, _ = store.issue_token("writer", {"repo:write"}, "acme/*")
    show(w.authorize(tok, force), force)

    print("\n2) policy explicitly permits force, same write token:")
    w2 = Warden(store, BranchPolicy(allow_force=True))
    tok2, _ = store.issue_token("writer2", {"repo:write"}, "acme/*")
    show(w2.authorize(tok2, force), force)

    print("\n3) default policy, but a branch:admin token (admins bypass the gate):")
    w3 = Warden(store, BranchPolicy(allow_force=False))
    tok3, _ = store.issue_token("admin", {"branch:admin"}, "acme/*")
    show(w3.authorize(tok3, force), force)

    print("\n4) force-push to a *protected* branch is denied on protection first:")
    protected_force = Action("push", "acme/api", "main", force=True)
    show(w2.authorize(tok2, protected_force), protected_force)

    print("\nForce is a policy decision plus a scope — never an accident.")
    store.close()


if __name__ == "__main__":
    main()
