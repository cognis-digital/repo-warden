"""Scenario 12 - least privilege under test.

A token can only ever do what its scope says — there is no implicit escalation.
This demo lines up every scope against an operation that sits one rung above it
and shows the denial: read can't push, push can't touch protected, write can't
force, and only admin clears the top. The point is that the *absence* of a scope
is a hard wall, not a soft suggestion.
"""
from _common import Action, BranchPolicy, Warden, fresh_store, rule, show


def main() -> None:
    store = fresh_store()
    rule("SCOPE ESCALATION BLOCKED  -  one rung up is always a DENY")

    warden = Warden(store, BranchPolicy(protected=["main"], allow_force=False))

    cases = [
        ("repo:read tries to push",       {"repo:read"},   Action("push", "acme/api", "feature/x")),
        ("branch:push tries protected",   {"branch:push"}, Action("push", "acme/api", "main")),
        ("repo:write tries force",        {"repo:write"},  Action("push", "acme/api", "feature/x", force=True)),
        ("branch:push tries del-protected", {"branch:push"}, Action("delete", "acme/api", "main")),
    ]
    print()
    for label, scopes, action in cases:
        token, _ = store.issue_token(label, scopes, "acme/*")
        d = warden.authorize(token, action)
        print(f"  {label}:")
        show(d, action)

    print("\nEvery line is a DENY — the scope you weren't granted is a scope you don't have.")
    store.close()


if __name__ == "__main__":
    main()
