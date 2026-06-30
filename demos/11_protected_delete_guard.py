"""Scenario 11 - 'who deleted main?' prevention.

Deleting a protected branch is one keystroke from a very bad afternoon.
repo-warden treats a delete of a protected ref like a privileged op: a plain
writer is denied, a branch admin is allowed, and an explicit
`allow_delete_protected` policy can open it for a break-glass window. This demo
contrasts an unprotected delete (fine) with protected deletes under each regime.
"""
from _common import Action, BranchPolicy, Warden, fresh_store, rule, show


def main() -> None:
    store = fresh_store()
    rule("PROTECTED DELETE GUARD  -  nobody fat-fingers `main` away")

    warden = Warden(store, BranchPolicy(protected=["main", "release/*"]))
    writer, _ = store.issue_token("writer", {"repo:write"}, "acme/*")

    print("\ndeleting an unprotected feature branch (routine cleanup):")
    a = Action("delete", "acme/api", "feature/old")
    show(warden.authorize(writer, a), a)

    print("\nwriter deleting protected refs (must be denied):")
    for a in [Action("delete", "acme/api", "main"),
              Action("delete", "acme/api", "release/2026.6")]:
        show(warden.authorize(writer, a), a)

    print("\nbranch admin deleting a protected ref (allowed):")
    admin, _ = store.issue_token("admin", {"branch:admin"}, "acme/*")
    a = Action("delete", "acme/api", "main")
    show(warden.authorize(admin, a), a)

    print("\nbreak-glass policy allow_delete_protected=True (writer, allowed):")
    glass = Warden(store, BranchPolicy(protected=["main"], allow_delete_protected=True))
    a = Action("delete", "acme/api", "main")
    show(glass.authorize(writer, a), a)

    print("\nProtected deletes are privileged by default; opening them is a deliberate act.")
    store.close()


if __name__ == "__main__":
    main()
