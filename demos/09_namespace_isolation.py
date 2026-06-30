"""Scenario 9 - multi-tenant platform.

One warden, many tenants. Each tenant's token is bound to a repo namespace glob,
and the namespace is checked *before* any scope — so even a repo:admin token for
`tenant-a/*` cannot read, push to, or delete anything under `tenant-b/*`. This
demo issues admin tokens for two tenants and proves the wall holds both ways.
"""
from _common import Action, Warden, fresh_store, rule, show


def main() -> None:
    store = fresh_store()
    rule("NAMESPACE ISOLATION  -  a tenant admin token stops at the tenant boundary")

    warden = Warden(store)
    tok_a, _ = store.issue_token("tenant-a-admin", {"repo:admin"}, namespace="tenant-a/*")
    tok_b, _ = store.issue_token("tenant-b-admin", {"repo:admin"}, namespace="tenant-b/*")
    print("\nIssued repo:admin tokens for tenant-a/* and tenant-b/*\n")

    print("tenant-a admin acting on its own repos:")
    for a in [Action("read", "tenant-a/api"),
              Action("push", "tenant-a/api", "main"),
              Action("delete", "tenant-a/web", "main")]:
        show(warden.authorize(tok_a, a), a)

    print("\ntenant-a admin reaching into tenant-b (must fail on namespace):")
    for a in [Action("read", "tenant-b/secrets"),
              Action("push", "tenant-b/api", "main")]:
        show(warden.authorize(tok_a, a), a)

    print("\nand the reverse, tenant-b admin into tenant-a:")
    show(warden.authorize(tok_b, Action("read", "tenant-a/api")),
         Action("read", "tenant-a/api"))

    print("\nNamespace is enforced before scope: admin in your tenant, nobody in another.")
    store.close()


if __name__ == "__main__":
    main()
