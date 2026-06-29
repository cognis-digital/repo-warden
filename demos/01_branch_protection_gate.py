"""Scenario 1 - platform engineering.

The everyday job: one branch-protection policy, evaluated per operation, so the
*same* token gets ALLOW on a feature branch and DENY on `main`. This is what you
wire into a server-side hook so the rule lives next to the remote, not in a wiki.
"""
from _common import Action, BranchPolicy, Warden, fresh_store, rule, show


def main() -> None:
    store = fresh_store()
    rule("BRANCH PROTECTION GATE  -  one policy, evaluated per operation")

    # Policy: main + release/* are protected; no force-push, no protected deletes.
    policy = BranchPolicy(protected=["main", "release/*"], allow_force=False)
    warden = Warden(store, policy)
    print(f"\nPolicy: protected={policy.protected}  allow_force={policy.allow_force}")

    # A CI bot that may push, but is not a branch admin.
    token, info = store.issue_token("ci-bot", {"branch:push"}, namespace="acme/*")
    print(f"Token : label='{info.label}' scopes={sorted(info.scopes)} namespace='{info.namespace}'\n")

    attempts = [
        Action("push",   "acme/api", "feature/login"),    # routine work -> allow
        Action("push",   "acme/api", "main"),             # protected     -> deny
        Action("push",   "acme/web", "release/2026.6"),   # protected glob -> deny
        Action("push",   "acme/api", "hotfix", force=True),  # force gate   -> deny
        Action("delete", "acme/api", "main"),             # protected del -> deny
        Action("push",   "other/secrets", "feature/x"),   # out of namespace -> deny
    ]
    for a in attempts:
        show(warden.authorize(token, a), a)

    print("\nSame credential, six outcomes — the decision is the policy, not the person.")
    print("Each decision carries a rule tag (push / protected-branch / force-push / ...) for logging.")
    store.close()


if __name__ == "__main__":
    main()
