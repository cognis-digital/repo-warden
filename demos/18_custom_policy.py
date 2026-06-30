"""Scenario 18 - tailoring the branch policy to a repo's conventions.

The default policy protects main/master/release/*. Real repos differ: a
trunk-based shop protects only `trunk`; a GitFlow shop protects `develop` and
`hotfix/*`; an environment-promotion repo protects `env/prod`. This demo runs
the same push set against three custom `BranchPolicy` objects to show the policy
is data, not code you have to fork.
"""
from _common import Action, BranchPolicy, Warden, fresh_store, rule


POLICIES = {
    "trunk-based":  BranchPolicy(protected=["trunk"]),
    "gitflow":      BranchPolicy(protected=["develop", "hotfix/*", "release/*"]),
    "env-promote":  BranchPolicy(protected=["env/prod", "env/staging"]),
}

BRANCHES = ["trunk", "develop", "hotfix/urgent", "env/prod", "feature/x"]


def main() -> None:
    store = fresh_store()
    rule("CUSTOM POLICY  -  protection is configuration, not a code fork")

    token, _ = store.issue_token("dev", {"branch:push"}, "acme/*")

    col = 16
    header = "  branch \\ policy " + "".join(f"{name:<{col}}" for name in POLICIES)
    print("\n" + header)
    print("  " + "-" * (len(header) - 2))

    for branch in BRANCHES:
        cells = []
        for name, policy in POLICIES.items():
            warden = Warden(store, policy)
            d = warden.authorize(token, Action("push", "acme/api", branch))
            cells.append("push-ok" if d.allowed else "PROTECTED")
        print(f"  {branch:<16}" + "".join(f"{c:<{col}}" for c in cells))

    print("\nSame branch:push token; what's protected is entirely the policy's call.")
    store.close()


if __name__ == "__main__":
    main()
