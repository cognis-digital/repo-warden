"""Scenario 4 - open-source maintainers.

A maintainer hands out access in tiers: a drive-by contributor reads, a trusted
contributor pushes to feature branches, a release manager owns protected
branches. repo-warden's five scopes map onto exactly that ladder. This demo runs
the same battery of operations against each rung and prints the access matrix.
"""
from _common import Action, BranchPolicy, Warden, fresh_store, rule


RUNGS = [
    ("read-only",    {"repo:read"}),
    ("contributor",  {"branch:push"}),
    ("write",        {"repo:write"}),
    ("release-mgr",  {"branch:admin"}),
    ("owner",        {"repo:admin"}),
]

OPS = [
    ("read",            Action("read",   "oss/project")),
    ("push feature",    Action("push",   "oss/project", "feature/docs")),
    ("push main",       Action("push",   "oss/project", "main")),
    ("force main",      Action("push",   "oss/project", "main", force=True)),
    ("delete main",     Action("delete", "oss/project", "main")),
]


def main() -> None:
    store = fresh_store()
    rule("SCOPE LADDER  -  the access matrix for an OSS project's contributor tiers")

    warden = Warden(store, BranchPolicy(protected=["main"], allow_force=False))

    col = 13
    header = "  scope \\ op    " + "".join(f"{label:<{col}}" for label, _ in OPS)
    print("\n" + header)
    print("  " + "-" * (len(header) - 2))

    for name, scopes in RUNGS:
        token, _ = store.issue_token(name, scopes, namespace="oss/*")
        cells = []
        for _, action in OPS:
            d = warden.authorize(token, action)
            cells.append("yes" if d.allowed else "no")
        row = f"  {name:<13}" + "".join(f"{c:<{col}}" for c in cells)
        print(row)

    print("\nEach rung is a single scope set on a namespace-bound token —")
    print("promote a contributor by issuing a higher-scope token, demote by revoking.")
    store.close()


if __name__ == "__main__":
    main()
