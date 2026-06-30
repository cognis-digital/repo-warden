"""Scenario 14 - CI/git server, the messy real push.

A single `git push` can carry creates, fast-forwards, a protected-branch update,
and a delete all at once. A pre-receive hook is atomic: if *any* ref update is
denied, the whole push is rejected. This demo feeds a four-ref batch through the
same loop the CLI hook runs and shows the atomic reject, then the same batch
under an admin token sailing through.
"""
from _common import Action, BranchPolicy, Warden, fresh_store, rule

ZERO = "0" * 40


def evaluate(warden, repo, token, lines):
    denied = []
    for line in lines:
        old, new, ref = line.split()
        branch = ref.split("refs/heads/", 1)[-1] if ref.startswith("refs/heads/") else ref
        op = "delete" if new == ZERO else "push"
        d = warden.authorize(token, Action(op=op, repo=repo, branch=branch))
        verdict = "allow" if d.allowed else "DENY "
        print(f"   {verdict} {op:<6} {ref:<26} [{d.rule}]"
              + (f"  {d.reason}" if d.reason else ""))
        if not d.allowed:
            denied.append(d)
    return denied


def main() -> None:
    store = fresh_store()
    rule("HOOK MIXED BATCH  -  one push, many refs, atomic accept/reject")

    warden = Warden(store, BranchPolicy(protected=["main", "release/*"]))
    batch = [
        f"{ZERO} {'a'*40} refs/heads/feature/new",     # create   -> allow
        f"{'b'*40} {'c'*40} refs/heads/develop",       # ff push  -> allow
        f"{'d'*40} {'e'*40} refs/heads/main",          # protected-> DENY
        f"{'f'*40} {ZERO} refs/heads/release/2026.5",  # del prot -> DENY
    ]

    print("\n$ git push origin feature/new develop main :release/2026.5")
    print("\nbranch:push token (CI runner):")
    token, _ = store.issue_token("ci", {"branch:push"}, "acme/*")
    denied = evaluate(warden, "acme/api", token, batch)
    print(f"\n  -> hook exit {1 if denied else 0}: "
          + ("entire push rejected (atomic)" if denied else "accepted"))

    print("\nbranch:admin token (release manager):")
    admin, _ = store.issue_token("rel-mgr", {"branch:admin"}, "acme/*")
    denied2 = evaluate(warden, "acme/api", admin, batch)
    print(f"\n  -> hook exit {1 if denied2 else 0}: "
          + ("rejected" if denied2 else "accepted"))

    print("\nThe hook is all-or-nothing: a bad ref takes the whole push down with it.")
    store.close()


if __name__ == "__main__":
    main()
