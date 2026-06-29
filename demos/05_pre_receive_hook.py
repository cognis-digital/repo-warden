"""Scenario 5 - CI / git server operators.

Drop-in enforcement: wire repo-warden as a server-side `pre-receive` hook and a
rejected push fails exactly where it should — at the remote, before the refs
land. The real hook reads the standard `<old> <new> <ref>` lines git feeds it,
authorizes each ref update, and exits non-zero if any is denied. This demo
replays that exact loop against a batch push.
"""
from _common import Action, BranchPolicy, Warden, fresh_store, rule

ZERO = "0" * 40  # git's all-zero sha means "create" (old) or "delete" (new)


def evaluate_push(warden: Warden, repo: str, token: str, ref_lines: list[str]):
    """Mirror of repo_warden.cli.cmd_hook's core loop (stdin -> deny list)."""
    denied = []
    for line in ref_lines:
        old, new, ref = line.split()
        branch = ref.split("refs/heads/", 1)[-1] if ref.startswith("refs/heads/") else ref
        op = "delete" if new == ZERO else "push"
        force = op == "push" and old != ZERO  # non-ff is detected by the hook in practice
        decision = warden.authorize(token, Action(op=op, repo=repo, branch=branch))
        verdict = "allow" if decision.allowed else "DENY"
        print(f"   {verdict:<5} {op:<6} {ref:<28} [{decision.rule}]"
              + (f"  {decision.reason}" if decision.reason else ""))
        if not decision.allowed:
            denied.append(decision)
    return denied


def main() -> None:
    store = fresh_store()
    rule("PRE-RECEIVE HOOK  -  reject the bad push at the remote, before refs land")

    warden = Warden(store, BranchPolicy(protected=["main", "release/*"]))
    token, _ = store.issue_token("ci-runner", {"branch:push"}, namespace="acme/*")

    # A real push of three refs, exactly as git pipes them to a pre-receive hook.
    print("\n$ git push origin feature/x main release/2026.6")
    push = [
        f"{'a'*40} {'b'*40} refs/heads/feature/x",       # unprotected -> allow
        f"{'c'*40} {'d'*40} refs/heads/main",            # protected   -> DENY
        f"{'e'*40} {ZERO} refs/heads/release/2026.6",    # delete protected -> DENY
    ]
    print("\nhook authorizing each ref update:")
    denied = evaluate_push(warden, "acme/api", token, push)

    exit_code = 1 if denied else 0
    print(f"\nhook exit code: {exit_code}  ->  ", end="")
    if denied:
        print("! [remote rejected] push declined (the whole push is atomic)")
    else:
        print("push accepted")

    # Now the same push from a release manager: protected refs are authorized.
    admin_token, _ = store.issue_token("release-mgr", {"branch:admin"}, namespace="acme/*")
    print("\nSame push, but presented by a branch:admin token:")
    denied2 = evaluate_push(warden, "acme/api", admin_token, push)
    print(f"\nhook exit code: {1 if denied2 else 0}  ->  "
          + ("rejected" if denied2 else "push accepted"))

    print("\nThe gate lives on the server next to the remote — no client-side trust required.")
    store.close()


if __name__ == "__main__":
    main()
