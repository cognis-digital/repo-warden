"""Scenario 21 - short-lived credentials.

The safest token is one that dies on its own. `issue_token(expires_in=N)` mints
a credential that authenticates for N seconds and then fails closed — no
revocation call, no cleanup cron. This demo issues a 10-minute CI token against a
deterministic clock, shows it live inside the window and dead past it, and leaves
a second never-expiring token untouched.
"""
from _common import fresh_store, rule


def main() -> None:
    store = fresh_store()
    rule("TOKEN EXPIRY  -  a credential that retires itself")

    t0 = 1000.0
    short, info = store.issue_token("ci-job-42", {"branch:push"}, "acme/*",
                                    expires_in=600, now=t0)
    perm, _ = store.issue_token("dashboard", {"repo:read"}, "acme/*", now=t0)
    print(f"\nissued '{info.label}' expiring at t={info.expires_at:.0f} (600s window) "
          "and a never-expiring 'dashboard'\n")

    def state(token, now):
        return "live" if store.authenticate(token, now=now) is not None else "EXPIRED"

    print("ci-job-42 token, checked at points along the clock:")
    for dt in (0, 300, 599, 600, 601, 3600):
        print(f"    t=+{dt:>4.0f}s  authenticate -> {state(short, t0 + dt)}")

    print("\nthe never-expiring dashboard token is unaffected by the same clock:")
    for dt in (300, 601, 3600):
        print(f"    t=+{dt:>4.0f}s  authenticate -> {state(perm, t0 + dt)}")

    print("\nis_active(now) folds revocation and expiry into one check:")
    for label, tok in (("ci-job-42", short), ("dashboard", perm)):
        i = next(x for x in store.list_tokens() if x.label == label)
        print(f"    {label:<11} is_active(+300s)={i.is_active(t0 + 300)}  "
              f"is_active(+601s)={i.is_active(t0 + 601)}")

    print("\nShort-lived by default is least privilege over time, not just over scope.")
    store.close()


if __name__ == "__main__":
    main()
