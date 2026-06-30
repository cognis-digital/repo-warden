"""Scenario 20 - governing a fleet of agents at once.

When you run many agents, governance is a portfolio problem: each agent gets the
narrowest token for its job, you can see the whole fleet at a glance, and when
one agent is compromised you revoke exactly that one — the blast radius is a
single row, and every other agent keeps working. This demo provisions a small
fleet, runs each agent's signature operation, revokes the rogue, and reruns.
"""
from _common import Action, BranchPolicy, Warden, fresh_store, rule, show


FLEET = [
    # label,            scopes,            namespace,    signature op
    ("docs-bot",        {"repo:read"},     "acme/*",     Action("read", "acme/api")),
    ("test-runner",     {"branch:push"},   "acme/*",     Action("push", "acme/api", "ci/run-42")),
    ("dependabot",      {"branch:push"},   "acme/*",     Action("push", "acme/web", "deps/bump")),
    ("release-agent",   {"branch:admin"},  "acme/*",     Action("push", "acme/api", "main")),
    ("rogue-scraper",   {"repo:read"},     "acme/*",     Action("read", "acme/secrets")),
]


def main() -> None:
    store = fresh_store()
    rule("MULTI-AGENT FLEET  -  least privilege per agent, surgical revocation")

    warden = Warden(store, BranchPolicy(protected=["main", "release/*"]))
    tokens = {}
    print("\nprovisioning the fleet (one scoped token each):")
    for label, scopes, ns, _ in FLEET:
        tok, info = store.issue_token(label, scopes, ns)
        tokens[label] = (tok, info)
        print(f"    {label:<14} id={info.id} {sorted(scopes)} ns={ns}")

    print("\neach agent runs its signature operation:")
    for label, _, _, action in FLEET:
        tok, _ = tokens[label]
        show(warden.authorize(tok, action), action)

    rogue = "rogue-scraper"
    _, rinfo = tokens[rogue]
    print(f"\n>>> incident: {rogue} flagged exfiltrating — revoke id={rinfo.id}")
    store.revoke_token(rinfo.id)

    print("\nre-run after revocation (only the rogue is affected):")
    for label, _, _, action in FLEET:
        tok, _ = tokens[label]
        d = warden.authorize(tok, action)
        marker = "  <- killed" if (label == rogue and not d.allowed) else ""
        show(d, action)
        if marker:
            print(marker)

    active = [t.label for t in store.list_tokens() if t.active]
    print(f"\nfleet still operational: {active}")
    print("Revocation is per-agent: the fleet keeps humming, the rogue goes dark.")
    store.close()


if __name__ == "__main__":
    main()
