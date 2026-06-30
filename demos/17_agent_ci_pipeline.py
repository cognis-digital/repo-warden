"""Scenario 17 - end-to-end: an AI agent earns a token and runs a deploy.

The full story in one run: a coding agent requests access via device flow, a
human approves it, the agent receives a scoped token, and then the agent's CI
steps (read -> push feature -> open release branch) are each authorized through
the warden. The deploy step to a protected branch is correctly denied because
the agent was only granted branch:push — least privilege end to end.
"""
from _common import Action, BranchPolicy, DeviceFlow, Warden, fresh_store, rule, show


def main() -> None:
    store = fresh_store()
    rule("AGENT -> CI PIPELINE  -  device-flow grant drives a governed deploy")

    flow = DeviceFlow(store)
    warden = Warden(store, BranchPolicy(protected=["main", "release/*"]))
    t = 5000.0

    print("\n[1] agent requests narrow access (branch:push on acme/*):")
    start = flow.start_authorization("deploy-agent", {"repo:read", "branch:push"},
                                     "acme/*", now=t)
    print(f"    user_code={start['user_code']}  verify_at={start['verification_uri']}")

    print("\n[2] human approves the code out of band:")
    flow.approve(start["user_code"], "release-eng@acme", now=t + 8)
    print("    approved as release-eng@acme")

    print("\n[3] agent polls and receives its token:")
    grant = flow.poll(start["device_code"], now=t + 9)
    token = grant["access_token"]
    print(f"    token={token[:10]}...  scope={grant['scope']}  ns={grant['namespace']}")

    print("\n[4] the agent's pipeline steps, each authorized by the warden:")
    steps = [
        Action("read", "acme/api"),                    # checkout
        Action("push", "acme/api", "feature/agent-fix"),  # push work
        Action("push", "acme/api", "ci/agent-fix"),    # push CI branch
        Action("push", "acme/api", "main"),            # DEPLOY -> denied (least priv)
    ]
    for a in steps:
        show(warden.authorize(token, a), a)

    print("\n[5] the deploy needs more than the agent was given — so a human ships it.")
    print("    Escalation is explicit: nobody hands an agent main by accident.")
    store.close()


if __name__ == "__main__":
    main()
