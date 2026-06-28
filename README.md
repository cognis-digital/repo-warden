# repo-warden

[![CI](https://github.com/cognis-digital/repo-warden/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/repo-warden/actions/workflows/ci.yml)

> Part of the **[Accountable AI Engineering suite](https://github.com/cognis-digital/accountable-ai-suite)** — provable governance for AI agents on infrastructure you own.

**Access governance for the git repositories you already host. RFC 8628 device-flow auth, scoped revocable tokens, and branch protection you can drop in as a `pre-receive` hook — no forge migration.**

You don't need to move off GitHub or GitLab to govern how agents and humans touch your code. `repo-warden` is a thin authorization layer that sits over the remotes you already run, so human pushes and agent access flow through one controlled, revocable path.

- **Device-flow onboarding (RFC 8628).** Agents and CI obtain access with the OAuth 2.0 Device Authorization Grant — the headless "here's a code, go approve it" flow — not a proprietary token handshake or an embedded secret.
- **Scoped, revocable tokens bound to a namespace.** A token carries scopes (`repo:read`, `branch:push`, `branch:admin`, …) and a repo namespace glob (`acme/*`). Only a hash is stored; revocation is immediate.
- **Branch protection as policy.** Protected branches, force-push, and deletion are governed by an explicit policy and evaluated per operation.
- **Drop-in enforcement.** Wire it as a server-side `pre-receive` hook on any git host and rejected pushes fail exactly where they should.
- **Zero dependencies.** Pure standard library + SQLite.

## Install

```bash
pip install -e .
```

## Device flow (how an agent gets a token)

```bash
# 1. The agent/CI starts authorization
repo-warden device start --client ci-runner --scopes "branch:push" --namespace "acme/*" --db warden.db
# -> { "user_code": "BCDF-2345", "verification_uri": "...", "interval": 5, ... }

# 2. A human approves that code out of band
repo-warden device approve --user-code BCDF-2345 --subject alice --db warden.db

# 3. The agent polls and receives a scoped bearer token (delivered once)
repo-warden device poll --device-code <code> --db warden.db
# -> { "access_token": "rw_…", "token_type": "Bearer", "scope": "branch:push", "namespace": "acme/*" }
```

Polling respects the RFC 8628 `interval` (returns `slow_down` if you poll too fast), `authorization_pending` until approved, and `expired_token` after the lifetime.

## Authorize an operation

```bash
repo-warden authorize --token rw_… --op push --repo acme/api --branch feature/x   # allowed
repo-warden authorize --token rw_… --op push --repo acme/api --branch main        # denied: protected
```

```python
from repo_warden import Store, Warden, Action, BranchPolicy

store = Store("warden.db")
warden = Warden(store, BranchPolicy(protected=["main", "release/*"], allow_force=False))
warden.authorize(token, Action(op="push", repo="acme/api", branch="main")).allowed   # False
```

## Enforce it on a host you already run

Install as a `pre-receive` hook on your git server. It reads the standard
`<old> <new> <ref>` lines, authorizes each ref update, and rejects the push if
any is denied:

```sh
#!/bin/sh
# .git/hooks/pre-receive on the server
exec repo-warden hook --repo acme/api --db /var/lib/warden/warden.db
```

```
$ git push origin main
remote: repo-warden: DENY push refs/heads/main — push to protected branch 'main' requires branch:admin [protected-branch]
! [remote rejected] main -> main (pre-receive hook declined)
```

The agent's token is read from `$REPO_WARDEN_TOKEN`. A force-push or a branch deletion is governed by the same policy.

## Scopes & rules

| Scope | Grants |
|-------|--------|
| `repo:read` | read/clone within the namespace |
| `repo:write` | read + push to unprotected branches |
| `branch:push` | push to unprotected branches |
| `branch:admin` | push/force-push/delete protected branches |
| `repo:admin` | everything within the namespace |

Decision rules (each tagged for logging): `auth`, `namespace`, `read`, `push`, `protected-branch`, `force-push`, `delete-protected`.

## Composes with the suite

Pair with [`agentledger`](https://github.com/cognis-digital/agentledger) to get a signed, tamper-evident record of every authorized (and denied) git operation, and with [`sentinel-policy`](https://github.com/cognis-digital/sentinel-policy) for an org-wide governance doctrine above the branch policy.

## Testing

```bash
pip install -e ".[dev]"
pytest -q          # 19 tests
```

## License

Apache-2.0. © Cognis Digital.

> Status: v0.1 — runnable and tested. Roadmap: ancestry-aware force-push detection in the hook, token TTL + auto-expiry, CODEOWNERS-style path rules, and a smart-HTTP proxy mode for hosts without server-side hooks.
