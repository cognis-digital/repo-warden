# Demos

Twenty runnable scenarios in [`../demos/`](../demos/), each targeting a different
audience or failure mode. Every scenario builds its own throwaway **in-memory**
warden (or a self-cleaning temp DB), so you can run them in any order or on their
own — and they double as smoke tests under `pytest` (`tests/test_demos.py`).

```bash
PYTHONUTF8=1 python demos/run_all.py               # all twenty, end to end
PYTHONUTF8=1 python demos/02_agent_device_flow.py  # or just one
```

## Core walkthrough (1–5)

| # | Scenario | Audience | Shows |
|---|----------|----------|-------|
| 1 | [`01_branch_protection_gate.py`](../demos/01_branch_protection_gate.py) | Platform engineering | One `BranchPolicy`, evaluated per operation: the same `branch:push` token gets ALLOW on a feature branch and DENY on `main`, on a force-push, on a protected delete, and out of namespace — six outcomes, each tagged with its rule. |
| 2 | [`02_agent_device_flow.py`](../demos/02_agent_device_flow.py) | Teams onboarding AI agents / CI | The full RFC 8628 device flow against the real `DeviceFlow`: `authorization_pending`, `slow_down`, a human approval out of band, the token delivered exactly once, then that token authorizing a real push. |
| 3 | [`03_revocation_and_blast_radius.py`](../demos/03_revocation_and_blast_radius.py) | Security | Issue a contractor token, prove it works across the namespace, `revoke_token`, and watch every operation fail closed immediately. Only a BLAKE2b hash is stored — a DB leak is not a credential leak. |
| 4 | [`04_scope_ladder.py`](../demos/04_scope_ladder.py) | OSS maintainers | The access matrix: read-only / contributor / write / release-mgr / owner against read, push-feature, push-main, force, and delete — so the five scopes map onto a project's contributor tiers. |
| 5 | [`05_pre_receive_hook.py`](../demos/05_pre_receive_hook.py) | CI / git server operators | The drop-in `pre-receive` loop replayed in-process: a batch push of three refs parsed from git's `<old> <new> <ref>` format, denied atomically for a `branch:push` token and accepted for a `branch:admin` token. |

## Device-flow paths & failure modes (6–8)

| # | Scenario | Audience | Shows |
|---|----------|----------|-------|
| 6 | [`06_device_flow_timeout.py`](../demos/06_device_flow_timeout.py) | SRE / on-call | The request nobody approves in time: it expires, and **keeps** reporting `expired_token` on every later poll (not `invalid_grant`), so the agent's poll loop terminates cleanly. Approving after expiry is refused. |
| 7 | [`07_device_flow_denied.py`](../demos/07_device_flow_denied.py) | Approvers | An operator denies an unexpected request; the agent receives `access_denied`, no token is minted, and a denied code can't be salvaged by a late approve. |
| 8 | [`08_slow_down_backoff.py`](../demos/08_slow_down_backoff.py) | Client implementers | An over-eager client polling faster than `interval` is throttled with `slow_down` (RFC 8628 §3.5); a well-behaved client that waits the interval gets its token. |

## Authorization edges (9–12)

| # | Scenario | Audience | Shows |
|---|----------|----------|-------|
| 9 | [`09_namespace_isolation.py`](../demos/09_namespace_isolation.py) | Multi-tenant platform | Namespace is checked **before** scope: a `repo:admin` token for `tenant-a/*` can do anything in its own tenant and nothing in `tenant-b/*`, both directions. |
| 10 | [`10_force_push_policy.py`](../demos/10_force_push_policy.py) | History-rewrite governance | The same force-push under three regimes — default (off), `allow_force=True`, and a `branch:admin` bypass — plus the protected-branch check taking precedence. |
| 11 | [`11_protected_delete_guard.py`](../demos/11_protected_delete_guard.py) | "who deleted main?" prevention | Deleting a protected ref is privileged: writer denied, branch admin allowed, and a break-glass `allow_delete_protected` policy that opens it deliberately. |
| 12 | [`12_scope_escalation_blocked.py`](../demos/12_scope_escalation_blocked.py) | Least-privilege review | Every scope lined up against the operation one rung above it — all DENY. The absence of a scope is a hard wall, not a soft suggestion. |

## Operations & security (13–16)

| # | Scenario | Audience | Shows |
|---|----------|----------|-------|
| 13 | [`13_token_lifecycle.py`](../demos/13_token_lifecycle.py) | Operations / audit | A credential's whole life: issue, authenticate, list, use, revoke, re-list (inactive), and confirm the revoked token authenticates to nothing — the inventory an auditor reasons about. |
| 14 | [`14_hook_mixed_batch.py`](../demos/14_hook_mixed_batch.py) | CI / git server | A realistic four-ref push (create + fast-forward + protected update + delete) through the pre-receive loop: atomic reject for a writer, clean accept for an admin. |
| 15 | [`15_hash_storage_proof.py`](../demos/15_hash_storage_proof.py) | Security review | Dumps the raw `tokens` table to prove the plaintext isn't stored, the stored value is a 64-hex BLAKE2b digest, and the digest is deterministic yet one-way. |
| 16 | [`16_invalid_input_handling.py`](../demos/16_invalid_input_handling.py) | Hardening | Malformed input at every entry point — empty tokens, unknown/empty scopes, blank labels, missing repos, unknown ops, bad device codes — each rejected with a clear error or a fail-closed deny. |

## End-to-end & fleet (17–20)

| # | Scenario | Audience | Shows |
|---|----------|----------|-------|
| 17 | [`17_agent_ci_pipeline.py`](../demos/17_agent_ci_pipeline.py) | End-to-end | A coding agent earns a token via device flow, then runs a CI pipeline (read → push feature → push CI branch) through the warden; the deploy-to-`main` step is correctly denied — least privilege end to end. |
| 18 | [`18_custom_policy.py`](../demos/18_custom_policy.py) | Repo conventions | The same push set against trunk-based, GitFlow, and env-promotion `BranchPolicy` objects — protection is configuration, not a code fork. |
| 19 | [`19_persistence_roundtrip.py`](../demos/19_persistence_roundtrip.py) | Production deployment | Issue + revoke against a real on-disk SQLite store, "restart" the process, reopen, and show the identical active/revoked picture. Cleans up its temp file. |
| 20 | [`20_multi_agent_fleet.py`](../demos/20_multi_agent_fleet.py) | Agent-fleet operators | Provision a fleet of narrowly-scoped agent tokens, run each agent's signature op, revoke one rogue agent, and re-run — the blast radius is a single row; the rest of the fleet keeps working. |

---

Each demo prints clear, narrated output and exits 0. The same code paths are
covered by `pytest` — run `PYTHONUTF8=1 python -m pytest -q` for the full suite
(library tests plus the demo smoke tests).
