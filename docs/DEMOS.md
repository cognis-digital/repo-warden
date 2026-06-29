# Demos

Five runnable scenarios in [`../demos/`](../demos/), each targeting a different
audience. Every scenario builds its own throwaway **in-memory** warden (no files,
no network), so you can run them in any order or on their own — and they double
as smoke tests under `pytest` (`tests/test_demos.py`).

```bash
PYTHONUTF8=1 python demos/run_all.py             # all five, end to end
PYTHONUTF8=1 python demos/02_agent_device_flow.py  # or just one
```

| # | Scenario | Audience | Shows |
|---|----------|----------|-------|
| 1 | [`01_branch_protection_gate.py`](../demos/01_branch_protection_gate.py) | Platform engineering | One `BranchPolicy`, evaluated per operation: the same `branch:push` token gets ALLOW on a feature branch and DENY on `main`, on a force-push, on a protected delete, and out of namespace — six outcomes, each tagged with its rule. |
| 2 | [`02_agent_device_flow.py`](../demos/02_agent_device_flow.py) | Teams onboarding AI agents / CI | The full RFC 8628 device flow against the real `DeviceFlow`: `authorization_pending`, `slow_down`, a human approval out of band, the token delivered exactly once, then that token authorizing a real push. |
| 3 | [`03_revocation_and_blast_radius.py`](../demos/03_revocation_and_blast_radius.py) | Security | Issue a contractor token, prove it works across the namespace, `revoke_token`, and watch every operation fail closed immediately. Only a BLAKE2b hash is stored — a DB leak is not a credential leak. |
| 4 | [`04_scope_ladder.py`](../demos/04_scope_ladder.py) | OSS maintainers | The access matrix: read-only / contributor / write / release-mgr / owner against read, push-feature, push-main, force, and delete — so the five scopes map onto a project's contributor tiers. |
| 5 | [`05_pre_receive_hook.py`](../demos/05_pre_receive_hook.py) | CI / git server operators | The drop-in `pre-receive` loop replayed in-process: a batch push of three refs parsed from git's `<old> <new> <ref>` format, denied atomically for a `branch:push` token and accepted for a `branch:admin` token. |

---

Each demo prints clear, narrated output and exits 0. The same code paths are
covered by `pytest` — run `PYTHONUTF8=1 python -m pytest -q` for the full suite
(library tests plus the demo smoke tests).
