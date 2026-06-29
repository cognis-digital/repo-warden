"""The demo scenarios double as smoke tests: each must run end to end and exit 0.

This imports every scenario's main() and runs it, asserting it returns without
raising. It keeps the narrated demos honest against the real API over time.
"""
import importlib
import os
import sys

import pytest

DEMOS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "demos")
sys.path.insert(0, DEMOS_DIR)

SCENARIOS = [
    "01_branch_protection_gate",
    "02_agent_device_flow",
    "03_revocation_and_blast_radius",
    "04_scope_ladder",
    "05_pre_receive_hook",
]


@pytest.mark.parametrize("name", SCENARIOS)
def test_demo_runs(name, capsys):
    mod = importlib.import_module(name)
    mod.main()  # must not raise
    out = capsys.readouterr().out
    assert out.strip(), f"{name} produced no output"


def test_pre_receive_hook_logic_matches_cli():
    """The demo's hook loop must agree with the real cli.cmd_hook semantics."""
    import importlib as _il
    hook = _il.import_module("05_pre_receive_hook")
    from repo_warden import BranchPolicy, Store, Warden

    store = Store(":memory:")
    token, _ = store.issue_token("ci", {"branch:push"}, namespace="acme/*")
    warden = Warden(store, BranchPolicy(protected=["main"]))
    push = [
        f"{'a'*40} {'b'*40} refs/heads/feature/x",   # allow
        f"{'c'*40} {'d'*40} refs/heads/main",        # deny: protected
    ]
    denied = hook.evaluate_push(warden, "acme/api", token, push)
    assert len(denied) == 1 and denied[0].rule == "protected-branch"
    store.close()
