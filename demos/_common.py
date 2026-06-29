"""Shared helpers for the demo scenarios.

Every scenario builds its own throwaway in-memory warden (no files, no network)
so the demos can run in any order or on their own, and double as smoke tests.
"""
from __future__ import annotations

import os
import sys

# allow `python demos/NN_xxx.py` from anywhere
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from repo_warden import Action, BranchPolicy, DeviceFlow, Store, Warden  # noqa: E402


def fresh_store() -> Store:
    """A brand-new in-memory token/device store (nothing touches disk)."""
    return Store(":memory:")


def rule(title: str) -> None:
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def show(decision, action: Action) -> None:
    """Print one authorization decision the way a hook rejection would read."""
    verdict = "ALLOW" if decision.allowed else "DENY "
    where = action.branch or "-"
    force = " (force)" if action.force else ""
    line = f"  {verdict} {action.op:<6} {action.repo:<14} {where:<16}{force}  [{decision.rule}]"
    if decision.reason:
        line += f"  {decision.reason}"
    print(line)


__all__ = ["Action", "BranchPolicy", "DeviceFlow", "Store", "Warden",
           "fresh_store", "rule", "show"]
