"""Run every demo scenario end to end.

    python demos/run_all.py

Each scenario is independent and builds its own throwaway in-memory warden, so
they can be run in any order or on their own. No files are written, no network
is touched — the demos double as smoke tests.
"""
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

SCENARIOS = [
    "01_branch_protection_gate",
    "02_agent_device_flow",
    "03_revocation_and_blast_radius",
    "04_scope_ladder",
    "05_pre_receive_hook",
]


def main() -> None:
    for name in SCENARIOS:
        importlib.import_module(name).main()
    print("\n" + "=" * 70)
    print("  All demo scenarios completed.")
    print("=" * 70)


if __name__ == "__main__":
    main()
