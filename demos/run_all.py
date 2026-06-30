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
    "06_device_flow_timeout",
    "07_device_flow_denied",
    "08_slow_down_backoff",
    "09_namespace_isolation",
    "10_force_push_policy",
    "11_protected_delete_guard",
    "12_scope_escalation_blocked",
    "13_token_lifecycle",
    "14_hook_mixed_batch",
    "15_hash_storage_proof",
    "16_invalid_input_handling",
    "17_agent_ci_pipeline",
    "18_custom_policy",
    "19_persistence_roundtrip",
    "20_multi_agent_fleet",
]


def main() -> None:
    for name in SCENARIOS:
        importlib.import_module(name).main()
    print("\n" + "=" * 70)
    print("  All demo scenarios completed.")
    print("=" * 70)


if __name__ == "__main__":
    main()
