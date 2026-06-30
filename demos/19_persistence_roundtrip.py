"""Scenario 19 - it survives a restart.

In production the warden's store is a SQLite file, not memory — tokens and their
revocation state must outlive the process. This demo issues and revokes tokens
against a real on-disk DB, closes the store (simulating a restart), reopens it,
and shows the exact same active/revoked picture. Cleans up its temp file.
"""
import os
import tempfile

from _common import Store, rule


def snapshot(store) -> str:
    return ", ".join(f"{t.label}={'active' if t.active else 'revoked'}"
                     for t in store.list_tokens()) or "(none)"


def main() -> None:
    rule("PERSISTENCE ROUNDTRIP  -  state survives a process restart")

    path = os.path.join(tempfile.mkdtemp(prefix="repo_warden_demo_"), "warden.db")
    print(f"\nstore file: {path}")

    store = Store(path)
    keep, _ = store.issue_token("keep-me", {"repo:read"}, "acme/*")
    kill, kill_info = store.issue_token("revoke-me", {"repo:write"}, "acme/*")
    store.revoke_token(kill_info.id)
    print(f"\nbefore restart: {snapshot(store)}")
    print(f"  authenticate(keep-me)   -> {store.authenticate(keep) is not None}")
    print(f"  authenticate(revoke-me) -> {store.authenticate(kill) is not None}")
    store.close()

    print("\n--- process exits; a new one opens the same file ---\n")

    store2 = Store(path)
    print(f"after restart:  {snapshot(store2)}")
    print(f"  authenticate(keep-me)   -> {store2.authenticate(keep) is not None}")
    print(f"  authenticate(revoke-me) -> {store2.authenticate(kill) is not None}")
    store2.close()

    os.remove(path)
    os.rmdir(os.path.dirname(path))
    print("\nThe hash and the revocation both persisted — restart changes nothing.")


if __name__ == "__main__":
    main()
