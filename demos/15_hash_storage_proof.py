"""Scenario 15 - security review: 'what does a DB leak expose?'

repo-warden stores only a BLAKE2b-256 hash of each token, never the token. This
demo issues a token, then dumps the raw `tokens` table to prove the plaintext
isn't there, that the stored value is a 64-hex-char digest, and that the digest
is deterministic (so auth works) yet one-way (so a leak isn't a credential).
"""
from _common import fresh_store, rule
from repo_warden.store import _hash


def main() -> None:
    store = fresh_store()
    rule("HASH STORAGE PROOF  -  a database leak is not a credential leak")

    token, info = store.issue_token("prod-deployer", {"repo:write"}, "acme/*")
    print(f"\nissued token (shown once to the holder): {token}")

    row = store.conn.execute(
        "SELECT label, token_hash, scopes, namespace FROM tokens WHERE id=?",
        (info.id,)).fetchone()
    label, stored_hash, scopes, ns = row

    print("\nwhat the database actually holds for this row:")
    print(f"    label      = {label}")
    print(f"    token_hash = {stored_hash}")
    print(f"    scopes     = {scopes}")
    print(f"    namespace  = {ns}")

    print("\nverifications:")
    print(f"    plaintext token present in row?   {token in str(row)}")
    print(f"    stored value length (hex chars):  {len(stored_hash)}")
    print(f"    hash is deterministic:            {stored_hash == _hash(token)}")
    print(f"    a different token -> different hash: "
          f"{_hash(token) != _hash(token + 'x')}")

    print("\nAuth recomputes the hash and matches the row; the secret never rests at rest.")
    store.close()


if __name__ == "__main__":
    main()
