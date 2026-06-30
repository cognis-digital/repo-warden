"""End-to-end CLI tests: exercise repo_warden.cli.main with argv, against a
temporary on-disk DB so the full token/device/authorize/hook surface is covered
exactly as an operator would invoke it.
"""
import io
import json

import pytest

from repo_warden import cli


def run(argv, db, stdin=None, monkeypatch=None):
    """Invoke the CLI, returning (exit_code, parsed_stdout_or_text)."""
    full = list(argv)
    # inject --db right after the leaf subcommand is handled by each parser's
    # _add_db; every subcommand accepts --db, so append it.
    full += ["--db", db]
    import sys
    out = io.StringIO()
    old_out, old_in = sys.stdout, sys.stdin
    sys.stdout = out
    if stdin is not None:
        sys.stdin = io.StringIO(stdin)
    try:
        code = cli.main(full)
    finally:
        sys.stdout, sys.stdin = old_out, old_in
    text = out.getvalue()
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        parsed = text
    return code, parsed


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "warden.db")


# ---------------------------------------------------------------- token

def test_token_issue_and_list(db):
    code, out = run(["token", "issue", "--label", "bot",
                     "--scopes", "repo:read repo:write", "--namespace", "acme/*"], db)
    assert code == 0
    assert out["token"].startswith("rw_")
    assert out["namespace"] == "acme/*"

    code, listed = run(["token", "list"], db)
    assert code == 0
    assert len(listed["tokens"]) == 1
    assert listed["tokens"][0]["label"] == "bot"


def test_token_revoke(db):
    _, issued = run(["token", "issue", "--label", "bot", "--scopes", "repo:read"], db)
    code, listed = run(["token", "list"], db)
    tid = listed["tokens"][0]["id"]
    code, out = run(["token", "revoke", "--id", str(tid)], db)
    assert code == 0 and out["revoked"] is True

    code, listed2 = run(["token", "list"], db)
    assert listed2["tokens"][0]["active"] is False


def test_token_issue_bad_scope_raises(db):
    with pytest.raises(ValueError):
        run(["token", "issue", "--label", "bot", "--scopes", "repo:nope"], db)


def test_token_issue_with_expiry(db):
    code, out = run(["token", "issue", "--label", "ci", "--scopes", "branch:push",
                     "--namespace", "acme/*", "--expires-in", "600"], db)
    assert code == 0
    assert "expires_at" in out
    assert out["active"] is True


# ---------------------------------------------------------------- authorize

def test_authorize_allow_returns_zero(db):
    _, issued = run(["token", "issue", "--label", "ci", "--scopes", "branch:push",
                     "--namespace", "acme/*"], db)
    token = issued["token"]
    code, out = run(["authorize", "--token", token, "--op", "push",
                     "--repo", "acme/api", "--branch", "feature/x"], db)
    assert code == 0
    assert out["decision"]["allowed"] is True


def test_authorize_deny_protected_returns_two(db):
    _, issued = run(["token", "issue", "--label", "ci", "--scopes", "branch:push",
                     "--namespace", "acme/*"], db)
    token = issued["token"]
    code, out = run(["authorize", "--token", token, "--op", "push",
                     "--repo", "acme/api", "--branch", "main"], db)
    assert code == 2
    assert out["decision"]["allowed"] is False
    assert out["decision"]["rule"] == "protected-branch"


def test_authorize_custom_protected_globs(db):
    _, issued = run(["token", "issue", "--label", "ci", "--scopes", "branch:push",
                     "--namespace", "acme/*"], db)
    token = issued["token"]
    # 'main' is no longer protected under this custom policy
    code, out = run(["authorize", "--token", token, "--op", "push",
                     "--repo", "acme/api", "--branch", "main",
                     "--protected", "prod/*"], db)
    assert code == 0 and out["decision"]["allowed"] is True


def test_authorize_allow_force_flag(db):
    _, issued = run(["token", "issue", "--label", "w", "--scopes", "repo:write",
                     "--namespace", "acme/*"], db)
    token = issued["token"]
    code, out = run(["authorize", "--token", token, "--op", "push",
                     "--repo", "acme/api", "--branch", "feature/x",
                     "--force", "--allow-force"], db)
    assert code == 0 and out["decision"]["allowed"] is True


def test_authorize_invalid_token_returns_two(db):
    code, out = run(["authorize", "--token", "rw_nope", "--op", "read",
                     "--repo", "acme/api"], db)
    assert code == 2 and out["decision"]["rule"] == "auth"


# ---------------------------------------------------------------- device flow (CLI)

def test_device_full_flow_cli(db):
    code, start = run(["device", "start", "--client", "ci",
                       "--scopes", "branch:push", "--namespace", "acme/*"], db)
    assert code == 0
    user_code = start["user_code"]
    device_code = start["device_code"]

    # poll before approval: not an access_token -> exit 1
    code, _ = run(["device", "poll", "--device-code", device_code], db)
    assert code == 1

    code, approved = run(["device", "approve", "--user-code", user_code,
                          "--subject", "alice"], db)
    assert code == 0 and approved["approved"] is True

    code, granted = run(["device", "poll", "--device-code", device_code], db)
    assert code == 0
    assert granted["access_token"].startswith("rw_")


def test_device_approve_unknown_returns_one(db):
    code, out = run(["device", "approve", "--user-code", "ZZZZ-ZZZZ",
                     "--subject", "x"], db)
    assert code == 1 and out["approved"] is False


def test_device_deny_cli(db):
    code, start = run(["device", "start", "--client", "ci", "--scopes", "repo:read"], db)
    code, out = run(["device", "deny", "--user-code", start["user_code"]], db)
    assert code == 0 and out["denied"] is True


# ---------------------------------------------------------------- hook (pre-receive)

ZERO = "0" * 40


def test_hook_allows_clean_push(db):
    _, issued = run(["token", "issue", "--label", "ci", "--scopes", "branch:push",
                     "--namespace", "acme/*"], db)
    token = issued["token"]
    stdin = f"{'a'*40} {'b'*40} refs/heads/feature/x\n"
    code, _ = run(["hook", "--repo", "acme/api", "--token", token], db, stdin=stdin)
    assert code == 0


def test_hook_rejects_protected_push(db):
    _, issued = run(["token", "issue", "--label", "ci", "--scopes", "branch:push",
                     "--namespace", "acme/*"], db)
    token = issued["token"]
    stdin = (f"{'a'*40} {'b'*40} refs/heads/feature/x\n"
             f"{'c'*40} {'d'*40} refs/heads/main\n")
    code, _ = run(["hook", "--repo", "acme/api", "--token", token], db, stdin=stdin)
    assert code == 1  # the whole push is rejected atomically


def test_hook_detects_delete(db):
    _, issued = run(["token", "issue", "--label", "ci", "--scopes", "branch:push",
                     "--namespace", "acme/*"], db)
    token = issued["token"]
    # delete of a protected branch (new sha all zeros) -> reject
    stdin = f"{'e'*40} {ZERO} refs/heads/main\n"
    code, _ = run(["hook", "--repo", "acme/api", "--token", token], db, stdin=stdin)
    assert code == 1


def test_hook_token_from_env(db, monkeypatch):
    _, issued = run(["token", "issue", "--label", "ci", "--scopes", "branch:push",
                     "--namespace", "acme/*"], db)
    monkeypatch.setenv("REPO_WARDEN_TOKEN", issued["token"])
    stdin = f"{'a'*40} {'b'*40} refs/heads/feature/x\n"
    code, _ = run(["hook", "--repo", "acme/api"], db, stdin=stdin)
    assert code == 0


def test_hook_ignores_malformed_lines(db):
    _, issued = run(["token", "issue", "--label", "ci", "--scopes", "branch:push",
                     "--namespace", "acme/*"], db)
    token = issued["token"]
    stdin = "garbage line\n\n" + f"{'a'*40} {'b'*40} refs/heads/feature/x\n"
    code, _ = run(["hook", "--repo", "acme/api", "--token", token], db, stdin=stdin)
    assert code == 0


# ---------------------------------------------------------------- parser

def test_version_flag():
    with pytest.raises(SystemExit) as e:
        cli.main(["--version"])
    assert e.value.code == 0


def test_missing_subcommand_errors():
    with pytest.raises(SystemExit):
        cli.main([])
