"""repo-warden command line.

    repo-warden device start  --client ci --scopes "branch:push" --namespace "acme/*"
    repo-warden device approve --user-code BCDF-2345 --subject alice
    repo-warden device poll   --device-code <code>
    repo-warden token issue   --label bot --scopes "repo:read" --namespace "acme/*"
    repo-warden token list | revoke --id N
    repo-warden authorize --token rw_... --op push --repo acme/api --branch main [--force]
    repo-warden hook --repo acme/api          # git pre-receive bridge (reads stdin)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

from . import __version__
from .deviceflow import DeviceFlow
from .store import Store
from .warden import Action, BranchPolicy, Warden

DEFAULT_DB = "warden.db"
ZERO = "0" * 40


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _store(args) -> Store:
    return Store(getattr(args, "db", DEFAULT_DB))


def _policy(args) -> BranchPolicy:
    p = BranchPolicy()
    if getattr(args, "protected", None):
        p.protected = args.protected.split(",")
    if getattr(args, "allow_force", False):
        p.allow_force = True
    return p


def cmd_device(args) -> int:
    store = _store(args)
    try:
        flow = DeviceFlow(store)
        if args.dsub == "start":
            res = flow.start_authorization(args.client, set(args.scopes.split()), args.namespace)
            _print(res)
        elif args.dsub == "approve":
            ok = flow.approve(args.user_code, args.subject)
            _print({"approved": ok, "user_code": args.user_code})
            return 0 if ok else 1
        elif args.dsub == "deny":
            _print({"denied": flow.deny(args.user_code)})
        elif args.dsub == "poll":
            res = flow.poll(args.device_code)
            _print(res)
            return 0 if "access_token" in res else 1
        return 0
    finally:
        store.close()


def cmd_token(args) -> int:
    store = _store(args)
    try:
        if args.tsub == "issue":
            token, info = store.issue_token(args.label, set(args.scopes.split()), args.namespace)
            _print({"token": token, **info.as_dict(),
                    "note": "store this token now; only its hash is kept"})
        elif args.tsub == "list":
            _print({"tokens": [t.as_dict() for t in store.list_tokens()]})
        elif args.tsub == "revoke":
            _print({"revoked": store.revoke_token(args.id), "id": args.id})
        return 0
    finally:
        store.close()


def cmd_authorize(args) -> int:
    store = _store(args)
    try:
        warden = Warden(store, _policy(args))
        action = Action(op=args.op, repo=args.repo, branch=args.branch, force=args.force)
        decision = warden.authorize(args.token, action)
        _print({"action": vars(action), "decision": decision.as_dict()})
        return 0 if decision.allowed else 2
    finally:
        store.close()


def cmd_hook(args) -> int:
    """git pre-receive bridge: authorize each pushed ref, reject on any deny.

    Reads stdin lines of '<old-sha> <new-sha> <ref>' (the pre-receive format).
    The agent's token comes from $REPO_WARDEN_TOKEN. Exit non-zero rejects the
    whole push, exactly as a server-side hook should.
    """
    store = _store(args)
    try:
        token = os.environ.get("REPO_WARDEN_TOKEN", args.token or "")
        warden = Warden(store, _policy(args))
        denied = []
        seen = 0
        for line in sys.stdin:
            parts = line.split()
            if len(parts) != 3:
                continue
            seen += 1
            old, new, ref = parts
            branch = ref.split("refs/heads/", 1)[-1] if ref.startswith("refs/heads/") else ref
            op = "delete" if new == ZERO else "push"
            decision = warden.authorize(token, Action(op=op, repo=args.repo, branch=branch))
            if not decision.allowed:
                denied.append({"ref": ref, "op": op, "reason": decision.reason,
                               "rule": decision.rule})
        if denied:
            for d in denied:
                print(f"repo-warden: DENY {d['op']} {d['ref']} — {d['reason']} [{d['rule']}]",
                      file=sys.stderr)
            return 1
        print(f"repo-warden: allowed {seen} ref update(s)", file=sys.stderr)
        return 0
    finally:
        store.close()


def _add_db(p):
    p.add_argument("--db", default=DEFAULT_DB)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="repo-warden", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"repo-warden {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    pd = sub.add_parser("device", help="OAuth 2.0 device authorization grant")
    dsub = pd.add_subparsers(dest="dsub", required=True)
    d1 = dsub.add_parser("start"); _add_db(d1); d1.add_argument("--client", required=True)
    d1.add_argument("--scopes", default="repo:read"); d1.add_argument("--namespace", default="*")
    d2 = dsub.add_parser("approve"); _add_db(d2); d2.add_argument("--user-code", dest="user_code", required=True); d2.add_argument("--subject", required=True)
    d3 = dsub.add_parser("deny"); _add_db(d3); d3.add_argument("--user-code", dest="user_code", required=True)
    d4 = dsub.add_parser("poll"); _add_db(d4); d4.add_argument("--device-code", dest="device_code", required=True)
    pd.set_defaults(func=cmd_device)

    pt = sub.add_parser("token", help="manage scoped tokens")
    tsub = pt.add_subparsers(dest="tsub", required=True)
    t1 = tsub.add_parser("issue"); _add_db(t1); t1.add_argument("--label", required=True)
    t1.add_argument("--scopes", default="repo:read"); t1.add_argument("--namespace", default="*")
    t2 = tsub.add_parser("list"); _add_db(t2)
    t3 = tsub.add_parser("revoke"); _add_db(t3); t3.add_argument("--id", type=int, required=True)
    pt.set_defaults(func=cmd_token)

    pa = sub.add_parser("authorize", help="authorize a single git operation")
    _add_db(pa)
    pa.add_argument("--token", required=True)
    pa.add_argument("--op", choices=["read", "push", "delete"], required=True)
    pa.add_argument("--repo", required=True)
    pa.add_argument("--branch", default=None)
    pa.add_argument("--force", action="store_true")
    pa.add_argument("--protected", default=None, help="comma-separated protected branch globs")
    pa.add_argument("--allow-force", dest="allow_force", action="store_true")
    pa.set_defaults(func=cmd_authorize)

    ph = sub.add_parser("hook", help="git pre-receive bridge (reads stdin)")
    _add_db(ph)
    ph.add_argument("--repo", required=True)
    ph.add_argument("--token", default=None, help="defaults to $REPO_WARDEN_TOKEN")
    ph.add_argument("--protected", default=None)
    ph.add_argument("--allow-force", dest="allow_force", action="store_true")
    ph.set_defaults(func=cmd_hook)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
