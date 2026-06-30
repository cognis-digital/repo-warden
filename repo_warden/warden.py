"""Branch-protection authorization.

Given a presented token and an intended git operation, the warden returns an
allow/deny decision tagged with the rule that produced it (so it can be logged
or surfaced in a hook rejection message). The model is intentionally familiar:

  * read              needs repo:read (or repo:write / repo:admin)
  * push              needs branch:push or repo:write
  * push to protected needs branch:admin (or repo:admin)
  * force-push        needs branch:admin and policy.allow_force
  * delete protected  needs branch:admin (or policy.allow_delete_protected)

Namespaces are enforced first: a token scoped to `acme/*` cannot touch
`other-org/secrets` no matter its scopes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import List, Optional

from .store import Store


@dataclass(frozen=True)
class Action:
    op: str                       # read | push | delete
    repo: str                     # owner/repo
    branch: Optional[str] = None
    force: bool = False


@dataclass(frozen=True)
class Decision:
    allowed: bool
    rule: str
    reason: str = ""

    def as_dict(self) -> dict:
        return {"allowed": self.allowed, "rule": self.rule, "reason": self.reason}


@dataclass
class BranchPolicy:
    protected: List[str] = field(default_factory=lambda: ["main", "master", "release/*"])
    allow_force: bool = False
    allow_delete_protected: bool = False

    def is_protected(self, branch: Optional[str]) -> bool:
        if not branch:
            return False
        return any(fnmatch(branch, p) for p in self.protected)


class Warden:
    def __init__(self, store: Store, policy: Optional[BranchPolicy] = None):
        self.store = store
        self.policy = policy or BranchPolicy()

    def authorize(self, token: str, action: Action) -> Decision:
        if not action.repo:
            return Decision(False, "namespace", "no repository specified")
        info = self.store.authenticate(token)
        if info is None:
            return Decision(False, "auth", "invalid or revoked token")
        if not info.covers(action.repo):
            return Decision(False, "namespace",
                            f"token namespace '{info.namespace}' does not cover '{action.repo}'")

        scopes = info.scopes
        admin = "repo:admin" in scopes
        can_admin_branch = admin or "branch:admin" in scopes
        can_push = admin or "repo:write" in scopes or "branch:push" in scopes

        if action.op == "read":
            if admin or scopes & {"repo:read", "repo:write"}:
                return Decision(True, "read", "")
            return Decision(False, "read", "missing repo:read")

        if action.op in ("push", "delete"):
            if not can_push and not can_admin_branch:
                return Decision(False, "push", "missing branch:push or repo:write")
            protected = self.policy.is_protected(action.branch)

            if action.op == "delete":
                if protected and not self.policy.allow_delete_protected and not can_admin_branch:
                    return Decision(False, "delete-protected",
                                    f"deletion of protected branch '{action.branch}' "
                                    "requires branch:admin")
                return Decision(True, "delete", "")

            # push
            if protected and not can_admin_branch:
                return Decision(False, "protected-branch",
                                f"push to protected branch '{action.branch}' requires branch:admin")
            if action.force and not self.policy.allow_force and not can_admin_branch:
                return Decision(False, "force-push", "force-push is disabled by policy")
            return Decision(True, "push", "")

        return Decision(False, "unknown-op", f"unknown operation '{action.op}'")
