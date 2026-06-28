"""repo-warden — access governance for git repositories you already host.

repo-warden doesn't replace your git host. It layers authorization on top of
the remotes you already run (GitHub, GitLab, an internal mirror) so that human
and agent access flow through one governed path:

  * Agents (and humans) obtain access with the OAuth 2.0 Device Authorization
    Grant (RFC 8628) — the headless, copy-a-code flow that fits CI and CLI
    tools that can't pop a browser. No proprietary token dance.
  * Access is a scoped, revocable token bound to a repo namespace. Revocation
    is immediate; only a hash of the token is stored.
  * A branch-protection policy decides whether a given push/read/delete is
    allowed — protected branches, force-push and deletion controls — and the
    same decision can be enforced as a server-side git pre-receive hook on a
    host you already operate.
"""

from .store import Store, TokenInfo, VALID_SCOPES
from .deviceflow import DeviceFlow
from .warden import Action, BranchPolicy, Decision, Warden

__version__ = "0.1.0"
__all__ = [
    "Store", "TokenInfo", "VALID_SCOPES",
    "DeviceFlow", "Warden", "BranchPolicy", "Action", "Decision",
    "__version__",
]
