"""OAuth 2.0 Device Authorization Grant (RFC 8628).

The device-flow is the right shape for agents and CI: a headless client asks
for authorization, shows a short `user_code`, and polls while a human approves
that code out of band. No browser on the device, no embedded secret.

This implements the coordinator side:

  start_authorization()  -> device_code, user_code, verification_uri, interval
  poll(device_code)      -> {authorization_pending | slow_down | expired |
                             access_denied | complete + access_token}
  approve(user_code)     -> binds the request to a subject and mints the token
  deny(user_code)

Standard error codes from RFC 8628 §3.5 are used verbatim so existing OAuth
device-flow clients work unchanged.
"""

from __future__ import annotations

import secrets
import time
from typing import Optional

from .store import Store, VALID_SCOPES

_USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ23456789"  # no vowels/ambiguous chars
DEFAULT_LIFETIME = 600   # seconds
DEFAULT_INTERVAL = 5     # seconds between polls


def _user_code() -> str:
    raw = "".join(secrets.choice(_USER_CODE_ALPHABET) for _ in range(8))
    return f"{raw[:4]}-{raw[4:]}"


class DeviceFlow:
    def __init__(self, store: Store, verification_uri: str = "https://warden.local/device",
                 lifetime: int = DEFAULT_LIFETIME, interval: int = DEFAULT_INTERVAL):
        self.store = store
        self.verification_uri = verification_uri
        self.lifetime = lifetime
        self.interval = interval

    def start_authorization(self, client_id: str, scopes: set[str], namespace: str = "*",
                            *, now: Optional[float] = None) -> dict:
        if not client_id:
            raise ValueError("client_id is required")
        if not scopes:
            raise ValueError("at least one scope is required")
        # Validate scopes up front so an invalid grant is rejected before a
        # device_code/user_code is ever minted (no orphan pending rows).
        bad = set(scopes) - VALID_SCOPES
        if bad:
            raise ValueError(f"unknown scopes: {sorted(bad)}")
        now = time.time() if now is None else now
        device_code = secrets.token_urlsafe(32)
        user_code = _user_code()
        self.store.conn.execute(
            "INSERT INTO device_requests(device_code, user_code, client_id, scopes, namespace, "
            "status, created_at, expires_at, interval) VALUES(?,?,?,?,?,?,?,?,?)",
            (device_code, user_code, client_id, ",".join(sorted(scopes)), namespace,
             "pending", now, now + self.lifetime, self.interval),
        )
        self.store.conn.commit()
        return {
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": self.verification_uri,
            "verification_uri_complete": f"{self.verification_uri}?user_code={user_code}",
            "expires_in": self.lifetime,
            "interval": self.interval,
        }

    def _row(self, device_code: str):
        return self.store.conn.execute(
            "SELECT status, scopes, namespace, client_id, expires_at, interval, last_poll, "
            "subject, delivered_token FROM device_requests WHERE device_code=?",
            (device_code,),
        ).fetchone()

    def poll(self, device_code: str, *, now: Optional[float] = None) -> dict:
        if not device_code:
            return {"error": "invalid_grant"}
        now = time.time() if now is None else now
        row = self._row(device_code)
        if not row:
            return {"error": "invalid_grant"}
        status, scopes, ns, client_id, expires_at, interval, last_poll, subject, delivered = row

        if status in ("pending", "approved") and now > expires_at:
            self.store.conn.execute(
                "UPDATE device_requests SET status='expired' WHERE device_code=?", (device_code,))
            self.store.conn.commit()
            return {"error": "expired_token"}

        # a request already marked expired must keep reporting expired_token, not
        # fall through to invalid_grant on subsequent polls (RFC 8628 §3.5)
        if status == "expired":
            return {"error": "expired_token"}

        if status == "denied":
            return {"error": "access_denied"}

        if status == "approved":
            # The grant is ready: deliver the token exactly once and don't make
            # the client wait out another poll interval. The slow_down throttle
            # (RFC 8628 §3.5) only governs *waiting* on a pending request — once
            # the user has approved, an extra interval would just delay pickup.
            if delivered:
                self.store.conn.execute(
                    "UPDATE device_requests SET delivered_token=NULL, last_poll=? "
                    "WHERE device_code=?", (now, device_code))
                self.store.conn.commit()
                return {"access_token": delivered, "token_type": "Bearer",
                        "scope": scopes, "namespace": ns}
            return {"error": "access_denied"}  # already delivered / no token

        # status == 'pending': enforce the minimum polling interval (slow_down)
        if last_poll is not None and (now - last_poll) < interval:
            return {"error": "slow_down"}
        self.store.conn.execute(
            "UPDATE device_requests SET last_poll=? WHERE device_code=?", (now, device_code))
        self.store.conn.commit()

        if status == "pending":
            return {"error": "authorization_pending"}

        return {"error": "invalid_grant"}

    def approve(self, user_code: str, subject: str, *, now: Optional[float] = None) -> bool:
        if not user_code or not subject:
            return False
        row = self.store.conn.execute(
            "SELECT device_code, scopes, namespace, status, expires_at FROM device_requests "
            "WHERE user_code=?",
            (user_code.upper(),),
        ).fetchone()
        if not row:
            return False
        device_code, scopes, ns, status, expires_at = row
        now = time.time() if now is None else now
        if status != "pending" or now > expires_at:
            return False
        token, info = self.store.issue_token(
            f"device:{subject}", set(scopes.split(",")), ns, now=now)
        self.store.conn.execute(
            "UPDATE device_requests SET status='approved', subject=?, token_id=?, "
            "delivered_token=? WHERE device_code=?",
            (subject, info.id, token, device_code),
        )
        self.store.conn.commit()
        return True

    def deny(self, user_code: str) -> bool:
        if not user_code:
            return False
        cur = self.store.conn.execute(
            "UPDATE device_requests SET status='denied' WHERE user_code=? AND status='pending'",
            (user_code.upper(),),
        )
        self.store.conn.commit()
        return cur.rowcount > 0
