"""Canary tokens: unique, unpredictable references embedded in decoys.

Tokens are random (secrets module), one per decoy instance, optionally with
an expiry. A token callback is evidence of decoy INTERACTION - it is never
proof of a person's identity (a document previewer can fetch a beacon URL).
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional


def _utc() -> str:
    dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


class TokenRegistry:
    """In-memory + persisted registry mapping tokens to decoy IDs."""

    def __init__(self, callback_url_base: str = "http://127.0.0.1:8099/beacon"):
        self.base_url = callback_url_base.rstrip("/")
        self._tokens: Dict[str, Dict] = {}

    def issue(self, decoy_id: str, ttl_hours: Optional[int] = None) -> Dict:
        token = secrets.token_urlsafe(16)
        entry = {
            "token": token,
            "decoy_id": decoy_id,
            "created_at_utc": _utc(),
            "expires_at_utc": (
                (_utc_to_dt(_utc()) + timedelta(hours=ttl_hours)).strftime("%Y-%m-%dT%H:%M:%S.") + "000Z"
                if ttl_hours else None
            ),
            "url": f"{self.base_url}/{token}",
        }
        self._tokens[token] = entry
        return entry

    def url_for(self, decoy_id: str, ttl_hours: Optional[int] = None) -> str:
        return self.issue(decoy_id, ttl_hours)["url"]

    def resolve(self, token: str) -> Optional[Dict]:
        entry = self._tokens.get(token)
        if not entry:
            return None
        exp = entry.get("expires_at_utc")
        if exp:
            try:
                if _utc_to_dt(_utc()) > _utc_to_dt(exp):
                    return {**entry, "expired": True}
            except ValueError:
                pass
        return entry

    def all_tokens(self) -> Dict[str, Dict]:
        return dict(self._tokens)

    @property
    def base(self) -> str:
        return self.base_url


def _utc_to_dt(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))
