"""Server-side authenticated identity & principal registry for ALETHEIA protected application endpoints (ALETHEIA-01)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class AletheiaPrincipal:
    subject: str
    role: str  # GUEST | RESEARCHER | ARCHIVIST | ADMIN
    tenant_id: str
    active: bool = True


class AletheiaAuthError(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class AletheiaAuthService:
    """Issues & verifies HMAC-SHA256 bearer tokens resolved strictly against server-side principals."""

    def __init__(self, secret_key: str | None = None, principals: dict[str, AletheiaPrincipal] | None = None) -> None:
        raw = secret_key or os.getenv("ALETHEIA_TOKEN_SECRET") or secrets.token_hex(32)
        self._secret = raw.encode("utf-8")
        self._principals = dict(principals or self._default_principals())

    @staticmethod
    def _default_principals() -> dict[str, AletheiaPrincipal]:
        return {
            "sub-guest-meridien": AletheiaPrincipal("sub-guest-meridien", "GUEST", "observatoire-meridien"),
            "sub-researcher-meridien": AletheiaPrincipal("sub-researcher-meridien", "RESEARCHER", "observatoire-meridien"),
            "sub-admin-meridien": AletheiaPrincipal("sub-admin-meridien", "ADMIN", "observatoire-meridien"),
            "sub-archivist-qarawiyyin": AletheiaPrincipal("sub-archivist-qarawiyyin", "ARCHIVIST", "fondation-alqarawiyyin"),
        }

    @staticmethod
    def _b64e(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

    @staticmethod
    def _b64d(s: str) -> bytes:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

    def issue_token(self, subject: str, ttl_seconds: int = 1800) -> str:
        if subject not in self._principals:
            raise KeyError(f"Unknown subject: {subject}")
        now = int(time.time())
        h = self._b64e(json.dumps({"alg": "HS256", "typ": "ALETHEIA-SESSION"}).encode())
        p = self._b64e(json.dumps({"sub": subject, "iat": now, "exp": now + ttl_seconds}).encode())
        sig = self._b64e(hmac.new(self._secret, f"{h}.{p}".encode("ascii"), hashlib.sha256).digest())
        return f"{h}.{p}.{sig}"

    def verify_bearer(self, authorization: str | None) -> AletheiaPrincipal:
        if not authorization or not authorization.startswith("Bearer "):
            raise AletheiaAuthError(401, "Missing Bearer authentication token.")
        tok = authorization.split(" ", 1)[1].strip()
        parts = tok.split(".")
        if len(parts) != 3:
            raise AletheiaAuthError(401, "Malformed session token.")
        h, p, sig = parts
        expected = self._b64e(hmac.new(self._secret, f"{h}.{p}".encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            raise AletheiaAuthError(401, "Invalid token signature.")
        try:
            claims = json.loads(self._b64d(p))
        except Exception as exc:
            raise AletheiaAuthError(401, f"Invalid token payload: {exc}") from exc
        if not isinstance(claims.get("exp"), int) or time.time() > claims["exp"]:
            raise AletheiaAuthError(401, "Session token expired.")
        sub = claims.get("sub")
        if not isinstance(sub, str) or sub not in self._principals:
            raise AletheiaAuthError(401, "Unknown principal subject.")
        principal = self._principals[sub]
        if not principal.active:
            raise AletheiaAuthError(403, "Principal account disabled.")
        return principal
