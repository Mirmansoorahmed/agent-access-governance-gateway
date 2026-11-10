"""Caller identity (OIDC) -- pluggable token verifier.

Check 2 needs the caller's ``role``, ``department``, ``seniority`` and
``groups`` from a verified token. Verification is pluggable so the decision
pipeline is testable offline (no PyJWT, no network to a JWKS endpoint):

* :class:`Claims` -- the extracted, verified claim set the gateway consumes.
* :class:`TokenVerifier` -- protocol: ``verify(token) -> Claims`` or raise
  :class:`GatewayDenied(identity-invalid)``.
* :class:`HmacTokenVerifier` -- stdlib HS256 verifier (issuer/audience/expiry +
  HMAC signature). Enough to unit-test claim extraction and every failure mode
  offline. The lab's Keycloak realm issues HS256 test tokens for this path.
* :class:`StaticVerifier` -- maps opaque test tokens to fixed claims (used by
  the eval harness).
* ``build_keycloak_rs256_verifier`` / ``build_entra_verifier`` -- thin factory
  hooks for the real RS256 + JWKS path, wired in CI / the lab. Entra is an
  optional adapter: never required to run the lab.

Only the verified claim summary is kept; the raw token is never stored (feeds
evidence redaction, R9.2).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Protocol

from .errors import GatewayDenied, Reason


@dataclass(frozen=True)
class Claims:
    """Verified caller claims (summary only; never the raw token)."""

    subject: str
    role: str = ""
    department: str = ""
    seniority: str = ""
    groups: tuple[str, ...] = ()

    def summary(self) -> dict:
        """Evidence-safe summary (no secrets)."""
        return {
            "subject": self.subject,
            "role": self.role,
            "department": self.department,
            "seniority": self.seniority,
            "groups": list(self.groups),
        }


class TokenVerifier(Protocol):
    """Verifies a bearer token and returns verified :class:`Claims`."""

    def verify(self, token: str) -> Claims: ...


def _claims_from_payload(payload: dict) -> Claims:
    """Extract the gateway's claim set from a decoded JWT payload."""
    subject = payload.get("sub")
    if not subject:
        raise GatewayDenied(Reason.IDENTITY_INVALID, "token missing 'sub'")
    groups = payload.get("groups", [])
    if not isinstance(groups, list):
        raise GatewayDenied(Reason.IDENTITY_INVALID, "'groups' claim must be a list")
    return Claims(
        subject=str(subject),
        role=str(payload.get("role", "")),
        department=str(payload.get("department", "")),
        seniority=str(payload.get("seniority", "")),
        groups=tuple(str(g) for g in groups),
    )


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@dataclass
class HmacTokenVerifier:
    """Stdlib HS256 JWT verifier for the offline/lab test path."""

    secret: bytes
    issuer: str | None = None
    audience: str | None = None
    leeway_seconds: int = 0

    def verify(self, token: str) -> Claims:
        try:
            header_b64, payload_b64, signature_b64 = token.split(".")
        except ValueError as exc:
            raise GatewayDenied(Reason.IDENTITY_INVALID, "malformed token") from exc

        try:
            header = json.loads(_b64url_decode(header_b64))
            payload = json.loads(_b64url_decode(payload_b64))
        except (ValueError, json.JSONDecodeError) as exc:
            raise GatewayDenied(Reason.IDENTITY_INVALID, "undecodable token") from exc

        if header.get("alg") != "HS256":
            raise GatewayDenied(Reason.IDENTITY_INVALID, "unexpected token alg")

        expected = hmac.new(
            self.secret, f"{header_b64}.{payload_b64}".encode("ascii"), hashlib.sha256
        ).digest()
        try:
            provided = _b64url_decode(signature_b64)
        except ValueError as exc:
            raise GatewayDenied(Reason.IDENTITY_INVALID, "undecodable signature") from exc
        if not hmac.compare_digest(expected, provided):
            raise GatewayDenied(Reason.IDENTITY_INVALID, "bad signature")

        now = int(time.time())
        exp = payload.get("exp")
        if exp is not None and now > int(exp) + self.leeway_seconds:
            raise GatewayDenied(Reason.IDENTITY_INVALID, "token expired")
        if self.issuer is not None and payload.get("iss") != self.issuer:
            raise GatewayDenied(Reason.IDENTITY_INVALID, "issuer mismatch")
        if self.audience is not None and payload.get("aud") != self.audience:
            raise GatewayDenied(Reason.IDENTITY_INVALID, "audience mismatch")

        return _claims_from_payload(payload)

    def mint(self, payload: dict) -> str:
        """Test helper: mint an HS256 token for the given payload."""
        header_b64 = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        payload_b64 = _b64url_encode(json.dumps(payload).encode())
        signature = hmac.new(
            self.secret, f"{header_b64}.{payload_b64}".encode("ascii"), hashlib.sha256
        ).digest()
        return f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"


@dataclass
class StaticVerifier:
    """Maps opaque test tokens to fixed claims (eval harness convenience)."""

    tokens: dict[str, Claims] = field(default_factory=dict)

    def verify(self, token: str) -> Claims:
        claims = self.tokens.get(token)
        if claims is None:
            raise GatewayDenied(Reason.IDENTITY_INVALID, "unknown token")
        return claims


def build_keycloak_rs256_verifier(*_args, **_kwargs):  # pragma: no cover - needs network/jwt
    """Factory for the real RS256 + JWKS verifier (CI / lab only).

    Intentionally unimplemented in the offline core: it requires a JWT library
    and a reachable JWKS endpoint. Wired where network is available.
    """
    raise NotImplementedError(
        "RS256/JWKS verification is wired in CI/lab; use HmacTokenVerifier offline"
    )


def build_entra_verifier(*_args, **_kwargs):  # pragma: no cover - optional adapter stub
    """Optional Microsoft Entra adapter stub -- never required to run the lab."""
    raise NotImplementedError("Entra adapter is an optional stub; default lab uses Keycloak")
