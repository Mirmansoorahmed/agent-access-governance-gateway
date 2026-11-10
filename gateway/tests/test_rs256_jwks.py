"""Tests for the Keycloak RS256/JWKS verifier (task 5 follow-up).

Uses a pure-stdlib RSA keypair generated at import time (no PyJWT, no
``cryptography``, no ``openssl`` binary, no network), so RS256 verification is
exercised fully offline. A smaller 1024-bit key keeps generation fast; the
verifier is key-size agnostic.
"""

from __future__ import annotations

import base64
import json

import pytest

from gateway.errors import GatewayDenied, Reason
from gateway.identity import RS256JWKSVerifier, build_keycloak_rs256_verifier
from gateway.rsa_jwt import generate_rsa_keypair, int_to_b64url, sign_rs256

# One keypair for the whole module (keygen is the slow part).
_N, _E, _D = generate_rsa_keypair(bits=1024)
_KID = "test-key-1"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwks() -> dict:
    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": _KID,
                "alg": "RS256",
                "n": int_to_b64url(_N),
                "e": int_to_b64url(_E),
            }
        ]
    }


def _mint(
    payload: dict, *, kid: str | None = _KID, alg: str = "RS256", sign_with_d: int = _D
) -> str:
    header = {"alg": alg, "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    header_b64 = _b64url(json.dumps(header).encode())
    payload_b64 = _b64url(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = sign_rs256(signing_input, _N, sign_with_d)
    return f"{header_b64}.{payload_b64}.{_b64url(sig)}"


def test_valid_rs256_token_yields_claims():
    v = build_keycloak_rs256_verifier(jwks=_jwks())
    token = _mint(
        {
            "sub": "u1",
            "role": "advisor",
            "department": "advisory",
            "seniority": "senior",
            "groups": ["advisors"],
        }
    )
    claims = v.verify(token)
    assert claims.subject == "u1"
    assert claims.groups == ("advisors",)


def test_bad_signature_is_invalid():
    # Sign with a different private exponent -> signature will not verify.
    _, _, other_d = generate_rsa_keypair(bits=1024)
    v = RS256JWKSVerifier(jwks=_jwks())
    token = _mint({"sub": "u1", "groups": []}, sign_with_d=other_d)
    with pytest.raises(GatewayDenied) as exc:
        v.verify(token)
    assert exc.value.reason is Reason.IDENTITY_INVALID


def test_wrong_alg_is_invalid():
    v = RS256JWKSVerifier(jwks=_jwks())
    token = _mint({"sub": "u1", "groups": []}, alg="HS256")
    with pytest.raises(GatewayDenied) as exc:
        v.verify(token)
    assert exc.value.reason is Reason.IDENTITY_INVALID


def test_unknown_kid_is_invalid():
    v = RS256JWKSVerifier(jwks=_jwks())
    token = _mint({"sub": "u1", "groups": []}, kid="no-such-kid")
    with pytest.raises(GatewayDenied) as exc:
        v.verify(token)
    assert exc.value.reason is Reason.IDENTITY_INVALID


def test_issuer_and_audience_enforced():
    v = RS256JWKSVerifier(jwks=_jwks(), issuer="https://kc/realm", audience="gateway")
    good = _mint({"sub": "u1", "groups": [], "iss": "https://kc/realm", "aud": "gateway"})
    assert v.verify(good).subject == "u1"
    bad = _mint({"sub": "u1", "groups": [], "iss": "https://evil", "aud": "gateway"})
    with pytest.raises(GatewayDenied):
        v.verify(bad)


def test_audience_array_supported():
    v = RS256JWKSVerifier(jwks=_jwks(), audience="gateway")
    token = _mint({"sub": "u1", "groups": [], "aud": ["x", "gateway"]})
    assert v.verify(token).subject == "u1"


def test_jwks_loaded_from_file(tmp_path):
    path = tmp_path / "jwks.json"
    path.write_text(json.dumps(_jwks()), encoding="utf-8")
    v = build_keycloak_rs256_verifier(jwks=str(path))
    token = _mint({"sub": "u1", "groups": ["advisors"]})
    assert v.verify(token).groups == ("advisors",)


def test_no_rsa_keys_in_jwks_is_invalid():
    v = RS256JWKSVerifier(jwks={"keys": []})
    token = _mint({"sub": "u1", "groups": []})
    with pytest.raises(GatewayDenied) as exc:
        v.verify(token)
    assert exc.value.reason is Reason.IDENTITY_INVALID


def test_rsa_roundtrip_primitive():
    # Sanity: verify_rs256 accepts a correct signature and rejects a tampered one.
    from gateway.rsa_jwt import verify_rs256

    msg = b"header.payload"
    sig = sign_rs256(msg, _N, _D)
    assert verify_rs256(msg, sig, _N, _E) is True
    assert verify_rs256(b"header.tampered", sig, _N, _E) is False
