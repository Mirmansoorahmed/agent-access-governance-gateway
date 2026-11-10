"""Tests for OIDC claim extraction and verification failure modes (task 5)."""

from __future__ import annotations

import time

import pytest

from gateway.errors import GatewayDenied, Reason
from gateway.identity import (
    Claims,
    HmacTokenVerifier,
    StaticVerifier,
    build_entra_verifier,
    build_keycloak_rs256_verifier,
)

SECRET = b"unit-secret"


def _verifier(**kwargs) -> HmacTokenVerifier:
    return HmacTokenVerifier(secret=SECRET, **kwargs)


def test_valid_token_yields_claims():
    v = _verifier()
    token = v.mint(
        {
            "sub": "u1",
            "role": "advisor",
            "department": "advisory",
            "seniority": "senior",
            "groups": ["advisors", "eu"],
        }
    )
    claims = v.verify(token)
    assert claims == Claims("u1", "advisor", "advisory", "senior", ("advisors", "eu"))


def test_missing_sub_is_identity_invalid():
    v = _verifier()
    token = v.mint({"role": "advisor"})
    with pytest.raises(GatewayDenied) as exc:
        v.verify(token)
    assert exc.value.reason is Reason.IDENTITY_INVALID


def test_malformed_token_is_identity_invalid():
    with pytest.raises(GatewayDenied) as exc:
        _verifier().verify("not-a-jwt")
    assert exc.value.reason is Reason.IDENTITY_INVALID


def test_bad_signature_is_identity_invalid():
    token = HmacTokenVerifier(secret=b"other").mint({"sub": "u1", "groups": []})
    with pytest.raises(GatewayDenied) as exc:
        _verifier().verify(token)
    assert exc.value.reason is Reason.IDENTITY_INVALID


def test_expired_token_is_identity_invalid():
    v = _verifier()
    token = v.mint({"sub": "u1", "groups": [], "exp": int(time.time()) - 10})
    with pytest.raises(GatewayDenied) as exc:
        v.verify(token)
    assert exc.value.reason is Reason.IDENTITY_INVALID


def test_leeway_allows_recently_expired():
    v = _verifier(leeway_seconds=60)
    token = v.mint({"sub": "u1", "groups": [], "exp": int(time.time()) - 5})
    assert v.verify(token).subject == "u1"


def test_issuer_mismatch_is_identity_invalid():
    v = _verifier(issuer="https://keycloak/realm")
    token = v.mint({"sub": "u1", "groups": [], "iss": "https://evil"})
    with pytest.raises(GatewayDenied) as exc:
        v.verify(token)
    assert exc.value.reason is Reason.IDENTITY_INVALID


def test_audience_mismatch_is_identity_invalid():
    v = _verifier(audience="gateway")
    token = v.mint({"sub": "u1", "groups": [], "aud": "someone-else"})
    with pytest.raises(GatewayDenied) as exc:
        v.verify(token)
    assert exc.value.reason is Reason.IDENTITY_INVALID


def test_issuer_and_audience_match_ok():
    v = _verifier(issuer="iss", audience="aud")
    token = v.mint({"sub": "u1", "groups": ["advisors"], "iss": "iss", "aud": "aud"})
    assert v.verify(token).groups == ("advisors",)


def test_non_list_groups_is_identity_invalid():
    v = _verifier()
    token = v.mint({"sub": "u1", "groups": "advisors"})
    with pytest.raises(GatewayDenied) as exc:
        v.verify(token)
    assert exc.value.reason is Reason.IDENTITY_INVALID


def test_wrong_alg_is_identity_invalid():
    # Hand-craft a token with alg=none.
    import base64
    import json

    def b64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = b64(json.dumps({"sub": "u1", "groups": []}).encode())
    with pytest.raises(GatewayDenied) as exc:
        _verifier().verify(f"{header}.{payload}.")
    assert exc.value.reason is Reason.IDENTITY_INVALID


def test_static_verifier_known_and_unknown():
    claims = Claims("u1", groups=("advisors",))
    v = StaticVerifier(tokens={"tok": claims})
    assert v.verify("tok") is claims
    with pytest.raises(GatewayDenied):
        v.verify("nope")


def test_claims_summary_has_no_raw_token():
    summary = Claims("u1", "advisor", "advisory", "senior", ("advisors",)).summary()
    assert summary == {
        "subject": "u1",
        "role": "advisor",
        "department": "advisory",
        "seniority": "senior",
        "groups": ["advisors"],
    }


def test_rs256_and_entra_factories_are_stubs():
    with pytest.raises(NotImplementedError):
        build_keycloak_rs256_verifier()
    with pytest.raises(NotImplementedError):
        build_entra_verifier()
