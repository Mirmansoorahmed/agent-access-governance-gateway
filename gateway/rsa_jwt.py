"""Pure-standard-library RSA (RS256) primitives for JWT verification.

The offline sandbox has neither PyJWT nor ``cryptography``, yet the gateway must
verify RS256 JWTs (Keycloak's default) and be testable offline. RSASSA-PKCS1-v1_5
verification is just modular exponentiation plus a fixed SHA-256 padding check --
all expressible with Python's big integers and :mod:`hashlib`. This module
provides:

* :func:`verify_rs256` -- verify a signed ``header.payload`` against an RSA
  public key ``(n, e)`` (as from a JWKS entry).
* :func:`sign_rs256` / :func:`generate_rsa_keypair` -- test-only helpers so the
  suite can mint and verify real RS256 tokens without any third-party library or
  the ``openssl`` binary.
* base64url int <-> bytes helpers matching the JWK encoding.

Security note: this is a deliberately small, auditable verifier for a lab PEP.
In production you would prefer a vetted crypto library; the adapter boundary
(``RS256JWKSVerifier``) makes that swap trivial.
"""

from __future__ import annotations

import base64
import hashlib
import secrets

# PKCS#1 v1.5 DigestInfo prefix for SHA-256 (RFC 8017, section 9.2).
_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def b64url_to_int(value: str) -> int:
    """Decode a base64url-encoded big-endian integer (JWK ``n`` / ``e``)."""
    padding = "=" * (-len(value) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(value + padding), "big")


def int_to_b64url(value: int) -> str:
    """Encode an integer as base64url (minimal big-endian bytes)."""
    length = (value.bit_length() + 7) // 8
    raw = value.to_bytes(length or 1, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _emsa_pkcs1_v15(message: bytes, em_len: int) -> bytes:
    """Build the EMSA-PKCS1-v1_5 encoded message for SHA-256."""
    digest = hashlib.sha256(message).digest()
    t = _SHA256_DIGEST_INFO_PREFIX + digest
    # EM = 0x00 || 0x01 || PS (0xFF...) || 0x00 || T
    ps_len = em_len - len(t) - 3
    if ps_len < 8:
        raise ValueError("intended encoded message length too short")
    return b"\x00\x01" + (b"\xff" * ps_len) + b"\x00" + t


def verify_rs256(signing_input: bytes, signature: bytes, n: int, e: int) -> bool:
    """Verify an RS256 signature over *signing_input* with public key (n, e)."""
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    sig_int = int.from_bytes(signature, "big")
    if sig_int >= n:
        return False
    em_int = pow(sig_int, e, n)
    em = em_int.to_bytes(k, "big")
    try:
        expected = _emsa_pkcs1_v15(signing_input, k)
    except ValueError:
        return False
    return secrets.compare_digest(em, expected)


# --------------------------------------------------------------------------
# Test-only helpers (keygen + signing). Not used on the verification path.
# --------------------------------------------------------------------------
def sign_rs256(signing_input: bytes, n: int, d: int) -> bytes:
    """Sign *signing_input* with the RSA private exponent (test helper)."""
    k = (n.bit_length() + 7) // 8
    em = _emsa_pkcs1_v15(signing_input, k)
    sig_int = pow(int.from_bytes(em, "big"), d, n)
    return sig_int.to_bytes(k, "big")


def _is_probable_prime(num: int, rounds: int = 40) -> bool:
    if num < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if num % small == 0:
            return num == small
    d = num - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(num - 3) + 2
        x = pow(a, d, num)
        if x in (1, num - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, num)
            if x == num - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def generate_rsa_keypair(bits: int = 2048, e: int = 65537) -> tuple[int, int, int]:
    """Generate an RSA keypair ``(n, e, d)`` using only the standard library.

    Test-only. Returns the modulus, public exponent, and private exponent.
    """
    half = bits // 2
    while True:
        p = _gen_prime(half)
        q = _gen_prime(bits - half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        d = pow(e, -1, phi)
        if n.bit_length() == bits:
            return n, e, d
