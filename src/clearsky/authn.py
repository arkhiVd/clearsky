"""Cognito JWT verification for the API lambda — pure stdlib.

The dashboard is served from CloudFront+S3 and signs users in against
Cognito directly (USER_PASSWORD_AUTH via the custom login page). Every
/api/* request carries the Cognito ID token as a Bearer header, and the
Lambda function URL sits behind CloudFront OAC (SigV4) — so this module
is the user-identity gate, and OAC is the network gate.

RS256 verification is implemented with hashlib + integer math
(EMSA-PKCS1-v1_5) so the lambda keeps the project's zero-dependency rule.
JWKS is fetched once per container from the pool's well-known URL.
"""

import base64
import hashlib
import json
import logging
import os
import time
import urllib.request

logger = logging.getLogger(__name__)

_JWKS: dict[str, dict] = {}          # kid -> jwk, cached per container

# DER prefix for a SHA-256 DigestInfo (RFC 8017, EMSA-PKCS1-v1_5)
_SHA256_DER = bytes.fromhex("3031300d060960864801650304020105000420")


class AuthError(Exception):
    pass


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _jwks_url() -> str:
    region = os.environ.get("AWS_REGION", "us-east-1")
    pool = os.environ["COGNITO_POOL_ID"]
    return (f"https://cognito-idp.{region}.amazonaws.com/{pool}"
            "/.well-known/jwks.json")


def _get_jwk(kid: str) -> dict:
    if kid not in _JWKS:
        with urllib.request.urlopen(_jwks_url(), timeout=5) as resp:
            data = json.loads(resp.read())
        _JWKS.clear()
        _JWKS.update({k["kid"]: k for k in data.get("keys", [])})
    if kid not in _JWKS:
        raise AuthError("unknown signing key")
    return _JWKS[kid]


def _rs256_verify(signing_input: bytes, signature: bytes, jwk: dict) -> bool:
    n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    em = pow(int.from_bytes(signature, "big"), e, n).to_bytes(k, "big")
    digest = hashlib.sha256(signing_input).digest()
    t = _SHA256_DER + digest
    ps_len = k - len(t) - 3
    if ps_len < 8:
        return False
    expected = b"\x00\x01" + b"\xff" * ps_len + b"\x00" + t
    return em == expected


def verify(token: str) -> dict:
    """Validate a Cognito ID token; returns its claims or raises AuthError."""
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        header = json.loads(_b64url_decode(header_b64))
        claims = json.loads(_b64url_decode(payload_b64))
        signature = _b64url_decode(sig_b64)
    except Exception as err:
        raise AuthError("malformed token") from err
    if header.get("alg") != "RS256":
        raise AuthError("unexpected algorithm")
    jwk = _get_jwk(header.get("kid", ""))
    if not _rs256_verify(f"{header_b64}.{payload_b64}".encode("ascii"),
                         signature, jwk):
        raise AuthError("bad signature")
    if claims.get("exp", 0) < time.time():
        raise AuthError("token expired")
    if claims.get("token_use") != "id":
        raise AuthError("not an id token")
    if claims.get("aud") != os.environ.get("COGNITO_CLIENT_ID"):
        raise AuthError("wrong audience")
    region = os.environ.get("AWS_REGION", "us-east-1")
    issuer = (f"https://cognito-idp.{region}.amazonaws.com/"
              f"{os.environ.get('COGNITO_POOL_ID', '')}")
    if claims.get("iss") != issuer:
        raise AuthError("wrong issuer")
    return claims


def authenticate(event) -> dict:
    """Extract + verify the Bearer token from a function-URL event.

    The browser sends the token as x-authorization: the real Authorization
    header belongs to CloudFront's OAC SigV4 signature (and forwarding a
    viewer Authorization header would disable that signing entirely)."""
    headers = event.get("headers") or {}
    auth = (headers.get("x-authorization") or headers.get("X-Authorization")
            or headers.get("authorization") or headers.get("Authorization") or "")
    if not auth.startswith("Bearer "):
        raise AuthError("missing bearer token")
    return verify(auth[7:])
