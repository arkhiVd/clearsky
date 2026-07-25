"""authn: real RS256 round-trip using a locally generated key (pure math —
we build a valid PKCS1-v1_5 signature with the private exponent and check
verify() accepts it and rejects tampering)."""

import base64
import hashlib
import json
import time

import pytest

from clearsky import authn

# tiny deterministic RSA key (512-bit — fine for tests, never for prod)
import random

def _miller_rabin(n: int, rounds=40) -> bool:
    if n % 2 == 0:
        return n == 2
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int, rng: random.Random) -> int:
    while True:
        cand = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _miller_rabin(cand):
            return cand


_rng = random.Random(42)
P = _gen_prime(256, _rng)
Q = _gen_prime(256, _rng)
N = P * Q
E = 65537
D = pow(E, -1, (P - 1) * (Q - 1))
K = (N.bit_length() + 7) // 8


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _sign(signing_input: bytes) -> bytes:
    digest = hashlib.sha256(signing_input).digest()
    t = authn._SHA256_DER + digest
    em = b"\x00\x01" + b"\xff" * (K - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"), D, N).to_bytes(K, "big")


def _token(claims: dict, kid="test-key") -> str:
    header = _b64url(json.dumps({"alg": "RS256", "kid": kid}).encode())
    payload = _b64url(json.dumps(claims).encode())
    sig = _sign(f"{header}.{payload}".encode())
    return f"{header}.{payload}.{_b64url(sig)}"


@pytest.fixture()
def env(monkeypatch):
    monkeypatch.setenv("COGNITO_POOL_ID", "us-east-1_TEST")
    monkeypatch.setenv("COGNITO_CLIENT_ID", "client123")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    authn._JWKS.clear()
    authn._JWKS["test-key"] = {
        "kid": "test-key", "kty": "RSA",
        "n": _b64url(N.to_bytes(K, "big")),
        "e": _b64url(E.to_bytes(3, "big")),
    }
    yield
    authn._JWKS.clear()


def _claims(**over):
    base = {
        "sub": "user-1", "token_use": "id", "aud": "client123",
        "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TEST",
        "exp": int(time.time()) + 3600, "email": "u@example.com",
    }
    base.update(over)
    return base


def test_valid_token_verifies(env):
    claims = authn.verify(_token(_claims()))
    assert claims["sub"] == "user-1"


def test_rejects_tampered_payload(env):
    tok = _token(_claims())
    h, p, s = tok.split(".")
    forged = _b64url(json.dumps(_claims(sub="attacker")).encode())
    with pytest.raises(authn.AuthError, match="bad signature"):
        authn.verify(f"{h}.{forged}.{s}")


def test_rejects_expired_wrong_aud_and_access_token(env):
    with pytest.raises(authn.AuthError, match="expired"):
        authn.verify(_token(_claims(exp=int(time.time()) - 10)))
    with pytest.raises(authn.AuthError, match="audience"):
        authn.verify(_token(_claims(aud="other-client")))
    with pytest.raises(authn.AuthError, match="not an id token"):
        authn.verify(_token(_claims(token_use="access")))
    with pytest.raises(authn.AuthError, match="issuer"):
        authn.verify(_token(_claims(iss="https://evil.example.com")))


def test_authenticate_reads_bearer_header(env):
    event = {"headers": {"authorization": f"Bearer {_token(_claims())}"}}
    assert authn.authenticate(event)["sub"] == "user-1"
    with pytest.raises(authn.AuthError, match="missing bearer"):
        authn.authenticate({"headers": {}})


def test_rejects_alg_none(env):
    header = _b64url(json.dumps({"alg": "none", "kid": "test-key"}).encode())
    payload = _b64url(json.dumps(_claims()).encode())
    with pytest.raises(authn.AuthError, match="algorithm"):
        authn.verify(f"{header}.{payload}.{_b64url(b'')}")
