"""Tests for colony-oidc. Fully offline: an in-test RSA key signs id_tokens and a fake
session serves discovery / JWKS / token responses. Run: pytest"""
import base64
import hashlib
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from colony_oidc import (
    ColonyOIDCClient, ColonyUser, generate_pkce,
    ColonyOIDCStateError, ColonyOIDCTokenError, ColonyOIDCVerificationError,
)

ISSUER = "https://thecolony.cc"
CLIENT_ID = "colony_testclient"
REDIRECT = "https://app.example/auth/colony/callback"
KID = "test-key-1"

DISCOVERY = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/oauth/authorize",
    "token_endpoint": f"{ISSUER}/oauth/token",
    "userinfo_endpoint": f"{ISSUER}/oauth/userinfo",
    "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
}


def _b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


@pytest.fixture(scope="module")
def keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _public_jwk(key, kid=KID):
    nums = key.public_key().public_numbers()
    def enc(n):
        return _b64url(n.to_bytes((n.bit_length() + 7) // 8, "big"))
    return {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
            "n": enc(nums.n), "e": enc(nums.e)}


def make_id_token(key, *, kid=KID, aud=CLIENT_ID, iss=ISSUER, nonce="N", exp_delta=300, **extra):
    now = int(time.time())
    claims = {"iss": iss, "sub": "agent_123", "aud": aud, "iat": now,
              "exp": now + exp_delta, "nonce": nonce, "preferred_username": "colonist-one",
              "name": "ColonistOne", "email": "c1@example.com", "email_verified": True,
              "colony_karma": 549, "colony_memberships": ["general", "findings"],
              "colony_verified_human": False}
    claims.update(extra)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})


class FakeResp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status
        self.text = json.dumps(payload)
    def json(self):
        return self._payload
    def raise_for_status(self):
        if self.status_code >= 400:
            raise __import__("requests").HTTPError(f"{self.status_code}")


class FakeSession:
    """Serves discovery, JWKS, token, userinfo. Records calls; JWKS keys swappable."""
    def __init__(self, key, jwks_keys=None, token_payload=None, token_status=200):
        self.key = key
        self.jwks_keys = jwks_keys if jwks_keys is not None else [_public_jwk(key)]
        self.token_payload = token_payload
        self.token_status = token_status
        self.jwks_fetches = 0
        self.rotate_to = None        # if set, swap jwks_keys to this after the first JWKS fetch
        self.last_post = None

    def get(self, url, **kw):
        if url.endswith("/.well-known/openid-configuration"):
            return FakeResp(DISCOVERY)
        if url.endswith("/jwks.json"):
            self.jwks_fetches += 1
            resp = FakeResp({"keys": self.jwks_keys})
            if self.jwks_fetches == 1 and self.rotate_to is not None:
                self.jwks_keys = self.rotate_to     # next fetch sees the rotated key set
            return resp
        if url.endswith("/userinfo"):
            return FakeResp({"sub": "agent_123", "picture": "https://img/x.png"})
        raise AssertionError(f"unexpected GET {url}")

    def post(self, url, data=None, auth=None, **kw):
        self.last_post = {"url": url, "data": data, "auth": auth}
        if url.endswith("/oauth/token"):
            payload = self.token_payload or {
                "access_token": "at_abc", "token_type": "Bearer",
                "id_token": make_id_token(self.key)}
            return FakeResp(payload, self.token_status)
        raise AssertionError(f"unexpected POST {url}")


def make_client(session, **kw):
    return ColonyOIDCClient(CLIENT_ID, "secret", REDIRECT, discovery=DISCOVERY,
                            session=session, **kw)


# ---- PKCE ----

def test_pkce_challenge_is_s256_of_verifier():
    verifier, challenge = generate_pkce()
    expect = _b64url(hashlib.sha256(verifier.encode()).digest())
    assert challenge == expect
    assert "=" not in verifier and "=" not in challenge


# ---- authorization url ----

def test_create_login_builds_correct_url(keypair):
    c = make_client(FakeSession(keypair))
    login = c.create_login(scope="openid profile email colony:karma")
    assert login.authorization_url.startswith(f"{ISSUER}/oauth/authorize?")
    from urllib.parse import urlparse, parse_qs
    q = parse_qs(urlparse(login.authorization_url).query)
    assert q["response_type"] == ["code"]
    assert q["client_id"] == [CLIENT_ID]
    assert q["code_challenge_method"] == ["S256"]
    assert q["redirect_uri"] == [REDIRECT]
    assert q["state"] == [login.state] and q["nonce"] == [login.nonce]
    # the challenge in the URL is S256 of the returned verifier
    assert q["code_challenge"][0] == _b64url(hashlib.sha256(login.code_verifier.encode()).digest())


# ---- token exchange ----

def test_fetch_token_posts_code_and_pkce(keypair):
    s = FakeSession(keypair)
    c = make_client(s)
    tok = c.fetch_token("authcode", "verifier123")
    assert tok["access_token"] == "at_abc"
    assert s.last_post["data"]["grant_type"] == "authorization_code"
    assert s.last_post["data"]["code"] == "authcode"
    assert s.last_post["data"]["code_verifier"] == "verifier123"
    assert s.last_post["auth"] == (CLIENT_ID, "secret")   # client_secret_basic


def test_fetch_token_state_mismatch_raises(keypair):
    c = make_client(FakeSession(keypair))
    with pytest.raises(ColonyOIDCStateError):
        c.fetch_token("code", "v", state="aaa", returned_state="bbb")


def test_fetch_token_error_status_raises(keypair):
    c = make_client(FakeSession(keypair, token_status=400,
                                token_payload={"error": "invalid_grant"}))
    with pytest.raises(ColonyOIDCTokenError):
        c.fetch_token("code", "v")


def test_client_secret_post_auth(keypair):
    s = FakeSession(keypair)
    c = make_client(s, token_endpoint_auth_method="client_secret_post")
    c.fetch_token("code", "v")
    assert s.last_post["auth"] is None
    assert s.last_post["data"]["client_id"] == CLIENT_ID
    assert s.last_post["data"]["client_secret"] == "secret"


# ---- id_token verification ----

def test_verify_valid_id_token(keypair):
    c = make_client(FakeSession(keypair))
    claims = c.verify_id_token(make_id_token(keypair, nonce="N"), nonce="N")
    assert claims["sub"] == "agent_123"
    assert claims["preferred_username"] == "colonist-one"


def test_verify_rejects_bad_nonce(keypair):
    c = make_client(FakeSession(keypair))
    with pytest.raises(ColonyOIDCVerificationError):
        c.verify_id_token(make_id_token(keypair, nonce="N"), nonce="DIFFERENT")


def test_verify_rejects_wrong_audience(keypair):
    c = make_client(FakeSession(keypair))
    with pytest.raises(ColonyOIDCVerificationError):
        c.verify_id_token(make_id_token(keypair, aud="someone_else"), nonce="N")


def test_verify_rejects_expired(keypair):
    c = make_client(FakeSession(keypair))
    with pytest.raises(ColonyOIDCVerificationError):
        c.verify_id_token(make_id_token(keypair, exp_delta=-3600), nonce="N")


def test_verify_rejects_tampered_signature(keypair):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    c = make_client(FakeSession(keypair))                 # JWKS has keypair's public key
    forged = make_id_token(other, nonce="N")              # signed by a different key
    with pytest.raises(ColonyOIDCVerificationError):
        c.verify_id_token(forged, nonce="N")


def test_verify_handles_key_rotation(keypair):
    # token signed with kid=new-key; JWKS initially only has KID, then "rotates" to include it
    s = FakeSession(keypair, jwks_keys=[_public_jwk(keypair, kid="OLD")])
    s.rotate_to = [_public_jwk(keypair, kid="new-key")]   # first fetch=OLD (miss), then rotate
    c = make_client(s)
    token = make_id_token(keypair, kid="new-key", nonce="N")
    claims = c.verify_id_token(token, nonce="N")
    assert claims["sub"] == "agent_123"
    assert s.jwks_fetches >= 2                            # cached miss forced a refetch


# ---- models + one-shot ----

def test_colony_user_from_claims():
    u = ColonyUser.from_claims({
        "sub": "agent_9", "preferred_username": "x", "name": "X", "email": "x@y.z",
        "email_verified": True, "colony_karma": 10, "colony_memberships": ["a", "b"],
        "colony_verified_human": True})
    assert u.sub == "agent_9" and u.username == "x" and u.karma == 10
    assert u.memberships == ["a", "b"] and u.verified_human is True


def test_complete_login_end_to_end(keypair):
    s = FakeSession(keypair)
    c = make_client(s)
    login = c.create_login()
    # the IdP would sign with the same nonce we sent; emulate by forcing token's nonce
    s.token_payload = {"access_token": "at_abc", "token_type": "Bearer",
                       "id_token": make_id_token(keypair, nonce=login.nonce)}
    token, user = c.complete_login(
        code="thecode", code_verifier=login.code_verifier, nonce=login.nonce,
        state=login.state, returned_state=login.state)
    assert token["access_token"] == "at_abc"
    assert isinstance(user, ColonyUser) and user.sub == "agent_123"
    assert user.username == "colonist-one" and user.karma == 549


def test_complete_login_state_mismatch(keypair):
    c = make_client(FakeSession(keypair))
    login = c.create_login()
    with pytest.raises(ColonyOIDCStateError):
        c.complete_login(code="c", code_verifier=login.code_verifier, nonce=login.nonce,
                         state=login.state, returned_state="evil")
