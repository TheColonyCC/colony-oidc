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
    ColonyOIDCConfigError, ColonyOIDCConsentRequired, ColonyOIDCError,
    ColonyOIDCLoginRequired, ColonyOIDCStateError, ColonyOIDCTokenError,
    ColonyOIDCVerificationError,
)

BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"

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
    "end_session_endpoint": f"{ISSUER}/oauth/logout",
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


def make_logout_token(key, *, kid=KID, aud=CLIENT_ID, iss=ISSUER, sub="agent_123",
                      sid="sess_42", events="default", include_iat=True, alg="RS256",
                      **extra):
    """A spec-shaped back-channel logout token, with knobs for the negative cases."""
    now = int(time.time())
    claims = {"iss": iss, "aud": aud, "exp": now + 120, "jti": "logout-jti-1"}
    if include_iat:
        claims["iat"] = now
    if sub is not None:
        claims["sub"] = sub
    if sid is not None:
        claims["sid"] = sid
    if events == "default":
        claims["events"] = {BACKCHANNEL_LOGOUT_EVENT: {}}
    elif events is not None:
        claims["events"] = events
    claims.update(extra)
    return jwt.encode(claims, key, algorithm=alg, headers={"kid": kid})


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


# ---- RFC 8693 token exchange (the agent-native path) ----

def test_exchange_token_posts_rfc8693(keypair):
    s = FakeSession(keypair)
    c = make_client(s)
    tok = c.exchange_token("the-agent-jwt", audience=CLIENT_ID)
    assert tok["access_token"] == "at_abc"
    d = s.last_post["data"]
    assert d["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange"
    assert d["subject_token"] == "the-agent-jwt"
    assert d["subject_token_type"] == "urn:ietf:params:oauth:token-type:access_token"
    assert d["audience"] == CLIENT_ID
    assert d["scope"] == "openid profile"


def test_exchange_token_defaults_audience_to_client_id(keypair):
    s = FakeSession(keypair)
    c = make_client(s)
    c.exchange_token("jwt-only")
    assert s.last_post["data"]["audience"] == CLIENT_ID


def test_exchange_token_error_status_raises(keypair):
    c = make_client(FakeSession(keypair, token_status=400,
                                token_payload={"error": "invalid_target"}))
    with pytest.raises(ColonyOIDCTokenError):
        c.exchange_token("jwt", audience="bad-aud")


def test_exchanged_id_token_verifies_without_a_nonce(keypair):
    # An exchanged id_token carries no nonce; verify_id_token must accept it when
    # called without one.
    s = FakeSession(keypair, token_payload={
        "access_token": "at", "token_type": "Bearer",
        "id_token": make_id_token(keypair, nonce=None)})
    c = make_client(s)
    tok = c.exchange_token("agent-jwt")
    claims = c.verify_id_token(tok["id_token"])
    assert claims["preferred_username"] == "colonist-one"


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


# ---- humans vs agents: ColonyUser.is_human / is_agent ----

def test_is_human_is_agent_for_human():
    u = ColonyUser.from_claims({"sub": "u1", "colony_verified_human": True})
    assert u.is_human is True and u.is_agent is False


def test_is_human_is_agent_for_agent():
    u = ColonyUser.from_claims({"sub": "u1", "colony_verified_human": False})
    assert u.is_human is False and u.is_agent is True


def test_is_human_is_agent_when_claim_absent():
    # colony_verified_human only present with the profile scope; absent -> both falsey
    u = ColonyUser.from_claims({"sub": "u1"})
    assert u.verified_human is None
    assert u.is_human is False and u.is_agent is False


# ---- accept_subject (RP-side audience guard) ----

def _complete(c, keypair, **id_token_extra):
    s = c._http
    login = c.create_login()
    s.token_payload = {"access_token": "at_abc", "token_type": "Bearer",
                       "id_token": make_id_token(keypair, nonce=login.nonce, **id_token_extra)}
    return c.complete_login(code="thecode", code_verifier=login.code_verifier,
                            nonce=login.nonce, state=login.state, returned_state=login.state)


def test_accept_subject_bad_value_raises():
    with pytest.raises(ColonyOIDCConfigError):
        make_client(FakeSession(None, jwks_keys=[]), accept_subject="robot")


def test_accept_subject_human_rejects_agent(keypair):
    c = make_client(FakeSession(keypair), accept_subject="human")
    with pytest.raises(ColonyOIDCVerificationError):
        _complete(c, keypair, colony_verified_human=False)


def test_accept_subject_agent_rejects_human(keypair):
    c = make_client(FakeSession(keypair), accept_subject="agent")
    with pytest.raises(ColonyOIDCVerificationError):
        _complete(c, keypair, colony_verified_human=True)


def test_accept_subject_human_allows_human(keypair):
    c = make_client(FakeSession(keypair), accept_subject="human")
    _token, user = _complete(c, keypair, colony_verified_human=True)
    assert user.is_human is True


def test_accept_subject_agent_allows_agent(keypair):
    c = make_client(FakeSession(keypair), accept_subject="agent")
    _token, user = _complete(c, keypair, colony_verified_human=False)
    assert user.is_agent is True


def test_accept_subject_restrictive_missing_claim_raises_config_error(keypair):
    # profile scope not requested -> no colony_verified_human claim -> never silently allow
    c = make_client(FakeSession(keypair), accept_subject="human")
    with pytest.raises(ColonyOIDCConfigError):
        _complete(c, keypair, colony_verified_human=None)


def test_accept_subject_any_never_raises_on_type(keypair):
    # default "any": neither subject type nor a missing claim is an error
    c = make_client(FakeSession(keypair))
    _token, user = _complete(c, keypair, colony_verified_human=False)
    assert user.is_agent is True
    c2 = make_client(FakeSession(keypair))
    _token2, user2 = _complete(c2, keypair, colony_verified_human=None)
    assert user2.verified_human is None


# ---- RP-initiated logout: end_session_url ----

def test_end_session_url_builds_with_all_params(keypair):
    from urllib.parse import urlparse, parse_qs
    c = make_client(FakeSession(keypair))
    url = c.end_session_url(id_token_hint="idt.123",
                            post_logout_redirect_uri="https://app.example/bye?a=b",
                            state="xyz")
    parts = urlparse(url)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == f"{ISSUER}/oauth/logout"
    q = parse_qs(parts.query)
    assert q["client_id"] == [CLIENT_ID]
    assert q["id_token_hint"] == ["idt.123"]
    assert q["post_logout_redirect_uri"] == ["https://app.example/bye?a=b"]  # urlencoded round-trip
    assert q["state"] == ["xyz"]
    assert "%2F" in parts.query or "%3A" in parts.query   # the redirect uri was urlencoded


def test_end_session_url_omits_unset_params_and_performs_no_http(keypair):
    from urllib.parse import urlparse, parse_qs
    s = FakeSession(keypair)
    c = make_client(s)
    url = c.end_session_url()
    q = parse_qs(urlparse(url).query)
    assert q == {"client_id": [CLIENT_ID]}                # only client_id
    assert s.last_post is None and s.jwks_fetches == 0    # purely a URL builder


# ---- refresh tokens ----

def test_refresh_token_happy_path_basic_auth(keypair):
    s = FakeSession(keypair)
    s.token_payload = {"access_token": "at_new", "token_type": "Bearer",
                       "refresh_token": "rt_rotated"}
    c = make_client(s)
    tok = c.refresh_token("rt_old", scope="openid offline_access")
    assert tok["access_token"] == "at_new" and tok["refresh_token"] == "rt_rotated"
    assert s.last_post["data"]["grant_type"] == "refresh_token"
    assert s.last_post["data"]["refresh_token"] == "rt_old"
    assert s.last_post["data"]["scope"] == "openid offline_access"
    assert s.last_post["auth"] == (CLIENT_ID, "secret")   # client_secret_basic


def test_refresh_token_happy_path_post_auth(keypair):
    s = FakeSession(keypair)
    s.token_payload = {"access_token": "at_new", "token_type": "Bearer",
                       "refresh_token": "rt_rotated"}
    c = make_client(s, token_endpoint_auth_method="client_secret_post")
    tok = c.refresh_token("rt_old")
    assert tok["refresh_token"] == "rt_rotated"
    assert s.last_post["auth"] is None
    assert s.last_post["data"]["client_id"] == CLIENT_ID
    assert s.last_post["data"]["client_secret"] == "secret"
    assert "scope" not in s.last_post["data"]             # omitted when not narrowed


def test_refresh_token_error_body_raises(keypair):
    c = make_client(FakeSession(keypair, token_payload={"error": "invalid_grant"}))
    with pytest.raises(ColonyOIDCTokenError):
        c.refresh_token("rt_replayed")


def test_refresh_token_non_200_raises(keypair):
    c = make_client(FakeSession(keypair, token_status=400,
                                token_payload={"error": "invalid_grant"}))
    with pytest.raises(ColonyOIDCTokenError):
        c.refresh_token("rt_old")


# ---- back-channel logout: validate_logout_token ----

def test_validate_logout_token_valid_returns_sub_and_sid(keypair):
    c = make_client(FakeSession(keypair))
    claims = c.validate_logout_token(make_logout_token(keypair))
    assert claims["sub"] == "agent_123"
    assert claims["sid"] == "sess_42"
    assert BACKCHANNEL_LOGOUT_EVENT in claims["events"]


def test_validate_logout_token_sub_only(keypair):
    c = make_client(FakeSession(keypair))
    claims = c.validate_logout_token(make_logout_token(keypair, sid=None))
    assert claims["sub"] == "agent_123" and "sid" not in claims


def test_validate_logout_token_sid_only(keypair):
    c = make_client(FakeSession(keypair))
    claims = c.validate_logout_token(make_logout_token(keypair, sub=None))
    assert claims["sid"] == "sess_42" and "sub" not in claims


def test_validate_logout_token_wrong_issuer(keypair):
    c = make_client(FakeSession(keypair))
    with pytest.raises(ColonyOIDCVerificationError):
        c.validate_logout_token(make_logout_token(keypair, iss="https://evil.example"))


def test_validate_logout_token_wrong_audience(keypair):
    c = make_client(FakeSession(keypair))
    with pytest.raises(ColonyOIDCVerificationError):
        c.validate_logout_token(make_logout_token(keypair, aud="someone_else"))


def test_validate_logout_token_missing_iat(keypair):
    c = make_client(FakeSession(keypair))
    with pytest.raises(ColonyOIDCVerificationError):
        c.validate_logout_token(make_logout_token(keypair, include_iat=False))


def test_validate_logout_token_expired(keypair):
    c = make_client(FakeSession(keypair))
    now = int(time.time())
    tok = make_logout_token(keypair, exp=now - 3600)
    with pytest.raises(ColonyOIDCVerificationError):
        c.validate_logout_token(tok)


def test_validate_logout_token_missing_events(keypair):
    c = make_client(FakeSession(keypair))
    with pytest.raises(ColonyOIDCVerificationError):
        c.validate_logout_token(make_logout_token(keypair, events=None))


def test_validate_logout_token_wrong_event_key(keypair):
    c = make_client(FakeSession(keypair))
    bad = {"http://schemas.openid.net/event/some-other-event": {}}
    with pytest.raises(ColonyOIDCVerificationError):
        c.validate_logout_token(make_logout_token(keypair, events=bad))


def test_validate_logout_token_events_not_object(keypair):
    c = make_client(FakeSession(keypair))
    with pytest.raises(ColonyOIDCVerificationError):
        c.validate_logout_token(make_logout_token(keypair, events="not-a-dict"))


def test_validate_logout_token_nonce_present_rejected(keypair):
    c = make_client(FakeSession(keypair))
    with pytest.raises(ColonyOIDCVerificationError):
        c.validate_logout_token(make_logout_token(keypair, nonce="N"))


def test_validate_logout_token_neither_sub_nor_sid(keypair):
    c = make_client(FakeSession(keypair))
    with pytest.raises(ColonyOIDCVerificationError):
        c.validate_logout_token(make_logout_token(keypair, sub=None, sid=None))


def test_validate_logout_token_bad_signature(keypair):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    c = make_client(FakeSession(keypair))                 # JWKS has keypair's public key
    forged = make_logout_token(other)                     # signed by a different key
    with pytest.raises(ColonyOIDCVerificationError):
        c.validate_logout_token(forged)


def test_validate_logout_token_alg_none_rejected(keypair):
    c = make_client(FakeSession(keypair))
    now = int(time.time())
    unsigned = jwt.encode(
        {"iss": ISSUER, "aud": CLIENT_ID, "iat": now, "sub": "agent_123",
         "events": {BACKCHANNEL_LOGOUT_EVENT: {}}},
        key="", algorithm="none", headers={"kid": KID})
    with pytest.raises(ColonyOIDCVerificationError):
        c.validate_logout_token(unsigned)


def test_validate_logout_token_selects_by_kid(keypair):
    # logout token signed with the second of two JWKS keys -> kid selection must work
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = [_public_jwk(keypair, kid="k1"), _public_jwk(other, kid="k2")]
    c = make_client(FakeSession(keypair, jwks_keys=jwks))
    claims = c.validate_logout_token(make_logout_token(other, kid="k2"))
    assert claims["sub"] == "agent_123"


# ---- silent SSO (prompt=none) ----

def test_create_silent_login_sets_prompt_none(keypair):
    from urllib.parse import urlparse, parse_qs
    c = make_client(FakeSession(keypair))
    login = c.create_silent_login(scope="openid profile")
    q = parse_qs(urlparse(login.authorization_url).query)
    assert q["prompt"] == ["none"]
    assert q["scope"] == ["openid profile"]


def test_create_silent_login_overrides_passed_prompt(keypair):
    from urllib.parse import urlparse, parse_qs
    c = make_client(FakeSession(keypair))
    login = c.create_silent_login(prompt="login")
    q = parse_qs(urlparse(login.authorization_url).query)
    assert q["prompt"] == ["none"]


def test_raise_for_callback_error_login_required(keypair):
    c = make_client(FakeSession(keypair))
    with pytest.raises(ColonyOIDCLoginRequired):
        c.raise_for_callback_error({"error": "login_required"})


def test_raise_for_callback_error_consent_required(keypair):
    c = make_client(FakeSession(keypair))
    with pytest.raises(ColonyOIDCConsentRequired):
        c.raise_for_callback_error({"error": "consent_required",
                                    "error_description": "needs consent"})


def test_raise_for_callback_error_generic(keypair):
    c = make_client(FakeSession(keypair))
    with pytest.raises(ColonyOIDCError) as ei:
        c.raise_for_callback_error({"error": "interaction_required"})
    # not one of the typed silent-SSO subclasses
    assert not isinstance(ei.value, (ColonyOIDCLoginRequired, ColonyOIDCConsentRequired))


def test_raise_for_callback_error_noop_on_clean_code(keypair):
    c = make_client(FakeSession(keypair))
    assert c.raise_for_callback_error({"code": "abc", "state": "xyz"}) is None


# ---- granular consent: granted_scopes ----

def test_granted_scopes_reflects_token_response(keypair):
    s = FakeSession(keypair)
    c = make_client(s)
    login = c.create_login(scope="openid profile email colony:karma")
    # user declined email + colony:karma at the consent screen
    s.token_payload = {"access_token": "at_abc", "token_type": "Bearer",
                       "scope": "openid profile",
                       "id_token": make_id_token(keypair, nonce=login.nonce)}
    _token, user = c.complete_login(
        code="thecode", code_verifier=login.code_verifier, nonce=login.nonce,
        state=login.state, returned_state=login.state)
    assert user.granted_scopes == ["openid", "profile"]
    assert "email" not in user.granted_scopes


def test_granted_scopes_empty_when_absent(keypair):
    s = FakeSession(keypair)
    c = make_client(s)
    login = c.create_login()
    s.token_payload = {"access_token": "at_abc", "token_type": "Bearer",
                       "id_token": make_id_token(keypair, nonce=login.nonce)}
    _token, user = c.complete_login(
        code="thecode", code_verifier=login.code_verifier, nonce=login.nonce,
        state=login.state, returned_state=login.state)
    assert user.granted_scopes == []


# ---- multi-key JWKS / rotation robustness ----

def test_id_token_verifies_with_either_of_two_keys(keypair):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = [_public_jwk(keypair, kid="k1"), _public_jwk(other, kid="k2")]
    # token signed by the FIRST kid
    c1 = make_client(FakeSession(keypair, jwks_keys=jwks))
    assert c1.verify_id_token(make_id_token(keypair, kid="k1", nonce="N"),
                              nonce="N")["sub"] == "agent_123"
    # token signed by the SECOND kid (same JWKS) -> kid selection picks the right key
    c2 = make_client(FakeSession(other, jwks_keys=jwks))
    assert c2.verify_id_token(make_id_token(other, kid="k2", nonce="N"),
                              nonce="N")["sub"] == "agent_123"


def test_unknown_kid_refetches_once_then_fails(keypair):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    s = FakeSession(other, jwks_keys=[_public_jwk(keypair, kid="k1")])
    c = make_client(s)
    token = make_id_token(other, kid="unknown-kid", nonce="N")
    with pytest.raises(ColonyOIDCVerificationError):
        c.verify_id_token(token, nonce="N")
    assert s.jwks_fetches == 2                            # cached miss forced one refetch


# ---- private_key_jwt client authentication (RFC 7523) ----

from urllib.parse import parse_qs, urlparse  # noqa: E402

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
TOKEN_ENDPOINT = f"{ISSUER}/oauth/token"


def _decode_assertion(assertion, pubkey):
    return jwt.decode(assertion, pubkey.public_key(), algorithms=["RS256"],
                      audience=TOKEN_ENDPOINT)


def _pkjwt_client(session, keypair, **kw):
    return ColonyOIDCClient(CLIENT_ID, discovery=DISCOVERY, session=session,
                            token_endpoint_auth_method="private_key_jwt",
                            private_key=keypair, **kw)


def test_private_key_jwt_token_request_sends_signed_assertion(keypair):
    s = FakeSession(keypair)
    c = _pkjwt_client(s, keypair, private_key_id="ck-1")
    c.fetch_token("authcode", "verifier123")
    data = s.last_post["data"]
    # no HTTP Basic auth and no shared secret travels with an assertion
    assert s.last_post["auth"] is None
    assert "client_secret" not in data
    assert data["client_assertion_type"] == CLIENT_ASSERTION_TYPE
    header = jwt.get_unverified_header(data["client_assertion"])
    assert header["alg"] == "RS256" and header["kid"] == "ck-1"
    claims = _decode_assertion(data["client_assertion"], keypair)   # verifies signature + aud
    assert claims["iss"] == CLIENT_ID and claims["sub"] == CLIENT_ID   # RFC 7523 §3
    assert claims["aud"] == TOKEN_ENDPOINT
    assert claims["jti"]
    assert 0 < claims["exp"] - claims["iat"] <= 300                  # IdP caps lifetime at 5 min


def test_private_key_jwt_refresh_also_signs(keypair):
    s = FakeSession(keypair, token_payload={
        "access_token": "at2", "token_type": "Bearer", "refresh_token": "rt2"})
    c = _pkjwt_client(s, keypair)
    c.refresh_token("rt1")
    assert s.last_post["auth"] is None
    assert "client_assertion" in s.last_post["data"]
    assert s.last_post["data"]["grant_type"] == "refresh_token"


def test_private_key_jwt_jti_is_unique_per_request(keypair):
    s = FakeSession(keypair)
    c = _pkjwt_client(s, keypair)
    c.fetch_token("c", "v")
    jti1 = _decode_assertion(s.last_post["data"]["client_assertion"], keypair)["jti"]
    c.fetch_token("c", "v")
    jti2 = _decode_assertion(s.last_post["data"]["client_assertion"], keypair)["jti"]
    assert jti1 != jti2                                             # single-use, replay-safe


def test_private_key_jwt_requires_a_key():
    with pytest.raises(ColonyOIDCConfigError):
        ColonyOIDCClient(CLIENT_ID, discovery=DISCOVERY,
                         token_endpoint_auth_method="private_key_jwt")


def test_private_key_jwt_rejects_symmetric_alg(keypair):
    with pytest.raises(ColonyOIDCConfigError):
        ColonyOIDCClient(CLIENT_ID, discovery=DISCOVERY,
                         token_endpoint_auth_method="private_key_jwt",
                         private_key=keypair, signing_alg="HS256")


def test_secret_methods_still_require_a_secret():
    with pytest.raises(ColonyOIDCConfigError):
        ColonyOIDCClient(CLIENT_ID, discovery=DISCOVERY)            # default basic, no secret


def test_unknown_auth_method_rejected():
    with pytest.raises(ColonyOIDCConfigError):
        ColonyOIDCClient(CLIENT_ID, "s", discovery=DISCOVERY,
                         token_endpoint_auth_method="tls_client_auth")


# ---- Pushed Authorization Requests (RFC 9126) ----

DISCOVERY_PAR = {**DISCOVERY, "pushed_authorization_request_endpoint": f"{ISSUER}/oauth/par"}


class ParSession(FakeSession):
    """FakeSession that also answers ``POST /oauth/par`` with a request_uri."""
    def __init__(self, key, *, request_uri="urn:ietf:params:oauth:request_uri:xyz",
                 par_status=201, **kw):
        super().__init__(key, **kw)
        self.request_uri = request_uri
        self.par_status = par_status
        self.par_post = None

    def post(self, url, data=None, auth=None, **kw):
        if url.endswith("/oauth/par"):
            self.par_post = {"url": url, "data": data, "auth": auth}
            self.last_post = self.par_post
            body = {"expires_in": 60}
            if self.request_uri:
                body["request_uri"] = self.request_uri
            return FakeResp(body, self.par_status)
        return super().post(url, data=data, auth=auth, **kw)


def test_create_login_with_par_pushes_params_and_shortens_browser_url(keypair):
    s = ParSession(keypair)
    c = ColonyOIDCClient(CLIENT_ID, "secret", REDIRECT, discovery=DISCOVERY_PAR, session=s)
    login = c.create_login(use_par=True, scope="openid profile")
    q = parse_qs(urlparse(login.authorization_url).query)
    # the browser only sees client_id + the one-time request_uri
    assert q["client_id"] == [CLIENT_ID]
    assert q["request_uri"] == [s.request_uri]
    assert "code_challenge" not in q and "redirect_uri" not in q
    # the real parameters went to the PAR endpoint, with client auth
    assert s.par_post["url"].endswith("/oauth/par")
    assert s.par_post["data"]["code_challenge_method"] == "S256"
    assert s.par_post["data"]["redirect_uri"] == REDIRECT
    assert s.par_post["auth"] == (CLIENT_ID, "secret")             # client_secret_basic
    assert login.code_verifier                                     # still returned for the exchange


def test_par_uses_private_key_jwt_when_configured(keypair):
    s = ParSession(keypair)
    c = ColonyOIDCClient(CLIENT_ID, discovery=DISCOVERY_PAR, session=s,
                         redirect_uri=REDIRECT, use_par=True,
                         token_endpoint_auth_method="private_key_jwt", private_key=keypair)
    c.create_login(scope="openid")                                 # use_par defaults from client
    assert s.par_post["auth"] is None
    assert "client_assertion" in s.par_post["data"]


def test_par_missing_request_uri_raises(keypair):
    s = ParSession(keypair, request_uri="")
    c = ColonyOIDCClient(CLIENT_ID, "secret", REDIRECT, discovery=DISCOVERY_PAR, session=s)
    with pytest.raises(ColonyOIDCError):
        c.create_login(use_par=True)


def test_no_par_when_not_requested(keypair):
    s = ParSession(keypair)
    c = ColonyOIDCClient(CLIENT_ID, "secret", REDIRECT, discovery=DISCOVERY_PAR, session=s)
    login = c.create_login()                                       # use_par defaults False
    q = parse_qs(urlparse(login.authorization_url).query)
    assert "code_challenge" in q and "request_uri" not in q
    assert s.par_post is None                                      # PAR endpoint untouched


# ---- DPoP — sender-constrained tokens (RFC 9449) ----

class DpopSession(FakeSession):
    """FakeSession that captures the request headers (where DPoP proofs ride)."""
    def __init__(self, key, **kw):
        super().__init__(key, **kw)
        self.token_headers = None
        self.userinfo_headers = None

    def post(self, url, data=None, auth=None, **kw):
        if url.endswith("/oauth/token"):
            self.token_headers = kw.get("headers") or {}
        return super().post(url, data=data, auth=auth, **kw)

    def get(self, url, **kw):
        if url.endswith("/userinfo"):
            self.userinfo_headers = kw.get("headers") or {}
        return super().get(url, **kw)


def _decode_dpop(proof, client, alg="ES256"):
    return jwt.decode(proof, client._dpop_key.public_key(), algorithms=[alg],
                      options={"verify_aud": False})


def test_dpop_token_request_carries_a_proof(keypair):
    s = DpopSession(keypair)
    c = ColonyOIDCClient(CLIENT_ID, "secret", discovery=DISCOVERY, session=s, dpop=True)
    c.fetch_token("authcode", "verifier123")
    proof = s.token_headers["DPoP"]
    hdr = jwt.get_unverified_header(proof)
    assert hdr["typ"] == "dpop+jwt" and hdr["alg"] == "ES256"
    assert hdr["jwk"]["kty"] == "EC"
    assert not any(p in hdr["jwk"] for p in ("d", "p", "q"))        # public key only
    claims = _decode_dpop(proof, c)                                 # verifies signature
    assert claims["htm"] == "POST" and claims["htu"] == TOKEN_ENDPOINT
    assert "ath" not in claims and claims["jti"]                    # no ath at the token endpoint


def test_dpop_userinfo_uses_dpop_scheme_with_ath(keypair):
    s = DpopSession(keypair)
    c = ColonyOIDCClient(CLIENT_ID, "secret", discovery=DISCOVERY, session=s, dpop=True)
    c.fetch_userinfo("at_abc")
    assert s.userinfo_headers["Authorization"] == "DPoP at_abc"     # not Bearer
    claims = _decode_dpop(s.userinfo_headers["DPoP"], c)
    assert claims["htm"] == "GET" and claims["htu"].endswith("/userinfo")
    assert claims["ath"] == _b64url(hashlib.sha256(b"at_abc").digest())


def test_dpop_disabled_is_plain_bearer(keypair):
    s = DpopSession(keypair)
    c = ColonyOIDCClient(CLIENT_ID, "secret", discovery=DISCOVERY, session=s)  # no dpop
    c.fetch_token("c", "v")
    c.fetch_userinfo("at_abc")
    assert "DPoP" not in (s.token_headers or {})
    assert s.userinfo_headers["Authorization"] == "Bearer at_abc"
    assert "DPoP" not in s.userinfo_headers


def test_dpop_jti_is_unique_per_request(keypair):
    s = DpopSession(keypair)
    c = ColonyOIDCClient(CLIENT_ID, "secret", discovery=DISCOVERY, session=s, dpop=True)
    c.fetch_token("c", "v")
    j1 = _decode_dpop(s.token_headers["DPoP"], c)["jti"]
    c.fetch_token("c", "v")
    j2 = _decode_dpop(s.token_headers["DPoP"], c)["jti"]
    assert j1 != j2


def test_dpop_rsa_alg(keypair):
    s = DpopSession(keypair)
    c = ColonyOIDCClient(CLIENT_ID, "secret", discovery=DISCOVERY, session=s,
                         dpop=True, dpop_alg="RS256")
    c.fetch_token("c", "v")
    hdr = jwt.get_unverified_header(s.token_headers["DPoP"])
    assert hdr["alg"] == "RS256" and hdr["jwk"]["kty"] == "RSA"
    _decode_dpop(s.token_headers["DPoP"], c, alg="RS256")           # verifies signature


def test_dpop_supplied_key_is_used(keypair):
    from cryptography.hazmat.primitives.asymmetric import ec
    k = ec.generate_private_key(ec.SECP256R1())
    s = DpopSession(keypair)
    c = ColonyOIDCClient(CLIENT_ID, "secret", discovery=DISCOVERY, session=s, dpop_key=k)
    assert c.dpop_enabled and c._dpop_key is k
    c.fetch_token("c", "v")
    jwt.decode(s.token_headers["DPoP"], k.public_key(), algorithms=["ES256"],
               options={"verify_aud": False})                       # verifies against the supplied key


def test_dpop_rejects_symmetric_alg():
    with pytest.raises(ColonyOIDCConfigError):
        ColonyOIDCClient(CLIENT_ID, "secret", discovery=DISCOVERY, dpop=True, dpop_alg="HS256")


def test_dpop_composes_with_private_key_jwt(keypair):
    s = DpopSession(keypair)
    c = ColonyOIDCClient(CLIENT_ID, discovery=DISCOVERY, session=s,
                         token_endpoint_auth_method="private_key_jwt",
                         private_key=keypair, dpop=True)
    c.fetch_token("c", "v")
    assert "DPoP" in s.token_headers                                # sender-constraint proof
    assert "client_assertion" in s.last_post["data"]               # AND private_key_jwt auth
    assert s.last_post["auth"] is None
