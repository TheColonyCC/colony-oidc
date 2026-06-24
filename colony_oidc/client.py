"""colony-oidc — "Login with the Colony" for Python.

A small, framework-agnostic OpenID Connect **client** for thecolony.cc — the Python
counterpart of the PHP ``thecolony/oauth2-colony`` provider. Authorization Code + PKCE
(S256), id_token verified RS256 against the published JWKS (with key-rotation retry),
issuer/audience/expiry/nonce checks.

Standard library + ``requests`` + ``pyjwt[crypto]``. Bring your own framework: the
``examples/`` directory shows Flask, but the client has no web-framework dependency.

    client = ColonyOIDCClient(client_id="...", client_secret="...",
                              redirect_uri="https://app.example/auth/colony/callback")
    login = client.create_login()            # -> stash login.state/nonce/code_verifier in session
    # redirect the user to login.authorization_url ...
    # on the callback (?code=...&state=...):
    token, user = client.complete_login(
        code=request.args["code"],
        returned_state=request.args["state"],
        state=session["state"], nonce=session["nonce"],
        code_verifier=session["code_verifier"])
    # user.sub is your stable account key
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from typing import Any, Mapping
from urllib.parse import urlencode

import jwt
import requests
from jwt.algorithms import RSAAlgorithm

from .exceptions import (
    ColonyOIDCConfigError,
    ColonyOIDCConsentRequired,
    ColonyOIDCError,
    ColonyOIDCLoginRequired,
    ColonyOIDCStateError,
    ColonyOIDCTokenError,
    ColonyOIDCVerificationError,
)
from .models import ColonyUser, LoginRequest

DEFAULT_ISSUER = "https://thecolony.cc"
DEFAULT_SCOPE = "openid profile email"

# Client authentication methods we support at the token / PAR endpoints.
TOKEN_AUTH_METHODS = ("client_secret_basic", "client_secret_post", "private_key_jwt")

# private_key_jwt (RFC 7523 / RFC 7521 §4.2). The Colony accepts the same
# asymmetric algorithm set the IdP advertises in discovery's
# ``token_endpoint_auth_signing_alg_values_supported``.
_CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
_CLIENT_ASSERTION_ALGS = (
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512",
)
# Each assertion is single-use (fresh jti) and short-lived; the IdP caps the
# accepted lifetime at 5 min, so stay well under it.
_ASSERTION_LIFETIME = 60
# RFC 8693 OAuth 2.0 Token Exchange — the agent-native login path.
_GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
_TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"

# DPoP (RFC 9449) — sender-constrained tokens. ES256 first: an EC P-256 proof
# key is the compact, conventional default for DPoP.
DPOP_ALGS = (
    "ES256", "ES384", "ES512",
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_pkce() -> tuple[str, str]:
    """Returns (code_verifier, code_challenge) for PKCE S256."""
    verifier = _b64url(secrets.token_bytes(32))           # 43-char high-entropy verifier
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


class ColonyOIDCClient:
    def __init__(
        self,
        client_id: str,
        client_secret: str | None = None,
        redirect_uri: str | None = None,
        *,
        issuer: str = DEFAULT_ISSUER,
        scope: str = DEFAULT_SCOPE,
        session: requests.Session | None = None,
        discovery: dict[str, Any] | None = None,
        leeway: int = 30,
        timeout: float = 15.0,
        token_endpoint_auth_method: str = "client_secret_basic",
        private_key: Any = None,
        private_key_id: str | None = None,
        signing_alg: str = "RS256",
        use_par: bool = False,
        dpop: bool = False,
        dpop_key: Any = None,
        dpop_alg: str = "ES256",
        accept_subject: str = "any",
    ) -> None:
        if not client_id:
            raise ColonyOIDCConfigError("client_id is required")
        if token_endpoint_auth_method not in TOKEN_AUTH_METHODS:
            raise ColonyOIDCConfigError(
                "token_endpoint_auth_method must be one of " + ", ".join(TOKEN_AUTH_METHODS))
        if token_endpoint_auth_method == "private_key_jwt":
            # Asymmetric client auth: a signing key replaces the shared secret.
            if not private_key:
                raise ColonyOIDCConfigError(
                    "private_key is required for token_endpoint_auth_method='private_key_jwt'")
            if signing_alg not in _CLIENT_ASSERTION_ALGS:
                raise ColonyOIDCConfigError(
                    "signing_alg must be one of " + ", ".join(_CLIENT_ASSERTION_ALGS))
        elif not client_secret:
            raise ColonyOIDCConfigError(
                f"client_secret is required for token_endpoint_auth_method={token_endpoint_auth_method!r}")
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.issuer = issuer.rstrip("/")
        self.scope = scope
        self.leeway = leeway
        self.timeout = timeout
        self.token_endpoint_auth_method = token_endpoint_auth_method
        self.private_key = private_key
        self.private_key_id = private_key_id
        self.signing_alg = signing_alg
        self.use_par = use_par
        self._init_dpop(dpop, dpop_key, dpop_alg)
        if accept_subject not in ("any", "human", "agent"):
            raise ColonyOIDCConfigError(
                "accept_subject must be 'any', 'human', or 'agent'")
        self.accept_subject = accept_subject
        self._http = session or requests.Session()
        self._discovery = discovery
        self._jwks_cache: dict[str, Any] | None = None

    # ---- discovery ----

    @property
    def discovery(self) -> dict[str, Any]:
        if self._discovery is None:
            url = f"{self.issuer}/.well-known/openid-configuration"
            try:
                r = self._http.get(url, timeout=self.timeout)
                r.raise_for_status()
                self._discovery = r.json()
            except requests.RequestException as e:
                raise ColonyOIDCConfigError(f"could not fetch discovery from {url}: {e}") from e
            if self._discovery.get("issuer", self.issuer).rstrip("/") != self.issuer:
                raise ColonyOIDCConfigError(
                    f"discovery issuer {self._discovery.get('issuer')!r} != {self.issuer!r}")
        return self._discovery

    def _endpoint(self, key: str) -> str:
        url = self.discovery.get(key)
        if not url:
            raise ColonyOIDCConfigError(f"discovery is missing {key}")
        return url

    # ---- step 1: build the authorization URL ----

    def create_login(
        self,
        *,
        redirect_uri: str | None = None,
        scope: str | None = None,
        state: str | None = None,
        nonce: str | None = None,
        code_verifier: str | None = None,
        prompt: str | None = None,
        use_par: bool | None = None,
        **extra: str,
    ) -> LoginRequest:
        redirect = redirect_uri or self.redirect_uri
        if not redirect:
            raise ColonyOIDCConfigError("redirect_uri must be set on the client or passed in")
        state = state or secrets.token_urlsafe(24)
        nonce = nonce or secrets.token_urlsafe(24)
        verifier = code_verifier or generate_pkce()[0]
        challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": redirect,
            "scope": scope or self.scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        if prompt:
            params["prompt"] = prompt
        params.update(extra)
        authorization_endpoint = self._endpoint("authorization_endpoint")
        if self.use_par if use_par is None else use_par:
            # RFC 9126: push the parameters server-side, then send the browser to the
            # authorization endpoint with just client_id + the issued one-time request_uri.
            request_uri = self._pushed_authorization_request(params)
            query = urlencode({"client_id": self.client_id, "request_uri": request_uri})
        else:
            query = urlencode(params)
        url = f"{authorization_endpoint}?{query}"
        return LoginRequest(authorization_url=url, state=state, nonce=nonce,
                            code_verifier=verifier, redirect_uri=redirect)

    def _pushed_authorization_request(self, params: Mapping[str, str]) -> str:
        """Push the authorization ``params`` to the PAR endpoint (RFC 9126) and return the
        issued one-time ``request_uri``.

        Authenticates with the same client credential as the token endpoint
        (:meth:`_client_auth`), so ``private_key_jwt`` and ``client_secret_*`` clients both
        work. Reads ``pushed_authorization_request_endpoint`` from discovery; raises
        :class:`ColonyOIDCConfigError` if the IdP doesn't advertise PAR, and
        :class:`ColonyOIDCError` on a transport or protocol failure."""
        endpoint = self._endpoint("pushed_authorization_request_endpoint")
        data = dict(params)
        auth = self._client_auth(data)
        try:
            r = self._http.post(endpoint, data=data, auth=auth,
                                 headers={"Accept": "application/json"}, timeout=self.timeout)
        except requests.RequestException as e:
            raise ColonyOIDCError(f"PAR request failed: {e}") from e
        if r.status_code not in (200, 201):
            raise ColonyOIDCError(f"PAR endpoint returned {r.status_code}: {r.text[:300]}")
        try:
            body = r.json()
        except ValueError as e:
            raise ColonyOIDCError("PAR endpoint did not return JSON") from e
        request_uri = body.get("request_uri")
        if not request_uri:
            raise ColonyOIDCError("PAR response missing request_uri")
        return str(request_uri)

    def create_silent_login(self, **kwargs: Any) -> LoginRequest:
        """Build a **silent SSO** login request (``prompt=none``).

        Convenience wrapper over :meth:`create_login` that forces ``prompt="none"``: the
        IdP will not show any UI. Use it (typically in a hidden iframe) to re-authenticate
        a user who already has a Colony session without an interactive redirect. The
        callback yields one of three outcomes — ``?code=...`` on success, or
        ``?error=login_required`` / ``?error=consent_required`` on failure — which
        :meth:`raise_for_callback_error` turns into typed exceptions.

        Accepts the same keyword arguments as :meth:`create_login` (any ``prompt`` you pass
        is overridden to ``"none"``)."""
        kwargs["prompt"] = "none"
        return self.create_login(**kwargs)

    def raise_for_callback_error(self, params: Mapping[str, str]) -> None:
        """Inspect the callback query params and raise on any OAuth ``error``.

        Call this **first** on the callback, before :meth:`complete_login`. When the IdP
        returns an ``error`` parameter — chiefly the silent-SSO (``prompt=none``) outcomes
        ``login_required`` and ``consent_required`` — this raises the matching typed
        exception (:class:`ColonyOIDCLoginRequired` / :class:`ColonyOIDCConsentRequired`),
        or a generic :class:`ColonyOIDCError` for any other ``error`` value. Returns
        cleanly (``None``) when there is no ``error`` — proceed to :meth:`complete_login`."""
        error = params.get("error")
        if not error:
            return
        description = params.get("error_description") or ""
        detail = f"{error}: {description}" if description else error
        if error == "login_required":
            raise ColonyOIDCLoginRequired(detail)
        if error == "consent_required":
            raise ColonyOIDCConsentRequired(detail)
        raise ColonyOIDCError(f"authorization error: {detail}")

    # ---- step 2: exchange the code for tokens ----

    def fetch_token(
        self,
        code: str,
        code_verifier: str,
        *,
        redirect_uri: str | None = None,
        returned_state: str | None = None,
        state: str | None = None,
    ) -> dict[str, Any]:
        if state is not None and returned_state is not None and not secrets.compare_digest(
                str(state), str(returned_state)):
            raise ColonyOIDCStateError("OAuth state mismatch (possible CSRF)")
        redirect = redirect_uri or self.redirect_uri
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect,
            "code_verifier": code_verifier,
        }
        return self._token_request(data)

    def _client_auth(self, data: dict[str, Any]) -> tuple[str, str] | None:
        """Apply the configured client authentication to an outgoing token/PAR request.

        Mutates ``data`` in place — adding the ``private_key_jwt`` assertion or the
        POST-body ``client_id``/``client_secret`` — and returns the HTTP Basic-auth
        tuple for ``requests`` (or ``None`` when the credential travels in the body).
        Shared by :meth:`fetch_token`, :meth:`refresh_token` and
        :meth:`_pushed_authorization_request` so all three authenticate identically."""
        if self.token_endpoint_auth_method == "private_key_jwt":
            data["client_assertion_type"] = _CLIENT_ASSERTION_TYPE
            data["client_assertion"] = self._build_client_assertion()
            return None
        if self.token_endpoint_auth_method == "client_secret_post":
            data["client_id"] = self.client_id
            data["client_secret"] = self.client_secret or ""
            return None
        return (self.client_id, self.client_secret or "")  # client_secret_basic

    def _build_client_assertion(self) -> str:
        """Build a signed ``private_key_jwt`` client-authentication assertion (RFC 7523).

        ``iss`` and ``sub`` are the client_id; ``aud`` is the token endpoint (the Colony
        accepts that or the issuer); a fresh ``jti`` plus a short ``exp`` make it
        single-use and replay-bounded. Signed with the configured ``private_key`` and
        ``signing_alg`` (an RS/PS/ES 256/384/512 key). The same assertion authenticates
        the token, refresh and PAR requests."""
        now = int(time.time())
        claims = {
            "iss": self.client_id,
            "sub": self.client_id,
            "aud": self._endpoint("token_endpoint"),
            "jti": secrets.token_urlsafe(32),
            "iat": now,
            "exp": now + _ASSERTION_LIFETIME,
        }
        headers = {"kid": self.private_key_id} if self.private_key_id else None
        return jwt.encode(claims, self.private_key, algorithm=self.signing_alg, headers=headers)

    # ---- DPoP (RFC 9449): sender-constrained tokens ----

    def _init_dpop(self, dpop: bool, dpop_key: Any, dpop_alg: str) -> None:
        """Set up the DPoP proof key, if enabled. When ``dpop`` is true (or a
        ``dpop_key`` is supplied) the client binds its tokens to a held key:
        every token/refresh request carries a DPoP proof, and access tokens are
        presented at the resource with the ``DPoP`` scheme. A fresh EC P-256 key
        is generated when none is provided."""
        self.dpop_enabled = bool(dpop or dpop_key is not None)
        self._dpop_key: Any = None
        self._dpop_alg = dpop_alg
        self._dpop_jwk: dict[str, Any] | None = None
        if not self.dpop_enabled:
            return
        if dpop_alg not in DPOP_ALGS:
            raise ColonyOIDCConfigError("dpop_alg must be one of " + ", ".join(DPOP_ALGS))
        key = dpop_key
        if isinstance(key, (str, bytes)):
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            key = load_pem_private_key(key.encode() if isinstance(key, str) else key, password=None)
        if key is None:
            key = self._generate_dpop_key(dpop_alg)
        self._dpop_key = key
        from jwt.algorithms import ECAlgorithm, RSAAlgorithm
        algcls = ECAlgorithm if dpop_alg.startswith("ES") else RSAAlgorithm
        # The proof embeds ONLY the public JWK (the IdP rejects private params).
        self._dpop_jwk = algcls.to_jwk(self._dpop_key.public_key(), as_dict=True)

    @staticmethod
    def _generate_dpop_key(alg: str) -> Any:
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        if alg.startswith("ES"):
            curve: ec.EllipticCurve
            if alg == "ES256":
                curve = ec.SECP256R1()
            elif alg == "ES384":
                curve = ec.SECP384R1()
            else:
                curve = ec.SECP521R1()
            return ec.generate_private_key(curve)
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def _dpop_proof(self, htm: str, htu: str, *, access_token: str | None = None) -> str:
        """Build a DPoP proof JWT (RFC 9449) for an ``htm`` request to ``htu``.

        Carries a fresh ``jti`` + ``iat`` and embeds the public proof key in the
        ``jwk`` header. At a protected resource pass ``access_token`` so the
        proof includes ``ath`` = base64url(sha256(token))."""
        claims: dict[str, Any] = {
            "jti": secrets.token_urlsafe(32), "htm": htm, "htu": htu,
            "iat": int(time.time()),
        }
        if access_token is not None:
            claims["ath"] = _b64url(hashlib.sha256(access_token.encode()).digest())
        return jwt.encode(claims, self._dpop_key, algorithm=self._dpop_alg,
                          headers={"typ": "dpop+jwt", "jwk": self._dpop_jwk})

    def _token_request(self, data: dict[str, Any]) -> dict[str, Any]:
        """POST the token endpoint with the configured client auth, mapping any failure to
        :class:`ColonyOIDCTokenError`. Shared by :meth:`fetch_token` and
        :meth:`refresh_token` so both speak identical client authentication (secret or
        ``private_key_jwt``) and error handling. When DPoP is enabled a proof is
        attached so the issued tokens are sender-constrained to the proof key."""
        auth = self._client_auth(data)
        headers = {"Accept": "application/json"}
        token_endpoint = self._endpoint("token_endpoint")
        if self.dpop_enabled:
            headers["DPoP"] = self._dpop_proof("POST", token_endpoint)
        try:
            r = self._http.post(token_endpoint, data=data, auth=auth,
                                 headers=headers, timeout=self.timeout)
        except requests.RequestException as e:
            raise ColonyOIDCTokenError(f"token request failed: {e}") from e
        if r.status_code != 200:
            raise ColonyOIDCTokenError(f"token endpoint returned {r.status_code}: {r.text[:300]}")
        try:
            token = r.json()
        except ValueError as e:
            raise ColonyOIDCTokenError("token endpoint did not return JSON") from e
        if "error" in token:
            raise ColonyOIDCTokenError(
                f"token error: {token.get('error')}: {token.get('error_description')}")
        if "access_token" not in token:
            raise ColonyOIDCTokenError("token response missing access_token")
        return token

    def refresh_token(self, refresh_token: str, *, scope: str | None = None) -> dict[str, Any]:
        """Exchange a ``refresh_token`` for a fresh token set (``grant_type=refresh_token``).

        Request a ``refresh_token`` in the first place by including ``offline_access`` in your
        login ``scope``. The Colony **rotates** refresh tokens on every use: the returned dict
        carries a new ``refresh_token`` you must persist; the one you passed in is now spent
        (replaying it is rejected). Pass ``scope`` to request a narrowed set of scopes.

        Uses the same client-auth + error mapping as :meth:`fetch_token`; failures raise
        :class:`ColonyOIDCTokenError`."""
        data: dict[str, Any] = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        if scope:
            data["scope"] = scope
        return self._token_request(data)

    def exchange_token(
        self,
        subject_token: str,
        *,
        audience: str | None = None,
        scope: str = "openid profile",
        subject_token_type: str = _TOKEN_TYPE_ACCESS_TOKEN,
        **extra: str,
    ) -> dict[str, Any]:
        """Trade a ``subject_token`` for a fresh, audience-scoped token set via
        OAuth 2.0 Token Exchange (RFC 8693) — the **agent-native** login path.

        An agent has no browser session, so instead of the redirect/consent flow it
        exchanges its Colony API JWT (the ``subject_token``) for an ``id_token`` in a
        single request: no redirect, authorization code or nonce. The returned dict
        carries an ``id_token`` you verify with :meth:`verify_id_token` — call it with
        ``nonce=None``, as exchanged tokens carry no nonce (and have no
        redirect/replay vector). ``audience`` defaults to this client's id.

        Uses the same client authentication (secret or ``private_key_jwt``), DPoP and
        error mapping as :meth:`fetch_token`; failures raise
        :class:`ColonyOIDCTokenError`."""
        data: dict[str, Any] = {
            "grant_type": _GRANT_TOKEN_EXCHANGE,
            "subject_token": subject_token,
            "subject_token_type": subject_token_type,
            "audience": audience or self.client_id,
            "scope": scope,
        }
        data.update(extra)
        return self._token_request(data)

    # ---- step 3: verify the id_token ----

    def _jwks(self, *, force: bool = False) -> dict[str, Any]:
        if self._jwks_cache is None or force:
            url = self._endpoint("jwks_uri")
            try:
                r = self._http.get(url, timeout=self.timeout)
                r.raise_for_status()
                self._jwks_cache = r.json()
            except requests.RequestException as e:
                raise ColonyOIDCVerificationError(f"could not fetch JWKS from {url}: {e}") from e
        assert self._jwks_cache is not None
        return self._jwks_cache

    def _signing_key(self, kid: str | None):
        def find(jwks):
            keys = jwks.get("keys", [])
            if kid is None:
                return keys[0] if len(keys) == 1 else None
            for k in keys:
                if k.get("kid") == kid:
                    return k
            return None
        jwk = find(self._jwks())
        if jwk is None:                       # key rotation: refetch once, then give up
            jwk = find(self._jwks(force=True))
        if jwk is None:
            raise ColonyOIDCVerificationError(f"no JWKS key matches id_token kid={kid!r}")
        return RSAAlgorithm.from_jwk(json.dumps(jwk))

    def verify_id_token(self, id_token: str, *, nonce: str | None = None) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as e:
            raise ColonyOIDCVerificationError(f"malformed id_token: {e}") from e
        key = self._signing_key(header.get("kid"))
        try:
            claims = jwt.decode(
                id_token, key, algorithms=["RS256"], audience=self.client_id,
                issuer=self.issuer, leeway=self.leeway,
                options={"require": ["exp", "iat", "aud", "iss", "sub"]},
            )
        except jwt.PyJWTError as e:
            raise ColonyOIDCVerificationError(f"id_token verification failed: {e}") from e
        if nonce is not None and claims.get("nonce") != nonce:
            raise ColonyOIDCVerificationError("id_token nonce mismatch (possible replay)")
        return claims

    # ---- back-channel logout ----

    BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"

    def validate_logout_token(self, logout_token: str) -> dict[str, Any]:
        """Validate a back-channel ``logout_token`` (OIDC Back-Channel Logout 1.0 §2.4/§2.6).

        Call this from your registered back-channel logout endpoint with the
        ``logout_token`` form field the Colony POSTs there. Returns the validated claims
        (always carrying ``sub`` and/or ``sid``) so you can terminate that subject's /
        session's local session; raises :class:`ColonyOIDCVerificationError` on **any**
        validation failure.

        Verified, per spec:

        - RS256 signature against the live JWKS (same kid-selection + single rotation
          refetch as :meth:`verify_id_token`); ``alg: none`` / non-RS256 is rejected.
        - ``iss`` == issuer, ``aud`` == this client_id, and ``iat`` is **required**
          (``exp`` is validated when present).
        - an ``events`` claim that is a JSON object containing the
          ``http://schemas.openid.net/event/backchannel-logout`` member.
        - **at least one** of ``sub`` / ``sid`` (a logout token with neither is invalid).
        - **no** ``nonce`` claim (its presence proves the token is an id_token, not a
          logout token)."""
        try:
            header = jwt.get_unverified_header(logout_token)
        except jwt.PyJWTError as e:
            raise ColonyOIDCVerificationError(f"malformed logout_token: {e}") from e
        alg = header.get("alg")
        if alg != "RS256":
            raise ColonyOIDCVerificationError(
                f"logout_token alg must be RS256, got {alg!r}")
        key = self._signing_key(header.get("kid"))
        try:
            claims = jwt.decode(
                logout_token, key, algorithms=["RS256"], audience=self.client_id,
                issuer=self.issuer, leeway=self.leeway,
                options={"require": ["iat", "aud", "iss"]},
            )
        except jwt.PyJWTError as e:
            raise ColonyOIDCVerificationError(
                f"logout_token verification failed: {e}") from e
        # §2.4: a logout token MUST NOT contain a nonce (that would be an id_token).
        if "nonce" in claims:
            raise ColonyOIDCVerificationError(
                "logout_token must not contain a 'nonce' claim")
        # §2.4: MUST have a sub and/or sid identifying the subject/session to log out.
        if claims.get("sub") is None and claims.get("sid") is None:
            raise ColonyOIDCVerificationError(
                "logout_token must contain a 'sub' and/or 'sid' claim")
        # §2.4: the events claim asserts this is a back-channel logout event.
        events = claims.get("events")
        if not isinstance(events, dict):
            raise ColonyOIDCVerificationError(
                "logout_token must contain an 'events' object")
        if self.BACKCHANNEL_LOGOUT_EVENT not in events:
            raise ColonyOIDCVerificationError(
                "logout_token 'events' is missing the back-channel-logout event member")
        return claims

    # ---- userinfo (optional) ----

    def fetch_userinfo(self, access_token: str) -> dict[str, Any]:
        """Fetch the UserInfo claims for ``access_token``.

        When DPoP is enabled the token is a sender-constrained one, so it is
        presented with the ``DPoP`` auth scheme (RFC 9449 §7.1) plus a proof
        carrying ``ath`` bound to this token; otherwise it is a plain Bearer."""
        userinfo_endpoint = self._endpoint("userinfo_endpoint")
        if self.dpop_enabled:
            headers = {"Authorization": f"DPoP {access_token}",
                       "DPoP": self._dpop_proof("GET", userinfo_endpoint, access_token=access_token),
                       "Accept": "application/json"}
        else:
            headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
        try:
            r = self._http.get(userinfo_endpoint, headers=headers, timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        except requests.RequestException as e:
            raise ColonyOIDCTokenError(f"userinfo request failed: {e}") from e

    # ---- RP-initiated logout ----

    def end_session_url(
        self,
        *,
        id_token_hint: str | None = None,
        post_logout_redirect_uri: str | None = None,
        state: str | None = None,
    ) -> str:
        """Build the RP-initiated logout URL (no HTTP performed).

        Redirect the user's browser here to end their Colony SSO session. Reads
        ``end_session_endpoint`` from discovery. The returned URL always carries
        ``client_id``; ``id_token_hint``, ``post_logout_redirect_uri`` and ``state`` are
        included only when supplied.

        ``post_logout_redirect_uri`` must be **pre-registered** with the Colony for this
        client. If it isn't (or none is given), the Colony shows an on-site
        "you've been logged out" notice rather than bouncing the user back."""
        params = {"client_id": self.client_id}
        if id_token_hint:
            params["id_token_hint"] = id_token_hint
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
        if state:
            params["state"] = state
        return f"{self._endpoint('end_session_endpoint')}?{urlencode(params)}"

    # ---- one-shot convenience ----

    def complete_login(
        self,
        *,
        code: str,
        code_verifier: str,
        nonce: str,
        state: str | None = None,
        returned_state: str | None = None,
        redirect_uri: str | None = None,
        fetch_userinfo: bool = False,
    ) -> tuple[dict[str, Any], ColonyUser]:
        """Exchange the code, verify the id_token, and return (token, ColonyUser).

        Pass the ``state``/``nonce``/``code_verifier`` you stashed at :meth:`create_login`
        plus the ``code`` and ``returned_state`` from the callback query string."""
        token = self.fetch_token(code, code_verifier, redirect_uri=redirect_uri,
                                 returned_state=returned_state, state=state)
        id_token = token.get("id_token")
        if not id_token:
            raise ColonyOIDCTokenError("token response had no id_token (is 'openid' in scope?)")
        claims = self.verify_id_token(id_token, nonce=nonce)
        if fetch_userinfo:
            claims = {**claims, **self.fetch_userinfo(token["access_token"])}
        # Under granular consent the user may grant fewer scopes than requested; the token
        # response's `scope` is the authoritative granted set. Surface it on the user.
        granted_scopes = [s for s in str(token.get("scope", "")).split() if s]
        user = ColonyUser.from_claims(claims, granted_scopes=granted_scopes)
        self._enforce_accept_subject(user)
        return token, user

    def _enforce_accept_subject(self, user: ColonyUser) -> None:
        """RP-side defense-in-depth for the configured ``accept_subject`` restriction.

        This complements — it does not replace — the IdP's own per-client audience-policy
        enforcement (humans only / agents only / both). When ``accept_subject`` is
        restrictive we re-check the verified ``colony_verified_human`` claim here too, so a
        misconfigured client never silently accepts the wrong subject type."""
        if self.accept_subject == "any":
            return
        if user.verified_human is None:
            raise ColonyOIDCConfigError(
                "accept_subject is restricted to "
                f"{self.accept_subject!r} but the id_token has no 'colony_verified_human' "
                "claim — request the 'profile' scope so the subject type can be enforced")
        if self.accept_subject == "human" and not user.is_human:
            raise ColonyOIDCVerificationError(
                "this client accepts human subjects only, but an agent authenticated")
        if self.accept_subject == "agent" and not user.is_agent:
            raise ColonyOIDCVerificationError(
                "this client accepts agent subjects only, but a human authenticated")
