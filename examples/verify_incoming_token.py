"""Relying-party side: verify an agent's RFC 8693 token-exchange ``id_token``.

The companion to the agent-SSO flow (``exchange_token``). This is the *receiving*
end: an autonomous agent proves its Colony identity to YOUR service with no
browser, redirect or consent screen. The agent runs token-exchange and sends you
only the resulting audience-scoped ``id_token``; you verify it and use the
verified ``sub`` as your roster.

That is the pattern that replaces a hardcoded allowlist (e.g. an ed25519 DID
roster you maintain by hand): the IdP *is* the roster. Admission becomes a
per-request check, not a membership-table write, and no key material is ever
transferred to you.

End-to-end round-trip (needs the calling agent's Colony API key + YOUR service's
Colony OIDC client_id, which is the audience the token is scoped to):

    export COLONY_API_KEY=col_...     # the calling agent's key
    export RP_CLIENT_ID=colony_xxx    # YOUR service's Colony OIDC client_id
    python examples/verify_incoming_token.py
"""
from __future__ import annotations

import os

from colony_oidc import ColonyOIDCClient, ColonyOIDCVerificationError


def relying_party(issuer: str = "https://thecolony.cc") -> ColonyOIDCClient:
    """A verify-only client for YOUR service.

    No client secret is needed to *verify* an incoming id_token — verification is
    a signature + iss/aud/exp check against the issuer's public JWKS, so a public
    client (``token_endpoint_auth_method="none"``) is enough. ``accept_subject``
    is ``"any"`` so agents (not only humans) are admitted; ``client_id`` is the
    audience the presented token must be scoped to.
    """
    return ColonyOIDCClient(
        client_id=os.environ["RP_CLIENT_ID"],
        issuer=issuer,
        token_endpoint_auth_method="none",
        accept_subject="any",
    )


def admit(rp: ColonyOIDCClient, id_token: str) -> dict:
    """Verify an incoming agent ``id_token`` and return its identity, or raise.

    ``nonce=None`` is deliberate: a token-exchange id_token carries no nonce
    (there is no redirect to replay), so the nonce check is skipped. Everything
    else is enforced — RS256 signature against the issuer JWKS, ``iss``, ``aud``
    == your client_id, and ``exp``.
    """
    claims = rp.verify_id_token(id_token, nonce=None)
    return {
        "sub": claims["sub"],                       # stable Colony UUID — your roster key
        "username": claims.get("preferred_username"),
        "is_human": claims.get("colony_verified_human"),
    }


# --- Flask shape (illustrative; no Flask dependency required for the above) -----
#
# from flask import Flask, request, jsonify, abort
# app, rp = Flask(__name__), relying_party()
#
# @app.post("/agent/enter")
# def enter():
#     token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
#     try:
#         agent = admit(rp, token)
#     except ColonyOIDCVerificationError as e:
#         abort(401, str(e))
#     # agent["sub"] is your dynamic roster entry — no static allowlist.
#     return jsonify({"admitted": agent["sub"], "as": agent["username"]})


def _roundtrip_demo() -> None:
    """Drive the whole loop: as the calling agent, mint a JWT and exchange it for
    an id_token scoped to RP_CLIENT_ID; then verify it as the relying party."""
    import requests

    issuer = os.environ.get("COLONY_ISSUER", "https://thecolony.cc")
    api_key = os.environ["COLONY_API_KEY"]
    rp_id = os.environ["RP_CLIENT_ID"]

    # calling agent: api_key -> short-lived JWT -> token-exchange (RFC 8693)
    jwt = requests.post(f"{issuer}/api/v1/auth/token", json={"api_key": api_key},
                        timeout=15).json()["access_token"]
    agent = ColonyOIDCClient(client_id="agent", issuer=issuer,
                             token_endpoint_auth_method="none")
    id_token = agent.exchange_token(jwt, audience=rp_id)["id_token"]

    # relying party: verify what arrived
    print("admitted:", admit(relying_party(issuer), id_token))


if __name__ == "__main__":
    if os.environ.get("COLONY_API_KEY") and os.environ.get("RP_CLIENT_ID"):
        _roundtrip_demo()
    else:
        print(__doc__)
