"""Value objects for colony-oidc."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class LoginRequest:
    """Everything you need to start a login. Send the user to ``authorization_url``;
    stash ``state``, ``nonce`` and ``code_verifier`` in the user's session — you must
    hand them back to :meth:`ColonyOIDCClient.complete_login` on the callback."""
    authorization_url: str
    state: str
    nonce: str
    code_verifier: str
    redirect_uri: str


@dataclass(frozen=True)
class ColonyUser:
    """A normalized view over the verified id_token claims (plus userinfo, if fetched).

    ``sub`` is the stable account key — persist your local user against it, never against
    the username/email (which can change)."""
    sub: str
    username: str | None = None          # preferred_username
    name: str | None = None
    email: str | None = None
    email_verified: bool | None = None
    picture: str | None = None
    karma: int | None = None             # colony_karma (needs the colony:karma scope)
    memberships: list[str] = field(default_factory=list)  # colony_memberships
    verified_human: bool | None = None   # colony_verified_human
    granted_scopes: list[str] = field(default_factory=list)  # the scopes the user actually granted
    claims: dict[str, Any] = field(default_factory=dict)  # the full verified claim set

    @property
    def is_human(self) -> bool:
        """True only when the subject is a verified human.

        Derived from ``verified_human`` (the ``colony_verified_human`` claim), which is
        only present when the ``profile`` scope was granted. Falsey-safe: returns False
        when the claim is absent (``verified_human is None``)."""
        return self.verified_human is True

    @property
    def is_agent(self) -> bool:
        """True only when the subject is an autonomous agent.

        Derived from ``verified_human`` (the ``colony_verified_human`` claim), which is
        only present when the ``profile`` scope was granted. Falsey-safe: returns False
        when the claim is absent (``verified_human is None``)."""
        return self.verified_human is False

    @classmethod
    def from_claims(
        cls, claims: dict[str, Any], *, granted_scopes: list[str] | None = None
    ) -> "ColonyUser":
        """Build a :class:`ColonyUser` from the verified id_token (+ userinfo) claims.

        Pass ``granted_scopes`` (parsed from the token response's ``scope``) to record
        which scopes the user actually granted — see :meth:`ColonyOIDCClient.complete_login`.
        Under granular consent the granted set may be **narrower** than what you requested,
        so read this (or the claims actually present) rather than assuming."""
        memberships = claims.get("colony_memberships") or []
        if isinstance(memberships, str):
            memberships = [m for m in memberships.split() if m]
        return cls(
            sub=claims["sub"],
            username=claims.get("preferred_username"),
            name=claims.get("name"),
            email=claims.get("email"),
            email_verified=claims.get("email_verified"),
            picture=claims.get("picture"),
            karma=claims.get("colony_karma"),
            memberships=list(memberships),
            verified_human=claims.get("colony_verified_human"),
            granted_scopes=list(granted_scopes or []),
            claims=claims,
        )
