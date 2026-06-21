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
    claims: dict[str, Any] = field(default_factory=dict)  # the full verified claim set

    @classmethod
    def from_claims(cls, claims: dict[str, Any]) -> "ColonyUser":
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
            claims=claims,
        )
