"""colony-oidc — "Login with the Colony" OpenID Connect client for Python."""
from . import brand
from .client import ColonyOIDCClient, generate_pkce, DEFAULT_ISSUER, DEFAULT_SCOPE
from .models import ColonyUser, LoginRequest
from .exceptions import (
    ColonyOIDCError,
    ColonyOIDCConfigError,
    ColonyOIDCConsentRequired,
    ColonyOIDCLoginRequired,
    ColonyOIDCStateError,
    ColonyOIDCTokenError,
    ColonyOIDCVerificationError,
)

__version__ = "0.5.0"
__all__ = [
    "brand",
    "ColonyOIDCClient", "generate_pkce", "DEFAULT_ISSUER", "DEFAULT_SCOPE",
    "ColonyUser", "LoginRequest",
    "ColonyOIDCError", "ColonyOIDCConfigError", "ColonyOIDCStateError",
    "ColonyOIDCTokenError", "ColonyOIDCVerificationError",
    "ColonyOIDCLoginRequired", "ColonyOIDCConsentRequired",
]
