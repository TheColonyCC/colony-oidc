"""Exceptions for colony-oidc."""


class ColonyOIDCError(Exception):
    """Base for all colony-oidc errors."""


class ColonyOIDCConfigError(ColonyOIDCError):
    """Bad/missing configuration or discovery metadata."""


class ColonyOIDCStateError(ColonyOIDCError):
    """CSRF state mismatch on the authorization-code callback."""


class ColonyOIDCTokenError(ColonyOIDCError):
    """The token endpoint returned an error or an unusable response."""


class ColonyOIDCVerificationError(ColonyOIDCError):
    """The id_token (or logout_token) failed signature, claim, or nonce verification."""


class ColonyOIDCLoginRequired(ColonyOIDCError):
    """A silent (``prompt=none``) auth attempt failed because the user needs to log in.

    Raised by :meth:`ColonyOIDCClient.raise_for_callback_error` when the IdP returns
    ``?error=login_required`` — fall back to an interactive login."""


class ColonyOIDCConsentRequired(ColonyOIDCError):
    """A silent (``prompt=none``) auth attempt failed because the user must grant consent.

    Raised by :meth:`ColonyOIDCClient.raise_for_callback_error` when the IdP returns
    ``?error=consent_required`` — fall back to an interactive login so consent can be
    collected."""
