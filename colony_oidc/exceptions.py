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
    """The id_token failed signature, claim, or nonce verification."""
