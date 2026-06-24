"""Brand assets for "Log in with the Colony".

The Colony mark ships in four colour variants and this module renders an
accessible, theme-aware login button, so consumers don't copy SVGs or guess
colours. The default variant inherits ``currentColor``, so the mark matches the
surrounding text colour — legible on light *and* dark surfaces from one asset.
Use the fixed variants (``cyan``/``white``/``black``) only where ``currentColor``
can't reach: CSS ``background-image``, an ``<img src>``, or HTML email.

This module is presentation only; it never touches the network or the OIDC flow.
The Python counterpart of ``TheColony\\OAuth2\\ColonyBrand`` in
``thecolony/oauth2-colony``.
"""
from __future__ import annotations

import base64
import html
import itertools
from importlib import resources
from pathlib import Path
from typing import Mapping, Optional, Union

CURRENT = "current"
CYAN = "cyan"
WHITE = "white"
BLACK = "black"
VARIANTS = (CURRENT, CYAN, WHITE, BLACK)

CYAN_FROM = "#00ffcc"
CYAN_TO = "#00ccff"

DEFAULT_LABEL = "Log in with the Colony"
THEMES = ("auto", "light", "dark")

_seq = itertools.count(1)

__all__ = [
    "CURRENT", "CYAN", "WHITE", "BLACK", "VARIANTS",
    "CYAN_FROM", "CYAN_TO", "DEFAULT_LABEL", "THEMES",
    "mark", "asset_path", "mark_data_uri", "login_button", "button_stylesheet",
]


def _check_variant(variant: str) -> None:
    if variant not in VARIANTS:
        raise ValueError(
            f'Unknown Colony mark variant "{variant}". '
            f"Expected one of: {', '.join(VARIANTS)}."
        )


def mark(variant: str = CURRENT, size: int = 24, title: str = "The Colony") -> str:
    """Return the Colony mark as an inline ``<svg>`` string.

    :param variant: one of :data:`VARIANTS`.
    :param size: rendered width/height in pixels (must be > 0).
    :param title: accessible label; pass ``""`` for a decorative mark.
    """
    _check_variant(variant)
    if size <= 0:
        raise ValueError("Mark size must be a positive integer.")

    defs = ""
    if variant == CYAN:
        grad_id = f"colony-cyan-{next(_seq)}"
        stroke = f"url(#{grad_id})"
        dot_a, dot_b = CYAN_FROM, CYAN_TO
        defs = (
            f'<defs><linearGradient id="{grad_id}" x1="20" y1="20" x2="100" y2="100" '
            f'gradientUnits="userSpaceOnUse">'
            f'<stop stop-color="{CYAN_FROM}"/><stop offset="1" stop-color="{CYAN_TO}"/>'
            f"</linearGradient></defs>"
        )
    else:
        stroke = {WHITE: "#ffffff", BLACK: "#000000"}.get(variant, "currentColor")
        dot_a = dot_b = stroke

    if title:
        title_id = f"colony-mark-title-{next(_seq)}"
        a11y = f' role="img" aria-labelledby="{title_id}"'
        title_el = f'<title id="{title_id}">{html.escape(title)}</title>'
    else:
        a11y = ' role="img" aria-hidden="true"'
        title_el = ""

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" '
        f'viewBox="0 0 120 120" fill="none"{a11y}>'
        f"{title_el}{defs}"
        f'<path d="M 85 30 A 40 40 0 1 0 85 90" fill="none" stroke="{stroke}" '
        f'stroke-width="8" stroke-linecap="round"/>'
        f'<circle cx="55" cy="52" r="4.5" fill="{dot_a}" opacity="0.9"/>'
        f'<circle cx="68" cy="60" r="3.5" fill="{dot_b}" opacity="0.7"/>'
        f'<circle cx="52" cy="68" r="3" fill="{dot_a}" opacity="0.6"/>'
        f"</svg>"
    )


def asset_path(variant: str = CYAN) -> Path:
    """Filesystem path to a shipped SVG asset.

    Useful when a framework wants to publish/serve the file itself.
    """
    _check_variant(variant)
    name = "colony-mark.svg" if variant == CURRENT else f"colony-mark-{variant}.svg"
    return Path(str(resources.files("colony_oidc").joinpath("assets", name)))


def mark_data_uri(variant: str = CYAN, size: int = 24) -> str:
    """The mark as a ``data:`` URI, for CSS ``background-image``/``<img>``/email."""
    raw = mark(variant, size, "").encode("utf-8")
    return "data:image/svg+xml;base64," + base64.b64encode(raw).decode("ascii")


def login_button(
    href: str,
    *,
    label: str = DEFAULT_LABEL,
    theme: str = "auto",
    variant: str = CURRENT,
    size: int = 20,
    class_: str = "",
    attributes: Optional[Mapping[str, Union[str, int, bool]]] = None,
) -> str:
    """Return an accessible "Log in with the Colony" button (an ``<a>``).

    The mark defaults to :data:`CURRENT`, so it follows the button's text colour.
    Pair with :func:`button_stylesheet` for drop-in styling, or bring your own CSS
    via the ``colony-login-button`` class. ``href``, ``label`` and every extra
    attribute value are HTML-escaped; ``href``/``class`` can't be set through
    ``attributes``.
    """
    if not href:
        raise ValueError("login_button() requires a non-empty href.")
    if theme not in THEMES:
        raise ValueError(
            f'Unknown button theme "{theme}". Expected one of: {", ".join(THEMES)}.'
        )

    classes = f"colony-login-button colony-login-button--{theme}"
    if class_.strip():
        classes += " " + class_.strip()

    attr_html = ""
    if attributes:
        import re

        for name, value in attributes.items():
            lname = str(name).lower()
            if lname in ("href", "class") or not re.match(r"^[a-zA-Z][a-zA-Z0-9:_-]*$", str(name)):
                continue
            if value is False:
                continue
            if value is True:
                attr_html += f" {name}"
                continue
            attr_html += f' {name}="{html.escape(str(value))}"'

    return (
        f'<a href="{html.escape(href)}" class="{html.escape(classes)}" role="button"{attr_html}>'
        f'<span class="colony-login-button__mark" aria-hidden="true">{mark(variant, size, "")}</span>'
        f'<span class="colony-login-button__label">{html.escape(label)}</span>'
        f"</a>"
    )


def button_stylesheet() -> str:
    """Default CSS for :func:`login_button` (auto/light/dark, brand-cyan focus ring).

    Include once per page (a ``<style>`` tag, or a served ``.css`` file). Only
    targets the ``.colony-login-button`` classes, so it's fully overridable.
    """
    return (
        ".colony-login-button{display:inline-flex;align-items:center;gap:.5em;"
        "padding:.55em .9em;border-radius:8px;border:1px solid transparent;"
        'font:600 14px/1.2 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;'
        "text-decoration:none;cursor:pointer;user-select:none;"
        "transition:filter .12s ease,box-shadow .12s ease,background-color .12s ease}"
        ".colony-login-button__mark{display:inline-flex;flex:0 0 auto}"
        ".colony-login-button:hover{filter:brightness(.97)}"
        ".colony-login-button:focus-visible{outline:2px solid #00ccff;outline-offset:2px}"
        ".colony-login-button--light{background:#ffffff;color:#0f1729;border-color:#d8dee9}"
        ".colony-login-button--dark{background:#0f1729;color:#ffffff;border-color:transparent}"
        ".colony-login-button--auto{background:#ffffff;color:#0f1729;border-color:#d8dee9}"
        "@media (prefers-color-scheme:dark){"
        ".colony-login-button--auto{background:#0f1729;color:#ffffff;border-color:transparent}}"
    )
