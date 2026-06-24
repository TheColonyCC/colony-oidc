"""Tests for colony_oidc.brand — the "Log in with the Colony" assets + button."""
import base64

import pytest

from colony_oidc import brand


def test_current_variant_inherits_current_color():
    svg = brand.mark(brand.CURRENT, 24)
    assert "<svg" in svg
    assert 'width="24" height="24"' in svg
    assert 'viewBox="0 0 120 120"' in svg
    assert "currentColor" in svg
    assert "#00ffcc" not in svg


def test_cyan_variant_uses_brand_gradient():
    svg = brand.mark(brand.CYAN, 32)
    assert "linearGradient" in svg
    assert brand.CYAN_FROM in svg
    assert brand.CYAN_TO in svg
    assert 'width="32" height="32"' in svg


def test_cyan_gradient_ids_are_unique_per_call():
    import re

    a = re.search(r'id="(colony-cyan-\d+)"', brand.mark(brand.CYAN)).group(1)
    b = re.search(r'id="(colony-cyan-\d+)"', brand.mark(brand.CYAN)).group(1)
    assert a != b


def test_white_and_black_variants_use_solid_colours():
    assert "#ffffff" in brand.mark(brand.WHITE)
    assert "#000000" in brand.mark(brand.BLACK)


def test_title_renders_accessible_label():
    svg = brand.mark(brand.CURRENT, 24, "Sign in")
    assert "aria-labelledby" in svg
    assert "<title" in svg
    assert "Sign in" in svg


def test_empty_title_marks_decorative():
    svg = brand.mark(brand.CURRENT, 24, "")
    assert 'aria-hidden="true"' in svg
    assert "<title" not in svg


def test_title_is_html_escaped():
    svg = brand.mark(brand.CURRENT, 24, '<x>&"')
    assert "&lt;x&gt;" in svg
    assert "<x>" not in svg


def test_unknown_variant_raises():
    with pytest.raises(ValueError):
        brand.mark("purple")


def test_non_positive_size_raises():
    with pytest.raises(ValueError):
        brand.mark(brand.CURRENT, 0)


@pytest.mark.parametrize(
    "variant,filename",
    [
        (brand.CURRENT, "colony-mark.svg"),
        (brand.CYAN, "colony-mark-cyan.svg"),
        (brand.WHITE, "colony-mark-white.svg"),
        (brand.BLACK, "colony-mark-black.svg"),
    ],
)
def test_asset_path_points_at_shipped_readable_svg(variant, filename):
    path = brand.asset_path(variant)
    assert path.name == filename
    assert path.exists()
    assert "<svg" in path.read_text(encoding="utf-8")


def test_asset_path_rejects_unknown_variant():
    with pytest.raises(ValueError):
        brand.asset_path("chartreuse")


def test_data_uri_is_base64_svg():
    uri = brand.mark_data_uri(brand.CYAN, 16)
    assert uri.startswith("data:image/svg+xml;base64,")
    decoded = base64.b64decode(uri[len("data:image/svg+xml;base64,"):])
    assert b"<svg" in decoded


def test_login_button_renders_accessible_anchor():
    html_out = brand.login_button("https://thecolony.cc/oauth/authorize?x=1")
    assert '<a href="https://thecolony.cc/oauth/authorize?x=1"' in html_out
    assert 'role="button"' in html_out
    assert "colony-login-button colony-login-button--auto" in html_out
    assert brand.DEFAULT_LABEL in html_out
    assert "<svg" in html_out
    assert 'aria-hidden="true"' in html_out


def test_login_button_escapes_href_and_label():
    html_out = brand.login_button('https://x.test/?a=1&b="2"', label="Sign in <script>")
    assert "&amp;b=" in html_out
    assert "&quot;2&quot;" in html_out
    assert "Sign in &lt;script&gt;" in html_out
    assert "<script>" not in html_out


def test_login_button_honours_theme_variant_and_class():
    html_out = brand.login_button(
        "https://x.test", theme="dark", variant=brand.WHITE, class_="w-full"
    )
    assert "colony-login-button--dark" in html_out
    assert "w-full" in html_out
    assert "#ffffff" in html_out


def test_login_button_applies_safe_extra_attributes():
    html_out = brand.login_button(
        "https://x.test",
        attributes={
            "id": "colony-cta",
            "data-track": "login & go",
            "hidden": True,
            "disabled": False,
            "href": "https://evil.test",
            "class": "pwned",
            "bad attr": "x",
        },
    )
    assert 'id="colony-cta"' in html_out
    assert 'data-track="login &amp; go"' in html_out
    assert " hidden" in html_out
    assert "disabled" not in html_out
    assert "evil.test" not in html_out
    assert "pwned" not in html_out
    assert "bad attr" not in html_out


def test_login_button_rejects_empty_href():
    with pytest.raises(ValueError):
        brand.login_button("")


def test_login_button_rejects_unknown_theme():
    with pytest.raises(ValueError):
        brand.login_button("https://x.test", theme="neon")


def test_stylesheet_covers_themes():
    css = brand.button_stylesheet()
    assert ".colony-login-button" in css
    assert "--light" in css
    assert "--dark" in css
    assert "prefers-color-scheme:dark" in css
    assert "#00ccff" in css
