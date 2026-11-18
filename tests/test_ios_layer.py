"""The iOS layer: ios.css plus the phone tab bar.

ios.css sits on top of the brand stylesheets on every page. These
tests keep it loaded everywhere, keep its values in tokens.css, and
check that the phone tab bar marks the right tab for each page.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from fastapi_app.main import app

CSS = Path("fastapi_app/static/css")
IOS = CSS / "ios.css"
TOKENS = CSS / "tokens.css"

PAGES = {
    "/": "home",
    "/search": "plan",
    "/stop/Civic Centre": "plan",
    "/map": "map",
}


@pytest.fixture(name="client", scope="module")
def fixture_client():
    """One app client for the module (starts the app once)."""
    with TestClient(app) as c:
        yield c


@pytest.mark.parametrize("path", list(PAGES))
def test_every_page_loads_ios_layer_last(client, path):
    """ios.css loads on every page, after the brand stylesheets."""
    html = client.get(path).text
    assert "/static/css/ios.css" in html
    ios_at = html.index("/static/css/ios.css")
    for sheet in ("tokens.css", "base.css", "components.css", "landing.css"):
        at = html.find(f"/static/css/{sheet}")
        if at != -1:
            assert at < ios_at, f"{sheet} must load before ios.css on {path}"


@pytest.mark.parametrize("path, tab", list(PAGES.items()))
def test_tabbar_marks_current_tab(client, path, tab):
    """Exactly one tab is current, and it is the right one."""
    html = client.get(path).text
    assert 'class="tabbar"' in html
    assert 'aria-label="Sections"' in html
    current = re.findall(r'data-tab="(\w+)" aria-current="page"', html)
    assert current == [tab], f"{path}: current tabs {current}"


def test_tabbar_links_are_real_routes(client):
    """Every tab points at a page that answers 200."""
    html = client.get("/search").text
    hrefs = re.findall(r'class="tabbar__item" data-tab="\w+"[^>]*', html)
    assert len(hrefs) == 3
    for href in ("/", "/search", "/map"):
        assert f'<a href="{href}" class="tabbar__item"' in html
        assert client.get(href).status_code == 200


@pytest.mark.parametrize("path", list(PAGES))
def test_viewport_allows_safe_area(client, path):
    """viewport-fit=cover lets env(safe-area-inset-bottom) clear the home bar."""
    assert "viewport-fit=cover" in client.get(path).text


def test_ios_values_live_in_tokens():
    """Every --ios-* / --tabbar-* var ios.css uses is defined in tokens.css."""
    ios = IOS.read_text()
    tokens = TOKENS.read_text()
    used = set(re.findall(r"var\((--(?:ios|tabbar)-[a-z-]+)\)", ios))
    assert used, "ios.css should use the iOS tokens"
    for name in used:
        assert f"{name}:" in tokens, f"{name} missing from tokens.css"
    assert not re.search(r"^\s*--[a-z][\w-]*\s*:", ios, re.M), "ios.css must not define tokens"


def test_ios_layer_adds_no_new_brand_colours():
    """No hex colours in ios.css: brand colours stay in tokens.css."""
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", IOS.read_text())


def test_tabbar_only_on_phones():
    """The tab bar is hidden by default and shown only below 768px."""
    ios = IOS.read_text()
    assert re.search(r"\.tabbar\s*\{\s*display:\s*none;", ios)
    phone = ios.split("@media (max-width: 767px)", 1)[1]
    assert "position: fixed" in phone
    assert "env(safe-area-inset-bottom" in phone
