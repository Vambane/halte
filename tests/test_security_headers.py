"""Security headers on every response (November 2026 header review).

Before this, halte.co.za sent no CSP, no anti-framing header, no nosniff,
no HSTS, and served /docs, /redoc and /openapi.json in production.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from fastapi_app.security import MAP_HTML, build_csp, inline_script_hashes
# The uvicorn server fixture and Leaflet stub are shared with the XSS browser test.
from tests.test_security_hardening import _serve_leaflet, server  # noqa: F401  pylint: disable=unused-import

REPO = Path(__file__).resolve().parents[1]
TEMPLATES = REPO / "fastapi_app" / "templates"

PAGES = ["/", "/search", "/map", "/static/map/system_map.html", "/api/stops", "/health"]


@pytest.fixture(scope="module")
def client():
    from fastapi_app.main import app

    with TestClient(app) as c:
        yield c


@pytest.mark.parametrize("path", PAGES)
def test_every_response_has_security_headers(client, path):
    r = client.get(path)
    h = r.headers
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "SAMEORIGIN"
    assert h["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "geolocation=(self)" in h["permissions-policy"]
    assert "camera=()" in h["permissions-policy"]
    assert h["cross-origin-opener-policy"] == "same-origin"
    csp = h["content-security-policy"]
    assert "frame-ancestors 'self'" in csp
    assert "object-src 'none'" in csp
    assert "base-uri 'self'" in csp


def test_csp_blocks_inline_script_except_the_map_hash(client):
    csp = client.get("/").headers["content-security-policy"]
    script_src = re.search(r"script-src ([^;]+)", csp).group(1).split()
    assert "'unsafe-inline'" not in script_src
    assert "'unsafe-eval'" not in script_src
    hashes = [s for s in script_src if s.startswith("'sha256-")]
    assert hashes == inline_script_hashes(MAP_HTML)
    assert len(hashes) == 1


def test_no_template_has_inline_script():
    """Templates may only load scripts by src: the CSP has no hash for them."""
    for tpl in TEMPLATES.rglob("*.html"):
        src = tpl.read_text(encoding="utf-8")
        assert "<script>" not in src, tpl
        assert not re.search(r"\son[a-z]+\s*=\s*[\"']", src), tpl
        assert "javascript:" not in src, tpl


def test_map_hash_follows_file_contents(tmp_path):
    page = tmp_path / "p.html"
    page.write_text("<script>alert(1)</script>", encoding="utf-8")
    first = inline_script_hashes(page)
    page.write_text("<script>alert(2)</script>", encoding="utf-8")
    assert inline_script_hashes(page) != first
    assert first[0] in build_csp(first)


def test_hsts_only_over_https(client):
    assert "strict-transport-security" not in client.get("/health").headers
    r = client.get("/health", headers={"X-Forwarded-Proto": "https"})
    assert r.headers["strict-transport-security"] == (
        "max-age=31536000; includeSubDomains; preload"
    )


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_api_docs_are_off_by_default(client, path):
    assert client.get(path).status_code == 404


def test_render_start_command_hides_server_banner():
    assert "--no-server-header" in (REPO / "render.yaml").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Real browser: the CSP does not break the pages it protects
# ---------------------------------------------------------------------------

def test_pages_run_under_csp_without_violations(server):
    """Map (Leaflet + hashed inline script), landing, search and map pages load clean."""
    sync_api = pytest.importorskip("playwright.sync_api")
    base = server
    with sync_api.sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception as exc:  # browser binaries missing
            pytest.skip(f"no browser: {exc}")
        page = browser.new_page()
        page.route("**/unpkg.com/leaflet@1.9.4/**", _serve_leaflet)
        page.route("**/tile.openstreetmap.org/**", lambda r: r.abort())
        page.add_init_script("""
            window.__csp = [];
            document.addEventListener('securitypolicyviolation', e =>
                window.__csp.push(e.violatedDirective + ' ' + e.blockedURI));
        """)
        page.goto(base + "/static/map/system_map.html")
        try:
            page.wait_for_function("typeof L !== 'undefined'", timeout=10000)
        except sync_api.Error:
            browser.close()
            pytest.skip("Leaflet could not be loaded (offline, set LEAFLET_DIST)")
        page.wait_for_selector(".lrow", timeout=15000)
        assert page.evaluate("window.__csp") == []

        for path in ["/", "/search", "/map"]:
            page.goto(base + path)
            page.wait_for_load_state("load")
            page.wait_for_timeout(500)
            assert page.evaluate("window.__csp") == [], path
        browser.close()
