"""November 2026 hardening pass: Host allowlist, strict CSP, HSTS preload,
hidden files, security.txt, recent-search hygiene and the no-POST guard.

Each test names the item it covers. Live equivalents: tools/check_live_security.sh.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from fastapi_app.security import (
    MAP_HTML,
    PUBLIC_HOSTS,
    build_csp,
    inline_hashes,
    resolve_allowed_hosts,
)

REPO = Path(__file__).resolve().parents[1]
TEMPLATES = REPO / "fastapi_app" / "templates"
STATIC_JS = REPO / "fastapi_app" / "static" / "js"


@pytest.fixture(scope="module")
def client():
    from fastapi_app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture
def locked(client):
    """The app as it runs on Render: public host names only."""
    app = client.app
    before = app.state.allowed_hosts
    app.state.allowed_hosts = frozenset(PUBLIC_HOSTS)
    yield client
    app.state.allowed_hosts = before


def _csp_directive(csp: str, name: str) -> list[str]:
    match = re.search(rf"(?:^|; ){name} ([^;]+)", csp)
    return match.group(1).split() if match else []


# --- 1. Host allowlist -----------------------------------------------------------

def test_1_render_defaults_to_public_hosts_only():
    assert resolve_allowed_hosts("", {"RENDER": "true"}) == frozenset(PUBLIC_HOSTS)
    assert resolve_allowed_hosts("", {}) == frozenset()  # local dev, CI: any host
    assert resolve_allowed_hosts("a.test, B.test", {"RENDER": "true"}) == {"a.test", "b.test"}


@pytest.mark.parametrize("host", ["myciti-bus-timetable.onrender.com", "evil.example", ""])
def test_1_other_hosts_get_403(locked, host):
    r = locked.get("/", headers={"host": host})
    assert r.status_code == 403
    assert r.headers["x-frame-options"] == "SAMEORIGIN"  # still has security headers


@pytest.mark.parametrize("host", ["halte.co.za", "www.halte.co.za", "HALTE.co.za:443"])
def test_1_public_hosts_pass(locked, host):
    assert locked.get("/", headers={"host": host}).status_code == 200


def test_1_health_skips_the_lock_for_render_checks(locked):
    assert locked.get("/health", headers={"host": "10.0.0.5:10000"}).status_code != 403


# --- 3. Content-Security-Policy -------------------------------------------------

def test_3_csp_has_no_unsafe_keywords_anywhere(client):
    csp = client.get("/").headers["content-security-policy"]
    assert "'unsafe-inline'" not in csp
    assert "'unsafe-eval'" not in csp
    assert _csp_directive(csp, "default-src") == ["'self'"]
    for directive, value in [
        ("frame-ancestors", ["'self'"]), ("object-src", ["'none'"]),
        ("base-uri", ["'self'"]), ("form-action", ["'self'"]),
    ]:
        assert _csp_directive(csp, directive) == value, directive


def test_3_only_hosts_the_map_uses_are_allowed(client):
    csp = client.get("/map").headers["content-security-policy"]
    outside = set(re.findall(r"https://[^\s;]+", csp))
    assert outside == {"https://unpkg.com", "https://tile.openstreetmap.org"}
    assert _csp_directive(csp, "img-src") == ["'self'", "data:", "https://tile.openstreetmap.org"]
    assert _csp_directive(csp, "connect-src") == ["'self'"]


def test_3_map_inline_style_is_allowed_by_hash():
    styles = inline_hashes("style", MAP_HTML)
    assert len(styles) == 1
    assert _csp_directive(build_csp(), "style-src") == ["'self'", "https://unpkg.com", *styles]


def test_3_no_style_attributes_in_templates_or_map():
    """style="" attributes would be blocked: the CSP has no 'unsafe-inline'."""
    files = list(TEMPLATES.rglob("*.html")) + [MAP_HTML]
    for f in files:
        src = f.read_text(encoding="utf-8")
        assert not re.search(r"\sstyle\s*=", src), f
        if f != MAP_HTML:
            assert "<style" not in src, f


def test_3_route_colours_come_from_data_attributes():
    js = (STATIC_JS / "route-colors.js").read_text(encoding="utf-8")
    assert "setProperty('--route-color'" in js
    assert "#[0-9a-fA-F]{3,8}" in js  # only hex colours reach the style


# --- 4. HSTS --------------------------------------------------------------------

def test_4_hsts_is_one_year_with_subdomains_and_preload(client):
    r = client.get("/", headers={"X-Forwarded-Proto": "https"})
    assert r.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains; preload"


# --- 5. Recent searches on /search -----------------------------------------------

def test_5_static_js_never_uses_html_sinks():
    for js in STATIC_JS.glob("*.js"):
        src = js.read_text(encoding="utf-8")
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
            assert sink not in src, f"{js.name} uses {sink}"


def test_5_history_is_validated_and_length_limited():
    src = (STATIC_JS / "search.js").read_text(encoding="utf-8")
    assert "cleanHistory(JSON.parse(raw))" in src           # every read is cleaned
    assert re.search(r"try \{\s*var raw = localStorage", src)  # parse is inside try
    assert "MAX_STOP_LEN = 120" in src
    assert "DAY_TYPES = ['weekday', 'saturday', 'sunday']" in src
    assert "text.textContent = item.from_stop" in src


# --- 6. Hidden files, docs and debug ----------------------------------------------

@pytest.mark.parametrize("path", [
    "/.env", "/.env.local", "/.git/config", "/.git/HEAD", "/render.yaml", "/Dockerfile",
    "/requirements.txt", "/static/../render.yaml", "/static/%2e%2e/requirements.txt",
    "/docs", "/redoc", "/openapi.json", "/debug", "/__debug__", "/admin",
])
def test_6_sensitive_paths_are_404(client, path):
    assert client.get(path).status_code == 404


def test_6_debug_is_off(client):
    assert client.app.debug is False


def test_6_errors_do_not_leak_tracebacks(client):
    r = client.get("/journey", params={"legs": "x" * 5000})
    assert "Traceback" not in r.text


# --- 7. security.txt ---------------------------------------------------------------

def test_7_security_txt(client):
    r = client.get("/.well-known/security.txt")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    fields = dict(line.split(": ", 1) for line in r.text.strip().splitlines())
    assert fields["Contact"].startswith(("mailto:", "https://"))
    expires = datetime.strptime(fields["Expires"], "%Y-%m-%dT%H:%M:%SZ")
    expires = expires.replace(tzinfo=timezone.utc)
    days = (expires - datetime.now(timezone.utc)).days
    assert 0 < days <= 366  # RFC 9116: in the future, under a year out
    assert fields["Canonical"] == "https://halte.co.za/.well-known/security.txt"


# --- 8. No accounts yet ----------------------------------------------------------------

def test_8_no_state_changing_routes_until_auth_checklist_is_done(client):
    """Adding a POST/PUT/PATCH/DELETE route? Do SECURITY.md's login checklist first
    (password hashing, Secure/HttpOnly/SameSite cookies, CSRF, rate limits,
    generic errors), then update this test."""
    unsafe = sorted(
        (method, route.path)
        for route in client.app.routes
        for method in (getattr(route, "methods", None) or ())
        if method not in {"GET", "HEAD"}
    )
    assert unsafe == []


def test_8_no_secrets_committed():
    import subprocess

    tracked = subprocess.run(
        ["git", "ls-files"], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout.splitlines()
    assert not [f for f in tracked if re.search(r"(^|/)\.env(\.|$)|\.pem$|\.key$", f)]
