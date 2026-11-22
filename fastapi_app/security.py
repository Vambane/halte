"""HTTP security headers and the origin lock.

Halte has no login yet, so the main risks are a page being framed by
another site (clickjacking), injected script or style running in our origin,
browsers guessing content types, and the site being served under the
default *.onrender.com address. This module closes those off.

Content-Security-Policy
    Scripts and styles load only from this origin, plus Leaflet from unpkg
    (pinned and SRI-checked) on the system map. The map page's one inline
    ``<script>`` and one inline ``<style>`` are allowed by SHA-256 hash,
    computed from the file at startup so the policy follows edits to it.
    Nothing else inline is allowed: no 'unsafe-inline', no 'unsafe-eval',
    and no ``style="..."`` attributes (templates use classes; per-route
    colours are set from ``data-route-color`` by static/js/route-colors.js).
    Images: this origin, data: URIs and OpenStreetMap tiles, the only
    outside image host the map uses.

Framing
    ``frame-ancestors 'self'`` plus ``X-Frame-Options: SAMEORIGIN`` (for old
    browsers). Same-origin, not "none", because /map embeds the map page.

Host allowlist
    halte.co.za's DNS (GoDaddy) points straight at Render; there is no CDN of
    our own in front. Render also serves every service on a default
    *.onrender.com address. On Render the app answers only halte.co.za and
    www.halte.co.za and refuses other Host names with 403, so that second
    address stops serving the site. /health is exempt so Render's own
    health checks keep working.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
from pathlib import Path

STATIC_DIR = Path(__file__).parent / "static"
MAP_HTML = STATIC_DIR / "map" / "system_map.html"

LEAFLET_ORIGIN = "https://unpkg.com"
OSM_TILES = "https://tile.openstreetmap.org"

# One year with preload: the hstspreload.org submission minimum. Only sent
# over HTTPS (see the middleware). Every subdomain must serve HTTPS too.
HSTS_VALUE = "max-age=31536000; includeSubDomains; preload"

PUBLIC_HOSTS = ("halte.co.za", "www.halte.co.za")
# Paths that skip the Host check: Render's own health checks reach the
# service without the public Host name.
UNLOCKED_PATHS = frozenset({"/health"})

_INLINE = {
    "script": re.compile(r"<script>(.*?)</script>", re.S),
    "style": re.compile(r"<style>(.*?)</style>", re.S),
}


def inline_hashes(tag: str, html_path: Path = MAP_HTML) -> list[str]:
    """CSP source expressions ('sha256-...') for each bare inline <tag> in a file."""
    try:
        html = html_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    hashes = []
    for body in _INLINE[tag].findall(html):
        digest = hashlib.sha256(body.encode("utf-8")).digest()
        hashes.append(f"'sha256-{base64.b64encode(digest).decode('ascii')}'")
    return hashes


def inline_script_hashes(html_path: Path = MAP_HTML) -> list[str]:
    """CSP hashes for the inline <script> blocks in a file."""
    return inline_hashes("script", html_path)


def build_csp(
    script_hashes: list[str] | None = None, style_hashes: list[str] | None = None
) -> str:
    """The Content-Security-Policy value sent on every response."""
    scripts = inline_hashes("script") if script_hashes is None else script_hashes
    styles = inline_hashes("style") if style_hashes is None else style_hashes
    directives = {
        "default-src": ["'self'"],
        "script-src": ["'self'", LEAFLET_ORIGIN, *scripts],
        "style-src": ["'self'", LEAFLET_ORIGIN, *styles],
        "img-src": ["'self'", "data:", OSM_TILES],
        "font-src": ["'self'"],
        "connect-src": ["'self'"],
        "frame-src": ["'self'"],
        "frame-ancestors": ["'self'"],
        "object-src": ["'none'"],
        "base-uri": ["'self'"],
        "form-action": ["'self'"],
        "upgrade-insecure-requests": [],
    }
    return "; ".join(
        " ".join([name, *values]) if values else name
        for name, values in directives.items()
    )


def security_headers(csp: str) -> dict[str, str]:
    """Headers added to every response (HSTS is added separately, HTTPS only)."""
    return {
        "Content-Security-Policy": csp,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        # "Use my location" needs geolocation on our own pages; nothing else.
        "Permissions-Policy": (
            "geolocation=(self), camera=(), microphone=(), payment=(), usb=(), "
            "interest-cohort=()"
        ),
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
    }


def is_https(request) -> bool:
    """True when the browser reached us over HTTPS.

    Render's edge terminates TLS, so the app itself sees plain HTTP;
    the proxy's X-Forwarded-Proto says what the browser used.
    """
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    return proto.split(",")[0].strip().lower() == "https"


def resolve_allowed_hosts(configured: str, environ=os.environ) -> frozenset[str]:
    """Host names to accept. Empty set means any host (local dev, tests, CI)."""
    names = [h.strip().lower() for h in configured.split(",") if h.strip()]
    if not names and environ.get("RENDER"):
        names = list(PUBLIC_HOSTS)
    return frozenset(names)


def _host_name(host_header: str) -> str:
    """Lower-cased host from a Host header, without the port."""
    host = host_header.strip().lower()
    if host.startswith("["):  # IPv6 literal
        return host.split("]")[0] + "]"
    return host.rsplit(":", 1)[0] if ":" in host else host


def host_refused(request, allowed_hosts: frozenset[str]) -> bool:
    """True when the request's Host is not one we serve (answer 403)."""
    if not allowed_hosts or request.url.path in UNLOCKED_PATHS:
        return False
    return _host_name(request.headers.get("host", "")) not in allowed_hosts
