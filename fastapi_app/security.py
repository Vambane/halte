"""HTTP security headers and the origin lock.

Halte has no login yet, so the main risks are a page being framed by
another site (clickjacking), injected script or style running in our origin,
browsers guessing content types, and people reaching the Render origin
directly instead of through Cloudflare. This module closes those off.

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

Origin lock
    Render's edge sits behind its own Cloudflare, so a request can reach the
    Render service without passing through halte.co.za's Cloudflare zone.
    Two checks, both skipped for /health so Render's health checks work:

    * Host allowlist: only halte.co.za and www.halte.co.za on Render. This
      stops the default *.onrender.com address serving the site.
    * Origin secret: when ORIGIN_SECRET is set, every request must carry it
      in the X-Halte-Origin header, which a Cloudflare request-header
      Transform Rule adds. A Host header can be faked; the secret cannot.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
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
ORIGIN_HEADER = "x-halte-origin"
# Paths that skip the origin lock: Render's own health checks reach the
# service directly, without Cloudflare's header or the public Host name.
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

    Render and Cloudflare terminate TLS, so the app itself sees plain HTTP;
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


def origin_refusal(request, allowed_hosts: frozenset[str], origin_secret: str) -> str | None:
    """Why this request must be refused with 403, or None to let it through."""
    if request.url.path in UNLOCKED_PATHS:
        return None
    if allowed_hosts and _host_name(request.headers.get("host", "")) not in allowed_hosts:
        return "host"
    if origin_secret:
        sent = request.headers.get(ORIGIN_HEADER, "")
        if not hmac.compare_digest(sent.encode(), origin_secret.encode()):
            return "origin"
    return None
