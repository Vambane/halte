"""HTTP security headers for every response.

Halte has no login yet, so the main risks are a page being framed by
another site (clickjacking), injected script running in our origin, and
browsers guessing content types. These headers close those off.

Content-Security-Policy
    Scripts load only from this origin, plus Leaflet from unpkg (pinned and
    SRI-checked) on the system map. The map's one inline script is allowed
    by its SHA-256 hash, computed from the file at startup so the policy
    follows edits to that file. No other inline script is allowed, so an
    injected ``<script>`` or ``onerror=`` attribute does not run.
    Inline *styles* stay allowed: templates set ``--route-color`` and
    Leaflet positions tiles with style attributes.

Framing
    ``frame-ancestors 'self'`` plus ``X-Frame-Options: SAMEORIGIN`` (for old
    browsers). Same-origin, not "none", because /map embeds the map page.
"""
from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path

STATIC_DIR = Path(__file__).parent / "static"
MAP_HTML = STATIC_DIR / "map" / "system_map.html"

LEAFLET_ORIGIN = "https://unpkg.com"
OSM_TILES = "https://tile.openstreetmap.org"

# Two years, the HSTS preload minimum. Only sent over HTTPS (see middleware).
HSTS_VALUE = "max-age=63072000; includeSubDomains"

_INLINE_SCRIPT = re.compile(r"<script>(.*?)</script>", re.S)


def inline_script_hashes(html_path: Path = MAP_HTML) -> list[str]:
    """CSP source expressions ('sha256-...') for each inline <script> in a file."""
    try:
        html = html_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    hashes = []
    for body in _INLINE_SCRIPT.findall(html):
        digest = hashlib.sha256(body.encode("utf-8")).digest()
        hashes.append(f"'sha256-{base64.b64encode(digest).decode('ascii')}'")
    return hashes


def build_csp(script_hashes: list[str] | None = None) -> str:
    """The Content-Security-Policy value sent on every response."""
    hashes = inline_script_hashes() if script_hashes is None else script_hashes
    directives = {
        "default-src": ["'self'"],
        "script-src": ["'self'", LEAFLET_ORIGIN, *hashes],
        "style-src": ["'self'", LEAFLET_ORIGIN, "'unsafe-inline'"],
        "img-src": ["'self'", "data:", OSM_TILES, LEAFLET_ORIGIN],
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
