"""Privacy-friendly usage counts: one log line per page view, nothing stored.

Each counted request writes one line to the ``halte.usage`` logger, e.g.

    usage event=journey_search operator=both day=weekday source=reddit

and nothing else: no IP address, no user agent, no stop names, no times, no
cookies. Render keeps the logs; tools/usage_report.py turns them into daily
counts. No third-party script, so the Content-Security-Policy stays as it is.

``source`` says where a visit came from, to see which launch channel works:
the ``utm_source`` (or ``ref``) query parameter when a shared link carries one,
otherwise the referring site's name when it's on SOURCES, otherwise "other"
for another site or "direct" for none.
"""
from __future__ import annotations

import logging
import re
from typing import Optional
from urllib.parse import urlparse

from fastapi_app.config import OPERATOR_FILTERS

logger = logging.getLogger("halte.usage")

# Crawlers, link-preview fetchers and uptime monitors are not people.
BOT_UA = re.compile(
    r"bot|crawl|spider|slurp|preview|facebookexternalhit|whatsapp|monitor|"
    r"curl|wget|python-requests|httpx|headless|lighthouse|render",
    re.I,
)
DAY_TYPES = ("weekday", "saturday", "sunday")
SOURCE_RE = re.compile(r"^[a-z0-9_.-]{1,32}$")

# Referrer host -> source name for the channels the launch uses.
SOURCES = {
    "reddit.com": "reddit",
    "facebook.com": "facebook",
    "instagram.com": "instagram",
    "t.co": "x",
    "x.com": "x",
    "twitter.com": "x",
    "linkedin.com": "linkedin",
    "google.com": "google",
    "google.co.za": "google",
    "bing.com": "bing",
    "duckduckgo.com": "duckduckgo",
    "mybroadband.co.za": "mybroadband",
    "techcentral.co.za": "techcentral",
    "dailymaverick.co.za": "dailymaverick",
    "nexttrain.co.za": "nexttrain",
    "uct.ac.za": "uct",
}


# /api/stops/locations is only fetched when someone taps "Use my location".
EXACT_EVENTS = {
    "/": "landing",
    "/journey": "journey_view",
    "/api/stops/locations": "use_my_location",
}


def event_name(path: str, params) -> Optional[str]:
    """Which kind of page view this is, or None if it isn't counted."""
    if path in EXACT_EVENTS:
        return EXACT_EVENTS[path]
    if path.startswith("/stop/"):
        return "stop_board"
    if path == "/search":
        searched = params.get("from_stop") and params.get("to_stop")
        return "journey_search" if searched else "search_form"
    if path == "/map":
        return "trip_preview" if params.get("preview") == "1" else "map"
    return None


def _site(host: str) -> str:
    """'www.reddit.com' -> 'reddit.com'; 'old.reddit.com' -> 'reddit.com'."""
    host = host.lower().rsplit(":", 1)[0]
    for known in SOURCES:
        if host == known or host.endswith("." + known):
            return known
    return host


def source(params, referer: str, own_host: str) -> str:
    """Where this visit came from (see module docstring)."""
    tagged = (params.get("utm_source") or params.get("ref") or "").strip().lower()
    if tagged:
        return tagged if SOURCE_RE.match(tagged) else "other"
    if not referer:
        return "direct"
    host = urlparse(referer).hostname or ""
    if not host or host == own_host or host.endswith(".halte.co.za") or host == "halte.co.za":
        return "internal"
    return SOURCES.get(_site(host), "other")


def usage_line(request, status_code: int) -> Optional[str]:
    """The log line for this request, or None when it isn't counted."""
    if request.method != "GET" or status_code >= 400:
        return None
    params = request.query_params
    event = event_name(request.url.path, params)
    if event is None or BOT_UA.search(request.headers.get("user-agent", "") or "bot"):
        return None
    operator = params.get("operator", "both")
    day = params.get("day_type", "")
    parts = [
        f"event={event}",
        f"operator={operator if operator in OPERATOR_FILTERS else 'both'}",
        f"day={day if day in DAY_TYPES else '-'}",
        f"source={source(params, request.headers.get('referer', ''), request.url.hostname or '')}",
    ]
    return "usage " + " ".join(parts)


def record(request, status_code: int) -> None:
    """Write the usage line for this request, if it is counted."""
    line = usage_line(request, status_code)
    if line:
        logger.info(line)
