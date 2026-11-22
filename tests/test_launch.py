"""Launch readiness: share previews and icons, feedback link, usage counts,
the timetable-refresh guard and workflow (November 2026)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from PIL import Image
from starlette.datastructures import QueryParams

from fastapi_app.services import usage
from tools import check_snapshot, usage_report

REPO = Path(__file__).resolve().parents[1]
STATIC = REPO / "fastapi_app" / "static"
PHONE = {"user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)"}


@pytest.fixture(scope="module")
def client():
    from fastapi_app.main import app

    with TestClient(app) as c:
        yield c


# --- Share previews, icons, manifest -------------------------------------------

@pytest.mark.parametrize("path", ["/", "/search", "/map", "/stop/Civic%20Centre"])
def test_pages_have_share_preview_and_icons(client, path):
    html = client.get(path).text
    og_image = "https://halte.co.za/static/img/og-image.png"
    assert f'<meta property="og:image" content="{og_image}">' in html
    assert '<meta name="twitter:card" content="summary_large_image">' in html
    assert 'rel="apple-touch-icon"' in html
    assert '<link rel="manifest" href="/static/manifest.webmanifest">' in html


@pytest.mark.parametrize("name, size", [
    ("og-image.png", (1200, 630)), ("icon-512.png", (512, 512)), ("icon-192.png", (192, 192)),
    ("apple-touch-icon.png", (180, 180)), ("favicon-32.png", (32, 32)),
])
def test_brand_images_exist_at_the_right_size(client, name, size):
    r = client.get(f"/static/img/{name}")
    assert r.status_code == 200 and r.headers["content-type"] == "image/png"
    assert Image.open(STATIC / "img" / name).size == size


def test_manifest_is_valid_and_served_with_its_type(client):
    r = client.get("/static/manifest.webmanifest")
    assert r.headers["content-type"].startswith("application/manifest+json")
    manifest = json.loads(r.text)
    assert manifest["short_name"] == "Halte"
    assert manifest["display"] == "standalone"
    for entry in manifest["icons"]:
        assert client.get(entry["src"]).status_code == 200


# --- Feedback link ------------------------------------------------------------------

def test_feedback_link_hidden_until_configured(client):
    assert "Report a wrong time" not in client.get("/search").text


def test_feedback_link_carries_the_page(client):
    env = client.app.state.templates.env
    before = env.globals["feedback_href"]
    env.globals["feedback_href"] = "mailto:hello@example.org?subject=Halte%20feedback"
    try:
        html = client.get("/stop/Civic%20Centre").text
    finally:
        env.globals["feedback_href"] = before
    href = "mailto:hello@example.org?subject=Halte%20feedback&amp;body=Page%3A%20http"
    assert f'href="{href}' in html
    assert "Report a wrong time" in html


# --- Landing keeps tracking-only links ------------------------------------------------

def test_landing_stays_for_tracking_params(client):
    r = client.get("/?utm_source=reddit&utm_medium=post", follow_redirects=False)
    assert r.status_code == 200
    r = client.get("/?from_stop=Civic+Centre", follow_redirects=False)
    assert r.status_code == 301 and r.headers["location"] == "/search?from_stop=Civic+Centre"


# --- Usage counts ----------------------------------------------------------------------

class _Req:  # pylint: disable=too-few-public-methods
    def __init__(self, url: str, headers: dict, method: str = "GET"):
        from starlette.datastructures import URL

        self.url = URL("https://halte.co.za" + url)
        self.query_params = QueryParams(self.url.query)
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.method = method


def line(url: str, headers: dict | None = None, status: int = 200):
    return usage.usage_line(_Req(url, headers if headers is not None else PHONE), status)


def test_usage_line_has_no_personal_or_trip_details():
    out = line(
        "/search?from_stop=Civic+Centre&to_stop=Table+View&day_type=weekday&operator=myciti",
        {**PHONE, "referer": "https://old.reddit.com/r/capetown/x"},
    )
    assert out == "usage event=journey_search operator=myciti day=weekday source=reddit"
    assert "Civic" not in out and "Table" not in out and "iPhone" not in out


@pytest.mark.parametrize("url, headers, expected", [
    ("/", PHONE, "usage event=landing operator=both day=- source=direct"),
    ("/?utm_source=WhatsApp", PHONE, "usage event=landing operator=both day=- source=whatsapp"),
    ("/search", PHONE, "usage event=search_form operator=both day=- source=direct"),
    ("/stop/X?day_type=sunday", PHONE,
     "usage event=stop_board operator=both day=sunday source=direct"),
    ("/map?preview=1", PHONE, "usage event=trip_preview operator=both day=- source=direct"),
    ("/api/stops/locations", {**PHONE, "referer": "https://halte.co.za/search"},
     "usage event=use_my_location operator=both day=- source=internal"),
    ("/?utm_source=<script>", PHONE, "usage event=landing operator=both day=- source=other"),
    ("/search?operator=evil&day_type=evil", PHONE,
     "usage event=search_form operator=both day=- source=direct"),
])
def test_usage_events(url, headers, expected):
    assert line(url, headers) == expected


@pytest.mark.parametrize("url, headers, status", [
    ("/", {"user-agent": "WhatsApp/2.24"}, 200),           # link preview fetch
    ("/", {"user-agent": "Googlebot/2.1"}, 200),
    ("/", {}, 200),                                          # no user agent
    ("/static/css/base.css", PHONE, 200),                    # not a page
    ("/health", PHONE, 200),
    ("/stop/X", PHONE, 404),
])
def test_usage_skips_bots_assets_and_errors(url, headers, status):
    assert line(url, headers, status) is None


def test_usage_report_counts_render_log_lines():
    logs = [
        "2026-11-23 08:15:02,123 - halte.usage - INFO - usage event=journey_search "
        "operator=both day=weekday source=reddit",
        "2026-11-23 08:16:00,000 - halte.usage - INFO - usage event=landing operator=both "
        "day=- source=direct",
        "2026-11-24 07:00:00,000 - halte.usage - INFO - usage event=journey_search "
        "operator=myciti day=weekday source=direct",
        "INFO: 1.2.3.4 - GET / 200",
    ]
    text = usage_report.report(usage_report.parse(logs))
    assert "2026-11-23                 2" in text
    assert "journey_search             2" in text
    assert "reddit                     1" in text
    assert text.endswith("Total views 3, journey searches 2")


# --- Timetable refresh guard and workflow ------------------------------------------------

def test_snapshot_guard_refuses_lost_routes():
    old = {("myciti", "routes"): 47, ("myciti", "departures"): 170000, ("uct", "routes"): 15}
    assert check_snapshot.problems(old, dict(old)) == []
    assert check_snapshot.problems(old, {**old, ("myciti", "routes"): 44}) == []   # -6%
    assert check_snapshot.problems(old, {**old, ("myciti", "routes"): 40}) == [
        "myciti routes: 47 -> 40"
    ]
    assert check_snapshot.problems(old, {k: v for k, v in old.items() if k[0] != "uct"}) == [
        "uct routes: 15 -> 0"
    ]


def test_snapshot_guard_reads_the_committed_snapshot():
    counts = check_snapshot.counts(REPO / "data" / "snapshot")
    assert counts[("myciti", "routes")] > 0 and counts[("metrorail", "departures")] > 0


def test_refresh_workflow_is_weekly_guarded_and_tested():
    wf = (REPO / ".github" / "workflows" / "refresh-timetables.yml").read_text(encoding="utf-8")
    assert 'cron: "0 1 * * 1"' in wf and "workflow_dispatch" in wf
    guard = wf.index("tools/check_snapshot.py")
    scrape, tests, pr = (wf.index(s) for s in ("run_etl.py --all", "pytest -q", "gh pr create"))
    assert scrape < guard < tests < pr


# --- UCT expiry banner only where UCT is involved -----------------------------------------

def test_uct_banner_not_shown_on_myciti_only_searches(client):
    html = client.get("/search", params={
        "from_stop": "Civic Centre", "to_stop": "Table View", "day_type": "weekday",
    }).text
    assert "UCT shuttle timetable expired" not in html
    assert "UCT shuttle timetable expired" not in client.get("/stop/Civic%20Centre").text


def test_uct_banner_still_shown_for_uct_stops_when_expired(client):
    from fastapi_app.dependencies import get_connection
    from fastapi_app.services.uct_validity import uct_expiry_state

    _, warning = uct_expiry_state(get_connection())
    html = client.get("/stop/UC%20South").text
    assert ("UCT shuttle timetable expired" in html) == bool(warning)
