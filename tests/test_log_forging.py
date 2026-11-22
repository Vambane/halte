"""Request input cannot forge log lines (November 2026 live audit).

A stop name like "Fake\\n2026-11-19 09:00:00 - ... - ERROR - FORGED" used to
be logged with an f-string, writing a convincing fake ERROR line into the
production log. Stop and search inputs are now logged with %r.
"""
from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

FORGED = "Fake\n2026-11-19 09:00:00,000 - fastapi_app.main - ERROR - FORGED LOG LINE"


@pytest.fixture(scope="module")
def client():
    from fastapi_app.main import app

    with TestClient(app) as c:
        yield c


def _messages(caplog, logger_name: str) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == logger_name]


def test_stop_name_newline_stays_on_one_log_line(client, caplog):
    with caplog.at_level(logging.INFO, logger="fastapi_app.routes.stop"):
        client.get("/stop/" + FORGED.replace("\n", "%0A"))
    messages = _messages(caplog, "fastapi_app.routes.stop")
    assert any("FORGED LOG LINE" in m for m in messages)
    assert all("\n" not in m for m in messages)


def test_search_stop_names_newline_stays_on_one_log_line(client, caplog):
    with caplog.at_level(logging.INFO, logger="fastapi_app.routes.search"):
        client.get("/search", params={"from_stop": FORGED, "to_stop": "Civic Centre"})
    messages = _messages(caplog, "fastapi_app.routes.search")
    assert any("FORGED LOG LINE" in m for m in messages)
    assert all("\n" not in m for m in messages)
