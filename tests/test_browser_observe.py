"""Passive browser/network-observation layer.

Proves the observation layer (1) ingests only *observed* traffic into the existing
attack-surface graph, (2) enforces scope fail-closed (out-of-scope traffic dropped),
(3) records object-reference candidates + auth observations without asserting a
vulnerability, (4) never persists authentication material, and (5) feeds the same
SurfaceStore the planner already reads. NO network access occurs anywhere here.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bbagent.browser import NetworkObservationIngestor, ingest_har, parse_har
from bbagent.browser.models import ObservedExchange
from bbagent.config.loader import load_program
from bbagent.config.models import ProgramConfig, ScopeConfig, ScopeKind, ScopeRule
from bbagent.program.manager import ProgramManager
from bbagent.surface.models import AuthIdentity
from bbagent.surface.store import SurfaceStore
from bbagent.storage.db import Database

TEMU_YAML = str(Path(__file__).resolve().parents[1] / "programs" / "temu.yaml")

# A secret that appears in the SYNTHETIC test HAR only; it must never be persisted.
SECRET_COOKIE = "session=SUPERSECRET_cookie_do_not_persist"


def _obs_program() -> ProgramManager:
    """A loopback-style test program (NOT Temu) for functional assertions."""
    return ProgramManager(ProgramConfig(
        name="obs-test", authorized=True,
        scope=ScopeConfig(in_scope=[ScopeRule(kind=ScopeKind.DOMAIN, value="app.example.test")]),
    ))


def _sample_har() -> dict:
    """Synthetic HAR fixture (fabricated test data; no real service, no request)."""
    return {"log": {"version": "1.2", "entries": [
        # in-scope HTML page, unauthenticated
        {"request": {"method": "GET", "url": "https://app.example.test/dashboard",
                     "headers": [{"name": "Accept", "value": "text/html"}]},
         "response": {"status": 200, "headers": [{"name": "Content-Type", "value": "text/html"}],
                      "content": {"mimeType": "text/html",
                                  "text": "<html><title>Dash</title><a href='/orders/1001'>o</a></html>"}}},
        # in-scope authenticated JSON API GET: path id + json body ids + a Cookie (secret!)
        {"request": {"method": "GET",
                     "url": "https://app.example.test/api/v1/orders/1001?expand=items",
                     "headers": [{"name": "Cookie", "value": SECRET_COOKIE},
                                 {"name": "Referer", "value": "https://app.example.test/dashboard"}]},
         "response": {"status": 200,
                      "headers": [{"name": "Content-Type", "value": "application/json"},
                                  {"name": "Server", "value": "nginx"}],
                      "content": {"mimeType": "application/json",
                                  "text": json.dumps({"order": {"id": 1001, "user_id": "u-42",
                                                                "token": "unused"}})}}},
        # in-scope JS asset
        {"request": {"method": "GET", "url": "https://app.example.test/static/app.js",
                     "headers": []},
         "response": {"status": 200,
                      "headers": [{"name": "Content-Type", "value": "application/javascript"}],
                      "content": {"mimeType": "application/javascript",
                                  "text": "fetch('/api/v1/profile')"}}},
        # OUT-OF-SCOPE host -> must be dropped (fail-closed)
        {"request": {"method": "GET", "url": "https://evil.example.com/steal", "headers": []},
         "response": {"status": 200, "headers": [], "content": {"text": "x"}}},
        # non-http -> skipped
        {"request": {"method": "GET", "url": "data:text/plain,hi", "headers": []},
         "response": {"status": 200, "headers": [], "content": {}}},
    ]}}


def _dump_all_surface_rows(db: Database) -> str:
    tables = ["surface_assets", "surface_endpoints", "surface_params",
              "surface_object_refs", "surface_auth_obs", "surface_js", "surface_apis"]
    chunks: list[str] = []
    for t in tables:
        for row in db.connection.execute(f"SELECT * FROM {t}").fetchall():
            chunks.append(" ".join(str(v) for v in tuple(row)))
    return "\n".join(chunks)


# --- HAR parsing --------------------------------------------------------------

def test_parse_har_reads_only_observed_entries():
    exchanges = parse_har(_sample_har())
    assert len(exchanges) == 5
    orders = next(e for e in exchanges if "/orders/1001" in e.url)
    assert orders.method == "GET"
    assert orders.response_content_type == "application/json"
    assert orders.source_page == "https://app.example.test/dashboard"
    assert orders.looks_authenticated() is True          # Cookie present
    dash = next(e for e in exchanges if e.url.endswith("/dashboard"))
    assert dash.looks_authenticated() is False


def test_parse_har_tolerates_garbage():
    assert parse_har("not json") == []
    assert parse_har({"log": {}}) == []


def test_parse_har_status_zero_becomes_none():
    har = {"log": {"entries": [
        {"request": {"method": "GET", "url": "https://app.example.test/x", "headers": []},
         "response": {"status": 0, "headers": [], "content": {}}}]}}
    assert parse_har(har)[0].status is None


# --- ingestion into the existing surface graph --------------------------------

@pytest.fixture
def ingested():
    db = Database(":memory:")
    surface = SurfaceStore(db)
    program = _obs_program()
    report = ingest_har(program, surface, _sample_har(),
                        default_identity=AuthIdentity.IDENTITY_A,
                        identity_map={"researcher": AuthIdentity.IDENTITY_A})
    yield db, surface, program, report
    db.close()


def test_counts_and_scope_filtering(ingested):
    _, _, _, report = ingested
    assert report.exchanges_seen == 5
    assert report.non_http_skipped == 1              # data: URL
    assert report.out_of_scope_dropped == 1          # evil.example.com
    assert report.in_scope == 3
    assert report.endpoints == 3
    assert report.js_assets == 1


def test_out_of_scope_never_recorded(ingested):
    _, surface, program, _ = ingested
    urls = [e.url for e in surface.list_endpoints(program.name)]
    assert all("evil.example.com" not in u for u in urls)
    assert all("app.example.test" in u for u in urls)


def test_object_ref_candidates_from_path_and_json(ingested):
    _, surface, program, _ = ingested
    orders = next(e for e in surface.list_endpoints(program.name) if "/orders/1001" in e.url)
    values = {(r.value, r.location) for r in surface.object_refs_for(orders.id)}
    assert ("1001", "path") in values          # path id
    assert ("1001", "json:id") in values       # json body id
    assert ("u-42", "json:user_id") in values  # json body foreign id
    # Every recorded object ref is a candidate, never an assertion.
    assert all(r.candidate for r in surface.object_refs_for(orders.id))


def test_endpoints_are_browser_sourced_and_confirmed(ingested):
    _, surface, program, _ = ingested
    eps = surface.list_endpoints(program.name)
    assert eps and all(e.source == "browser" and e.confirmed for e in eps)


def test_auth_observations_recorded_per_identity(ingested):
    _, surface, program, _ = ingested
    dash = next(e for e in surface.list_endpoints(program.name) if e.url.endswith("/dashboard"))
    orders = next(e for e in surface.list_endpoints(program.name) if "/orders/1001" in e.url)
    dash_obs = {o.identity for o in surface.auth_observations_for(dash.id)}
    orders_obs = {o.identity for o in surface.auth_observations_for(orders.id)}
    assert AuthIdentity.UNAUTHENTICATED.value in dash_obs
    assert AuthIdentity.IDENTITY_A.value in orders_obs           # authenticated traffic
    # auth_requirement is set conservatively from the unauthenticated 200 only.
    assert surface.get_endpoint(dash.id).auth_requirement == "none"


def test_no_auth_material_persisted(ingested):
    db, _, _, _ = ingested
    dump = _dump_all_surface_rows(db)
    assert "SUPERSECRET" not in dump
    assert SECRET_COOKIE not in dump
    assert "Cookie" not in dump and "cookie=" not in dump


def test_feeds_planner_reading_path(ingested):
    # The planner reads exactly these store methods; prove they return the graph.
    _, surface, program, _ = ingested
    eps = surface.list_endpoints(program.name)
    assert len(eps) == 3
    # At least one endpoint carries both a parameter and object-ref candidates.
    orders = next(e for e in eps if "/orders/1001" in e.url)
    assert any(p.name == "expand" for p in surface.parameters_for(orders.id))
    assert surface.object_refs_for(orders.id)


# --- fail-closed against the REAL Temu scope (synthetic HAR, no request) ------

def test_temu_scope_is_failclosed_on_unknown_subdomain():
    db = Database(":memory:")
    surface = SurfaceStore(db)
    temu = ProgramManager(load_program(TEMU_YAML))
    har = {"log": {"entries": [
        {"request": {"method": "GET", "url": "https://www.temu.com/", "headers": []},
         "response": {"status": 200, "headers": [{"name": "Content-Type", "value": "text/html"}],
                      "content": {"text": "<html></html>", "mimeType": "text/html"}}},
        # unknown subdomain is NOT in the exact-host scope -> dropped
        {"request": {"method": "GET", "url": "https://api.temu.com/v1/secret", "headers": []},
         "response": {"status": 200, "headers": [], "content": {"text": "{}"}}},
    ]}}
    report = ingest_har(temu, surface, har)
    assert report.in_scope == 1
    assert report.out_of_scope_dropped == 1
    urls = [e.url for e in surface.list_endpoints(temu.config.name)]
    assert urls == ["https://www.temu.com/"]
    db.close()


def test_ingestor_takes_no_http_client():
    # Structural guarantee: the ingestor is constructed without any HTTP client,
    # so it cannot issue a request. Discovery here is purely passive.
    surface = SurfaceStore(Database(":memory:"))
    ing = NetworkObservationIngestor(_obs_program(), surface)
    assert not hasattr(ing, "http")
    # An empty ingest does nothing and contacts nothing.
    rep = ing.ingest([])
    assert rep.in_scope == 0 and rep.exchanges_seen == 0
