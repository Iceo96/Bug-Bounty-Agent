"""Integration tests for the attack-surface mapper against the local lab.

Real localhost socket; loopback only. Exercises manifest discovery, HTML
crawling, JavaScript discovery, API/param/object-ref extraction, auth-context
tracking, deduplication, and scope enforcement.
"""

from __future__ import annotations

import pytest

from bbagent.http.client import AuthorizedHTTPClient, RequestBlocked
from bbagent.program.manager import ProgramManager
from bbagent.recon import AttackSurfaceMapper
from bbagent.storage.db import Database
from bbagent.surface.models import AuthIdentity
from bbagent.surface.store import SurfaceStore
from bbagent.config.models import ScopeKind, ScopeRule
from bbagent_lab.agent_config import ENV_TOKEN_A, ENV_TOKEN_B, build_lab_program
from bbagent_lab.data import USERS
from bbagent_lab.server import BackgroundLab

PROG = "Local Vulnerable Lab"


@pytest.fixture
def lab():
    with BackgroundLab() as server:
        yield server


@pytest.fixture
def program(monkeypatch):
    monkeypatch.setenv(ENV_TOKEN_A, USERS["user_a"].token)
    monkeypatch.setenv(ENV_TOKEN_B, USERS["user_b"].token)
    return ProgramManager(build_lab_program())


@pytest.fixture
def surface():
    db = Database(":memory:")
    yield SurfaceStore(db)
    db.close()


async def _map(program, surface, lab, *, crawl=True):
    async with AuthorizedHTTPClient(program.config) as http:
        mapper = AttackSurfaceMapper(program, http, surface)
        await mapper.map_manifest(lab.base_url.rstrip("/") + "/")
        if crawl:
            await mapper.crawl(lab.base_url.rstrip("/") + "/site")


async def test_asset_discovery(program, surface, lab):
    await _map(program, surface, lab)
    urls = {a.url for a in surface.list_assets(PROG)}
    assert lab.base_url.rstrip("/") + "/" in urls          # manifest page
    assert lab.base_url.rstrip("/") + "/site" in urls       # crawled HTML page
    assert any(u.endswith("/site/about") for u in urls)


async def test_endpoint_discovery_and_api(program, surface, lab):
    await _map(program, surface, lab)
    eps = surface.list_endpoints(PROG)
    paths = {e.path for e in eps}
    assert "/api/notes/note-a1" in paths                    # from manifest
    assert "/api/profile/1001" in paths
    assert any(p.startswith("/site") for p in paths)        # from crawl
    assert any(e.path == "/api/search" for e in eps)        # from a form
    # API endpoints tracked separately.
    apis = surface.list_api_endpoints(PROG)
    assert any(a.path == "/api/notes/{id}" for a in apis)


async def test_javascript_discovery(program, surface, lab):
    await _map(program, surface, lab)
    js = surface.list_js_assets(PROG)
    assert len(js) == 1
    assert js[0].url.endswith("/static/app.js")
    assert len(js[0].sha256) == 64
    assert js[0].size > 0


async def test_api_candidate_and_param_extraction_from_js(program, surface, lab):
    await _map(program, surface, lab)
    eps = surface.list_endpoints(PROG)
    # Candidate endpoint discovered from JS (unconfirmed until verified).
    v1 = [e for e in eps if e.path == "/api/v1/users"]
    assert v1, "expected /api/v1/users candidate from JS"
    assert v1[0].confirmed is False
    assert v1[0].source == "javascript"
    names = {p.name for p in surface.parameters_for(v1[0].id)}
    assert {"role", "limit", "sort"} <= names

    # Form parameters extracted from HTML.
    search = [e for e in eps if e.path == "/api/search"][0]
    form_params = {p.name for p in surface.parameters_for(search.id)}
    assert {"q", "page", "limit"} <= form_params


async def test_authentication_context_tracking(program, surface, lab):
    await _map(program, surface, lab)
    notes = [e for e in surface.list_endpoints(PROG) if e.path == "/api/notes/note-a1"][0]
    obs = {o.identity: o.status_codes for o in surface.auth_observations_for(notes.id)}
    assert obs.get(AuthIdentity.UNAUTHENTICATED.value) == [401]
    assert obs.get(AuthIdentity.IDENTITY_A.value) == [200]
    assert obs.get(AuthIdentity.IDENTITY_B.value) == [200]  # vulnerable: B also 200
    assert notes.auth_requirement == "required"

    profile = [e for e in surface.list_endpoints(PROG) if e.path == "/api/profile/1001"][0]
    pobs = {o.identity: o.status_codes for o in surface.auth_observations_for(profile.id)}
    assert pobs.get(AuthIdentity.IDENTITY_A.value) == [200]
    assert pobs.get(AuthIdentity.IDENTITY_B.value) == [403]  # protected: B forbidden


async def test_object_reference_detection(program, surface, lab):
    await _map(program, surface, lab)
    profile = [e for e in surface.list_endpoints(PROG) if e.path == "/api/profile/1001"][0]
    refs = surface.object_refs_for(profile.id)
    kinds = {(r.value, r.kind) for r in refs}
    assert ("1001", "numeric") in kinds        # path id
    assert any(r.kind == "json_id" for r in refs)  # id from JSON body
    # Candidates only — never asserted as vulnerabilities.
    assert all(r.candidate for r in refs)


async def test_deduplication_across_runs(program, surface, lab):
    await _map(program, surface, lab)
    a1 = len(surface.list_assets(PROG))
    e1 = len(surface.list_endpoints(PROG))
    await _map(program, surface, lab)  # run again
    assert len(surface.list_assets(PROG)) == a1
    assert len(surface.list_endpoints(PROG)) == e1


async def test_loopback_only(program, surface, lab):
    await _map(program, surface, lab)
    for a in surface.list_assets(PROG):
        assert a.hostname in {"127.0.0.1", "localhost"}
    for e in surface.list_endpoints(PROG):
        assert "127.0.0.1" in e.url or "localhost" in e.url


async def test_scope_enforcement_refuses_external(program, surface, lab):
    async with AuthorizedHTTPClient(program.config) as http:
        mapper = AttackSurfaceMapper(program, http, surface)
        with pytest.raises(RequestBlocked):
            await mapper.map_manifest("http://example.com/manifest")
        with pytest.raises(RequestBlocked):
            await mapper.crawl("http://example.com/")


async def test_excluded_target_is_not_recorded(program, surface, lab):
    # Exclude the /site/about page explicitly; the mapper must skip it.
    about = lab.base_url.rstrip("/") + "/site/about"
    program.config.scope.excluded.append(ScopeRule(kind=ScopeKind.URL_PREFIX, value=about))
    await _map(program, surface, lab)
    urls = {a.url for a in surface.list_assets(PROG)}
    assert about not in urls
    assert lab.base_url.rstrip("/") + "/site" in urls  # the rest still crawled
