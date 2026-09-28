"""Unit tests for the SurfaceStore: upsert dedup, merges, relationships, aggregate."""

from __future__ import annotations

import pytest

from bbagent.storage.db import Database
from bbagent.surface.store import SurfaceStore
from bbagent.urlutils import endpoint_key


@pytest.fixture
def surface():
    db = Database(":memory:")
    yield SurfaceStore(db)
    db.close()


PROG = "P"


def test_asset_dedup_and_tech_merge(surface):
    a1 = surface.upsert_asset(PROG, scheme="http", hostname="127.0.0.1", port=8000,
                              url="http://127.0.0.1:8000/", status=200, technologies=["WSGIServer"])
    a2 = surface.upsert_asset(PROG, scheme="http", hostname="127.0.0.1", port=8000,
                              url="http://127.0.0.1:8000/", status=200, technologies=["Python/3"])
    assert a1.id == a2.id
    assert set(a2.technologies) == {"WSGIServer", "Python/3"}
    assert len(surface.list_assets(PROG)) == 1


def test_endpoint_dedup_by_template(surface):
    u1 = "http://127.0.0.1:8000/api/notes/note-a1"
    u2 = "http://127.0.0.1:8000/api/notes/note-b1"
    e1 = surface.upsert_endpoint(PROG, method="GET", url=u1, path="/api/notes/note-a1",
                                 template_key=endpoint_key("GET", u1), status_code=200)
    e2 = surface.upsert_endpoint(PROG, method="GET", url=u2, path="/api/notes/note-b1",
                                 template_key=endpoint_key("GET", u2), status_code=404)
    assert e1.id == e2.id
    assert set(surface.get_endpoint(e1.id).status_codes) == {200, 404}
    assert len(surface.list_endpoints(PROG)) == 1


def test_parameter_objref_authobs_dedup_and_merge(surface):
    u = "http://127.0.0.1:8000/api/profile/1001"
    ep = surface.upsert_endpoint(PROG, method="GET", url=u, path="/api/profile/1001",
                                 template_key=endpoint_key("GET", u))
    surface.upsert_parameter(PROG, endpoint_id=ep.id, name="q", location="query")
    surface.upsert_parameter(PROG, endpoint_id=ep.id, name="q", location="query")
    assert len(surface.parameters_for(ep.id)) == 1

    surface.upsert_object_ref(PROG, endpoint_id=ep.id, value="1001", kind="numeric", location="path")
    surface.upsert_object_ref(PROG, endpoint_id=ep.id, value="1001", kind="numeric", location="path")
    assert len(surface.object_refs_for(ep.id)) == 1

    surface.record_auth_observation(PROG, endpoint_id=ep.id, identity="identity_a", status_code=200)
    surface.record_auth_observation(PROG, endpoint_id=ep.id, identity="identity_a", status_code=200)
    obs = surface.auth_observations_for(ep.id)
    assert len(obs) == 1
    assert obs[0].status_codes == [200]


def test_relationships_and_aggregate(surface):
    a = surface.upsert_asset(PROG, scheme="http", hostname="127.0.0.1", port=8000,
                             url="http://127.0.0.1:8000/site", status=200)
    u = "http://127.0.0.1:8000/api/search?q=1"
    ep = surface.upsert_endpoint(PROG, method="GET", url=u, path="/api/search",
                                 template_key=endpoint_key("GET", u), query_params=["q"])
    surface.add_relationship(PROG, src_type="asset", src_id=a.id, dst_type="endpoint",
                             dst_id=ep.id, rel="contains")
    surface.add_relationship(PROG, src_type="asset", src_id=a.id, dst_type="endpoint",
                             dst_id=ep.id, rel="contains")  # dedup
    rels = surface.relationships(PROG, src_type="asset", src_id=a.id)
    assert len(rels) == 1

    surf = surface.attack_surface(PROG)
    assert surf["program"] == PROG
    assert len(surf["assets"]) == 1
    assert len(surf["endpoints"]) == 1
    assert len(surf["relationships"]) == 1
    # API mirror is separate only when the mapper records it; store doesn't auto-mirror.
    assert isinstance(surf["api_endpoints"], list)
