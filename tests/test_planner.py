"""Unit tests for the deterministic planner: generation, prioritization, dedup,
dry-run, verified-feedback regeneration guard, and the LLM boundary.

No network: the surface graph is populated directly.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import pytest

from bbagent.planner import (
    DeterministicPlanner,
    LLMPlanner,
    PlanContext,
    PlanRunner,
    PlanStatus,
    RunStore,
    TestBudget,
    default_capabilities,
)
from bbagent.program.manager import ProgramManager
from bbagent.storage.db import Database
from bbagent.surface.store import SurfaceStore
from bbagent.urlutils import endpoint_key
from bbagent_lab.agent_config import build_lab_program

PROG = "Local Vulnerable Lab"


@pytest.fixture
def program():
    return ProgramManager(build_lab_program())


@pytest.fixture
def db():
    d = Database(":memory:")
    yield d
    d.close()


@pytest.fixture
def surface(db):
    return SurfaceStore(db)


def _seed(surface, url, *, object_refs=(), auth=None, params=(), auth_req="unknown"):
    ep = surface.upsert_endpoint(
        PROG, method="GET", url=url, path=urlsplit(url).path or "/",
        template_key=endpoint_key("GET", url), confirmed=True,
    )
    if auth_req != "unknown":
        surface.set_endpoint_auth_requirement(ep.id, auth_req)
    for value, kind in object_refs:
        surface.upsert_object_ref(PROG, endpoint_id=ep.id, value=value, kind=kind, location="path")
    for ident, code in (auth or {}).items():
        surface.record_auth_observation(PROG, endpoint_id=ep.id, identity=ident, status_code=code)
    for p in params:
        surface.upsert_parameter(PROG, endpoint_id=ep.id, name=p, location="query")
    return ep


def _ctx(program, surface, known=None):
    return PlanContext(program, surface, default_capabilities(), known or set())


def test_generation_requires_object_reference(program, surface):
    _seed(surface, "http://127.0.0.1:8000/api/health")  # no object ref
    queue = DeterministicPlanner().plan(_ctx(program, surface))
    assert queue == []


def test_generates_idor_hypothesis(program, surface):
    _seed(surface, "http://127.0.0.1:8000/api/notes/note-a1",
          object_refs=[("note-a1", "path_id")],
          auth={"unauthenticated": 401, "identity_a": 200, "identity_b": 200},
          auth_req="required")
    queue = DeterministicPlanner().plan(_ctx(program, surface))
    assert len(queue) == 1
    ph = queue[0]
    assert ph.vulnerability_class == "idor"
    assert ph.method == "GET"
    assert ph.required_auth_context == ["user_a", "user_b"]
    assert "object reference" in ph.reasoning
    assert ph.status is PlanStatus.PLANNED


def test_deterministic_prioritization(program, surface):
    # Rich endpoint (api + differing auth + required + params) outranks a plain one.
    _seed(surface, "http://127.0.0.1:8000/api/notes/1",
          object_refs=[("1", "numeric")],
          auth={"unauthenticated": 401, "identity_a": 200, "identity_b": 403},
          params=["q"], auth_req="required")
    _seed(surface, "http://127.0.0.1:8000/files/9",
          object_refs=[("9", "numeric")])  # plain: no auth obs, not api
    p = DeterministicPlanner()
    q1 = p.plan(_ctx(program, surface))
    q2 = p.plan(_ctx(program, surface))
    assert [h.endpoint for h in q1] == [h.endpoint for h in q2]  # reproducible
    assert q1[0].priority_score > q1[1].priority_score
    assert "/api/notes/1" in q1[0].endpoint


def test_known_plan_keys_prevents_regeneration(program, surface):
    _seed(surface, "http://127.0.0.1:8000/api/notes/note-a1",
          object_refs=[("note-a1", "path_id")], auth={"identity_a": 200, "identity_b": 200})
    q = DeterministicPlanner().plan(_ctx(program, surface))
    assert len(q) == 1
    key = q[0].plan_key
    # Once known (e.g. already verified), it must not be regenerated.
    q2 = DeterministicPlanner().plan(_ctx(program, surface, known={key}))
    assert q2 == []


async def test_dry_run_executes_nothing(program, db, surface):
    _seed(surface, "http://127.0.0.1:8000/api/notes/note-a1",
          object_refs=[("note-a1", "path_id")], auth={"identity_a": 200, "identity_b": 200})
    runner = PlanRunner(program, db, surface)  # no http/evidence
    summary = await runner.run(dry_run=True)
    assert summary.generated == 1
    assert summary.executed == 0
    # Persisted as PLANNED.
    hyps = RunStore(db).hypotheses_for_run(summary.run_id)
    assert hyps and hyps[0]["status"] == "planned"


async def test_run_requires_http_when_not_dry(program, db, surface):
    _seed(surface, "http://127.0.0.1:8000/api/notes/note-a1",
          object_refs=[("note-a1", "path_id")], auth={"identity_a": 200, "identity_b": 200})
    runner = PlanRunner(program, db, surface)  # no http/evidence
    with pytest.raises(RuntimeError):
        await runner.run(dry_run=False)


# --- LLM boundary -------------------------------------------------------------

class _RecordingReasoner:
    """A fake LLM reasoner: it only ever receives serialized data and returns order."""

    def __init__(self):
        self.received = None

    def rank(self, candidates):
        self.received = candidates
        return [c["hypothesis_id"] for c in reversed(candidates)]


def test_llm_planner_only_reorders_data(program, surface):
    _seed(surface, "http://127.0.0.1:8000/api/notes/1", object_refs=[("1", "numeric")],
          auth={"identity_a": 200, "identity_b": 403}, params=["q"], auth_req="required")
    _seed(surface, "http://127.0.0.1:8000/files/9", object_refs=[("9", "numeric")])
    reasoner = _RecordingReasoner()
    det = DeterministicPlanner().plan(_ctx(program, surface))
    llm = LLMPlanner(reasoner=reasoner).plan(_ctx(program, surface))

    # Same set of hypotheses, reversed order per the reasoner.
    assert {h.plan_key for h in llm} == {h.plan_key for h in det}
    assert [h.plan_key for h in llm] == [h.plan_key for h in reversed(det)]
    # The reasoner received DATA ONLY (plain dicts), never objects/clients.
    assert all(isinstance(c, dict) for c in reasoner.received)
    assert "endpoint" in reasoner.received[0] and "hypothesis_id" in reasoner.received[0]


def test_llm_planner_falls_back_on_bad_reasoner(program, surface):
    _seed(surface, "http://127.0.0.1:8000/api/notes/1", object_refs=[("1", "numeric")],
          auth={"identity_a": 200, "identity_b": 403})

    class Bad:
        def rank(self, candidates):
            raise RuntimeError("boom")

    out = LLMPlanner(reasoner=Bad()).plan(_ctx(program, surface))
    assert len(out) == 1  # deterministic fallback, no crash
