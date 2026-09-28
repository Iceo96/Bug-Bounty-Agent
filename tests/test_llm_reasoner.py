"""Tests for the LLM Reasoner: validation, rejection paths, fallback, filtering.

No real LLM is used — a fake completion function returns crafted responses.
"""

from __future__ import annotations

import json

import pytest

from bbagent.config.models import LLMConfig, ProgramConfig, ScopeConfig, ScopeKind, ScopeRule
from bbagent.llm import sanitize_candidate, scrub_text
from bbagent.llm.reasoner import LLMReasoner, ReasonerRejected
from bbagent.planner import (
    DeterministicPlanner,
    LLMPlanner,
    PlanContext,
    default_capabilities,
)
from bbagent.program.manager import ProgramManager
from bbagent.storage.db import Database
from bbagent.surface.store import SurfaceStore
from bbagent.urlutils import endpoint_key
from bbagent_lab.agent_config import build_lab_program


class FakeComplete:
    """Records the prompt it was given and returns a canned response."""

    def __init__(self, response: str):
        self.response = response
        self.prompt: str | None = None

    def __call__(self, prompt: str) -> str:
        self.prompt = prompt
        return self.response


def _cand(hid, endpoint="http://127.0.0.1:8000/api/notes/1", target="127.0.0.1", method="GET"):
    return {
        "hypothesis_id": hid,
        "target": target,
        "endpoint": endpoint,
        "method": method,
        "vulnerability_class": "idor",
        "reasoning": "object reference; multiple identities",
        "expected_signal": "user_b receives user_a's object",
        "required_auth_context": ["user_a", "user_b"],
        "priority": "HIGH",
        "priority_score": 120,
    }


def _reasoner(response: str, **cfg):
    return LLMReasoner(LLMConfig(enabled=True, **cfg), FakeComplete(response))


def _ranking(*items) -> str:
    return json.dumps({"ranking": list(items), "overall_reasoning": "because"})


# --- validation ---------------------------------------------------------------

def test_valid_reorder():
    c1, c2 = _cand("a"), _cand("b", endpoint="http://127.0.0.1:8000/api/profile/2")
    resp = _ranking({"hypothesis_id": "b", "rank": 1}, {"hypothesis_id": "a", "rank": 2})
    order = _reasoner(resp).rank([c1, c2])
    assert order == ["b", "a"]


def test_malformed_response_rejected():
    with pytest.raises(ReasonerRejected):
        _reasoner("this is not json at all").rank([_cand("a")])


def test_invented_candidate_rejected():
    resp = _ranking({"hypothesis_id": "does-not-exist", "rank": 1})
    with pytest.raises(ReasonerRejected):
        _reasoner(resp).rank([_cand("a")])


def test_modified_endpoint_rejected():
    resp = _ranking({"hypothesis_id": "a", "rank": 1, "endpoint": "http://evil.com/x"})
    with pytest.raises(ReasonerRejected):
        _reasoner(resp).rank([_cand("a")])


def test_modified_target_rejected():
    resp = _ranking({"hypothesis_id": "a", "rank": 1, "target": "evil.com"})
    with pytest.raises(ReasonerRejected):
        _reasoner(resp).rank([_cand("a")])


def test_modified_method_rejected():
    resp = _ranking({"hypothesis_id": "a", "rank": 1, "method": "DELETE"})
    with pytest.raises(ReasonerRejected):
        _reasoner(resp).rank([_cand("a")])


def test_faithful_echo_is_accepted():
    c = _cand("a")
    resp = _ranking({"hypothesis_id": "a", "rank": 1, "endpoint": c["endpoint"],
                     "target": c["target"], "method": "get"})
    assert _reasoner(resp).rank([c]) == ["a"]


def test_max_candidates_truncation():
    cands = [_cand(f"h{i}", endpoint=f"http://127.0.0.1:8000/api/x/{i}") for i in range(5)]
    r = _reasoner(_ranking({"hypothesis_id": "h0", "rank": 1}), max_candidates=2)
    # Only the first 2 are known; if the model ranked h0 it's fine, unknown ids rejected.
    order = r.rank(cands)
    assert order == ["h0"]


# --- sensitive information filtering ------------------------------------------

def test_scrub_text_redacts_tokens():
    assert "[REDACTED]" in scrub_text("use Bearer abcdef123456 now")
    assert "[REDACTED]" in scrub_text("token tok_test_a_11111111 here")
    assert "hello world" == scrub_text("hello world")


def test_sanitize_drops_secret_keys_and_scrubs_values():
    dirty = {
        "hypothesis_id": "a",
        "endpoint": "http://127.0.0.1:8000/api/notes/1",
        "authorization": "Bearer tok_test_a_11111111",   # secret key -> dropped
        "required_inputs": {"token": "tok_test_a_11111111"},  # dropped
        "reasoning": "auth header Bearer tok_test_a_11111111 leaked",  # scrubbed
    }
    clean = sanitize_candidate(dirty)
    assert "authorization" not in clean
    assert "required_inputs" not in clean
    assert "[REDACTED]" in clean["reasoning"]
    assert "tok_test_a" not in json.dumps(clean)


def test_prompt_contains_no_secrets():
    dirty = _cand("a")
    dirty["reasoning"] = "leaked Bearer tok_test_a_11111111"
    dirty["authorization"] = "Bearer tok_test_a_11111111"
    fake = FakeComplete(_ranking({"hypothesis_id": "a", "rank": 1}))
    LLMReasoner(LLMConfig(enabled=True), fake).rank([dirty])
    assert "tok_test_a_11111111" not in fake.prompt
    assert "authorization" not in fake.prompt.lower()


# --- config -------------------------------------------------------------------

def test_llm_disabled_by_default():
    cfg = ProgramConfig(
        name="X", authorized=True,
        scope=ScopeConfig(in_scope=[ScopeRule(kind=ScopeKind.DOMAIN, value="a.com")]),
    )
    assert cfg.llm.enabled is False
    assert cfg.llm.fallback_to_deterministic is True


# --- planner integration + fallback ------------------------------------------

@pytest.fixture
def surface_ctx():
    db = Database(":memory:")
    surface = SurfaceStore(db)
    program = ProgramManager(build_lab_program())
    for path, val in (("/api/notes/1", "1"), ("/api/profile/2", "2")):
        url = "http://127.0.0.1:8000" + path
        ep = surface.upsert_endpoint("Local Vulnerable Lab", method="GET", url=url, path=path,
                                     template_key=endpoint_key("GET", url), confirmed=True)
        surface.upsert_object_ref("Local Vulnerable Lab", endpoint_id=ep.id, value=val,
                                  kind="numeric", location="path")
        surface.record_auth_observation("Local Vulnerable Lab", endpoint_id=ep.id,
                                        identity="identity_a", status_code=200)
    ctx = PlanContext(program, surface, default_capabilities(), set())
    yield ctx
    db.close()


def test_llmplanner_reorders_via_reasoner(surface_ctx):
    det = DeterministicPlanner().plan(surface_ctx)
    assert len(det) == 2
    # Reasoner ranks them in reverse of deterministic order.
    resp = _ranking(
        {"hypothesis_id": det[1].hypothesis_id, "rank": 1},
        {"hypothesis_id": det[0].hypothesis_id, "rank": 2},
    )
    planner = LLMPlanner(reasoner=_reasoner(resp))
    out = planner.plan(surface_ctx)
    assert [h.hypothesis_id for h in out] == [det[1].hypothesis_id, det[0].hypothesis_id]


def test_llmplanner_falls_back_on_malformed(surface_ctx):
    det = DeterministicPlanner().plan(surface_ctx)
    planner = LLMPlanner(reasoner=_reasoner("garbage"), fallback=True)
    out = planner.plan(surface_ctx)
    assert [h.hypothesis_id for h in out] == [h.hypothesis_id for h in det]  # deterministic order


def test_llmplanner_no_fallback_raises(surface_ctx):
    planner = LLMPlanner(reasoner=_reasoner("garbage"), fallback=False)
    with pytest.raises(Exception):
        planner.plan(surface_ctx)
