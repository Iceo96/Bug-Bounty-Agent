"""Priority 1: mechanical data-scoping — only authorized test entities may be
referenced; anything else is denied before transport."""

from __future__ import annotations

import httpx
import pytest

from bbagent.http.client import AuthorizedHTTPClient
from bbagent.policy import ProgramPolicyEngine
from bbagent.tools import ToolContext, ToolRequest, ToolRouter, default_tools
from bbagent_lab.wolt_sim import (
    BASE, CONSUMER_TOKEN, CONSUMER_USER_ID, ENV_CONSUMER, ENV_OTHER, H1_ENV, OTHER_TOKEN,
    VENUE_ID, WoltMockTransport, build_wolt_sim_program,
)

VENUE_URL = f"https://wolt.com/en/fin/helsinki/venue/test-{VENUE_ID}-sh0p"


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv(ENV_CONSUMER, CONSUMER_TOKEN)
    monkeypatch.setenv(ENV_OTHER, OTHER_TOKEN)
    monkeypatch.setenv(H1_ENV, "researcher-handle")


async def _dispatch(program, transport, **req):
    async with AuthorizedHTTPClient(program.config, transport=transport) as http:
        router = ToolRouter(default_tools(), ProgramPolicyEngine(program),
                            ToolContext(program=program, http=http))
        return await router.dispatch(ToolRequest(**req))


async def test_authorized_entity_proceeds(env):
    program = build_wolt_sim_program(enforce_data_scope=True)
    t = WoltMockTransport()
    res = await _dispatch(program, t, tool="http", identity="consumer_test",
                          arguments={"url": f"{BASE}/sim/v1/orders/{CONSUMER_USER_ID}", "method": "GET"})
    assert res.success is True and t.calls == 1   # authorized id -> reached transport


@pytest.mark.parametrize("url", [
    f"{BASE}/sim/v1/orders/999999999999999",                       # arbitrary user_id
    f"{BASE}/sim/v1/venues/aaaaaaaaaaaaaaaaaaaaaaaa",               # arbitrary venue_id
    "https://wolt.com/en/fin/helsinki/venue/test-99999999-sh0p",   # unauthorized venue URL
])
async def test_unauthorized_data_reference_denied(env, url):
    program = build_wolt_sim_program(enforce_data_scope=True)
    t = WoltMockTransport()
    res = await _dispatch(program, t, tool="http", identity="consumer_test",
                          arguments={"url": url, "method": "GET"})
    assert res.success is False and res.metadata.get("matched_rule") == "data_scope"
    assert t.calls == 0   # denied before transport


async def test_authorized_venue_url_is_exempt(env):
    program = build_wolt_sim_program(enforce_data_scope=True)
    t = WoltMockTransport()
    res = await _dispatch(program, t, tool="http", identity="consumer_test",
                          arguments={"url": VENUE_URL, "method": "GET"})
    assert res.success is True   # matches an authorized URL prefix -> proceeds


async def test_llm_cannot_smuggle_a_different_identifier(env):
    # The LLM supplies a different object id in the URL -> denied, zero transport.
    program = build_wolt_sim_program(enforce_data_scope=True)
    t = WoltMockTransport()
    res = await _dispatch(program, t, tool="http", identity="consumer_test",
                          arguments={"url": f"{BASE}/sim/v1/orders/deadbeefdeadbeefdeadbeef",
                                     "method": "GET"})
    assert res.success is False and t.calls == 0


def test_object_ref_extraction():
    from bbagent.policy.engine import _object_refs_in_url
    refs = _object_refs_in_url(f"{BASE}/sim/v1/orders/{CONSUMER_USER_ID}?id=42&q=probe")
    assert CONSUMER_USER_ID in refs and "42" in refs
    assert "probe" not in refs and "orders" not in refs
