"""Wolt program policy: exact representation of the supplied published rules,
fail-closed validation, and dry-run enforcement. No network is ever performed.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from bbagent import cli
from bbagent.config.loader import load_program
from bbagent.config.models import PolicyBudget
from bbagent.http.client import AuthorizedHTTPClient
from bbagent.policy import ProgramPolicyEngine
from bbagent.policy.validation import simulate, validate_policy
from bbagent.program.manager import ProgramManager
from bbagent.scope.engine import ScopeEngine
from bbagent.tools import ToolContext, ToolRequest, ToolRouter, default_tools
from bbagent_lab.agent_config import ENV_TOKEN_A, ENV_TOKEN_B
from bbagent_lab.data import USERS
from bbagent_lab.simulator import build_simulator_manager

WOLT = str(Path(__file__).resolve().parents[1] / "programs" / "wolt.yaml")


@pytest.fixture
def wolt():
    return ProgramManager(load_program(WOLT))


@pytest.fixture
def scope(wolt):
    return ScopeEngine(wolt.config.scope)


class CountingTransport(httpx.MockTransport):
    def __init__(self):
        self.calls = 0

        def handler(request):
            self.calls += 1
            return httpx.Response(200, text="{}", headers={"content-type": "application/json"})
        super().__init__(handler)


# --- scope: every explicit in-scope asset -------------------------------------

@pytest.mark.parametrize("url", [
    "https://wolt.com/en/",
    "https://restaurant-api.wolt.com/v1/venues",
    "https://ops.wolt.com/x",
    "https://merchant.wolt.com/dashboard",
    "https://drive.wolt.com/x",
    "https://corporate.wolt.com/x",
    "https://authentication.wolt.com/login",
    "https://anything.wolt.com/x",          # *.wolt.com wildcard
])
def test_in_scope_assets_allowed(scope, url):
    assert scope.is_allowed(url) is True


# --- scope: every explicit exclusion ------------------------------------------

@pytest.mark.parametrize("url", [
    "https://wolt.atlassian.net/x",
    "https://press.wolt.com/x",
    "https://links.wolt.com/x",
    "https://wolt.typeform.com/x",
    "https://gettest.wolt.com/x",
    "https://sub.pipedrive.com/x",                # *.pipedrive.com
    "https://blog.wolt.com/anything",             # excluded host beats *.wolt.com
    "https://wolt.com/en/wolt-for-work-contact-request",
    "https://restaurant-api.wolt.com/v1/waw-api/corporate-leads",
    "https://merchant.wolt.com/app/partner-with-wolt",
    "https://merchant.wolt.com/api/merchant-onboarding/merchant-admin/inbound-merchant",
    "https://merchant-onboarding-service.wolt.com/merchant-admin/inbound-merchant",
])
def test_excluded_assets_denied(scope, url):
    assert scope.is_allowed(url) is False


def test_excluded_host_precedence(scope):
    # blog.wolt.com matches *.wolt.com but is explicitly excluded -> denied.
    assert scope.is_allowed("https://blog.wolt.com/wp-login.php") is False
    assert scope.check("https://blog.wolt.com/x").reason.startswith("matched exclusion")


def test_excluded_path_precedence(scope):
    # merchant.wolt.com is in scope, but the specific excluded path is denied.
    assert scope.is_allowed("https://merchant.wolt.com/dashboard") is True
    assert scope.is_allowed("https://merchant.wolt.com/app/partner-with-wolt") is False


def test_forbidden_post_endpoints_denied_for_any_method(scope):
    # Represented as full URL exclusions -> ALL methods (incl. POST) are denied.
    for url in [
        "https://restaurant-api.wolt.com/v1/waw-api/corporate-leads",
        "https://merchant.wolt.com/api/merchant-onboarding/merchant-admin/inbound-merchant",
        "https://merchant-onboarding-service.wolt.com/merchant-admin/inbound-merchant",
    ]:
        assert scope.is_allowed(url) is False


# --- required header / identities represented ---------------------------------

def test_required_research_header_is_env_ref(wolt):
    assert wolt.config.required_header_refs == {"X-HackerOne-Research": "BBAGENT_H1_USERNAME"}
    # Not hardcoded as a literal value anywhere.
    assert "X-HackerOne-Research" not in wolt.config.required_headers


def test_identities_courier_merchant_absent(wolt):
    labels = {a.label for a in wolt.config.test_accounts}
    assert labels == {"consumer_test"}
    assert "courier" not in labels and "merchant" not in labels


def test_out_of_scope_categories_represented(wolt):
    fa = set(wolt.config.forbidden_actions)
    for cat in ("payment-processors", "dos", "brute-force", "social-engineering",
                "mass-entity-creation", "web:cors-without-impact", "mobile:lack-of-obfuscation"):
        assert cat in fa


# --- validation: NOT READY, fail closed ---------------------------------------

def test_policy_check_not_ready(wolt):
    report = validate_policy(wolt)
    assert report.ready is False
    assert report.dry_run_only is True
    # The mandated ambiguities are all present.
    joined = " ".join(report.ambiguities)
    assert "allowed_tools" in joined and "allowed_vulnerability_classes" in joined
    assert "allowed_methods" in joined and "request_budget" in joined
    # Human-review items include the un-modellable rules.
    review = " ".join(report.needs_human_review)
    assert "blog.wolt.com" in review and "venue-data-scoping" in review


def test_cli_policy_check_exit_1():
    assert cli.main(["policy-check", WOLT]) == 1


# --- dry-run: no action executes ----------------------------------------------

def test_simulation_denies_all_and_never_executes(wolt):
    actions = [
        {"tool": "http", "method": "GET", "url": "https://wolt.com/en/", "identity": "consumer_test"},
        {"tool": "http", "method": "GET", "url": "https://wolt.atlassian.net/x"},
        {"tool": "http", "method": "POST",
         "url": "https://restaurant-api.wolt.com/v1/waw-api/corporate-leads"},
        {"tool": "http", "method": "GET", "url": "https://restaurant-api.wolt.com/v1/x", "identity": "courier"},
        {"tool": "http", "method": "GET", "url": "https://restaurant-api.wolt.com/v1/x", "identity": "merchant"},
    ]
    decisions = simulate(wolt, actions)
    assert all(d.allowed is False for d in decisions)      # fail-closed (no tools/methods granted)
    assert all(d.would_execute is False for d in decisions)  # dry-run: nothing runs
    # Scope classification is still surfaced for transparency.
    assert decisions[0].scope == "in_scope" and decisions[1].scope == "excluded"


async def test_dry_run_blocks_execution_via_router(wolt):
    t = CountingTransport()
    async with AuthorizedHTTPClient(wolt.config, transport=t) as http:
        router = ToolRouter(default_tools(), ProgramPolicyEngine(wolt),
                            ToolContext(program=wolt, http=http))
        res = await router.dispatch(ToolRequest(
            tool="http", arguments={"url": "https://wolt.com/en/", "method": "GET"}))
    assert res.success is False
    assert t.calls == 0   # zero requests sent to Wolt


# --- generic rule enforcement (on a program that reaches the http gates) ------

def _sim_with(monkeypatch, **over):
    monkeypatch.setenv(ENV_TOKEN_A, USERS["user_a"].token)
    monkeypatch.setenv(ENV_TOKEN_B, USERS["user_b"].token)
    prog = build_simulator_manager()
    for k, v in over.items():
        setattr(prog.config, k, v)
    return prog


def test_env_ref_required_header_cannot_be_set(monkeypatch):
    prog = _sim_with(monkeypatch, required_header_refs={"X-HackerOne-Research": "BBAGENT_H1_USERNAME"})
    d = ProgramPolicyEngine(prog).evaluate(ToolRequest(
        tool="http", arguments={"url": "http://127.0.0.1:8000/x", "method": "GET",
                                "headers": {"X-HackerOne-Research": "attacker"}},
        target="http://127.0.0.1:8000/x"))
    assert d.allowed is False and d.matched_rule == "required_headers"


def test_forbidden_action_denied(monkeypatch):
    prog = _sim_with(monkeypatch, forbidden_actions=["dos"])
    d = ProgramPolicyEngine(prog).evaluate(ToolRequest(
        tool="http", arguments={"url": "http://127.0.0.1:8000/x", "method": "GET"},
        target="http://127.0.0.1:8000/x", requested_action="dos"))
    assert d.allowed is False and d.matched_rule == "forbidden_actions"
