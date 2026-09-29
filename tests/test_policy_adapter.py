"""Real-program policy adapter: validation (fail-closed) + dry-run simulation.

No network is ever performed. Proves that dry-run permanently prevents execution
and that ambiguous/missing rules make a program NOT READY.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from bbagent import cli
from bbagent.config.models import (
    PolicyBudget, ProgramConfig, ScopeConfig, ScopeKind, ScopeRule, TestAccount, TestingRestrictions,
)
from bbagent.http.client import AuthorizedHTTPClient
from bbagent.policy import ProgramPolicyEngine
from bbagent.policy.validation import simulate, validate_policy
from bbagent.program.manager import ProgramManager
from bbagent.tools import ToolContext, ToolRequest, ToolRouter, default_tools
from bbagent_lab.agent_config import ENV_TOKEN_A, ENV_TOKEN_B
from bbagent_lab.data import USERS
from bbagent_lab.simulator import build_simulator_manager

ROOT = Path(__file__).resolve().parents[1]
REAL_TEMPLATE = str(ROOT / "programs" / "real-program.example.yaml")
SIM_CONFIG = str(ROOT / "programs" / "simulator.yaml")


class CountingTransport(httpx.MockTransport):
    def __init__(self):
        self.calls = 0

        def handler(request):
            self.calls += 1
            return httpx.Response(200, headers={"content-type": "application/json"}, text="{}")
        super().__init__(handler)


def _base(**over):
    """A minimal, otherwise-ready program config for validation edge cases."""
    kw = dict(
        name="t", authorized=True,
        scope=ScopeConfig(in_scope=[ScopeRule(kind=ScopeKind.DOMAIN, value="127.0.0.1")]),
        restrictions=TestingRestrictions(allowed_methods=["GET"]),
        allowed_tools=["http"],
        allowed_vulnerability_classes=["idor"],
        request_budget=PolicyBudget(),
    )
    kw.update(over)
    return ProgramManager(ProgramConfig(**kw))


# --- validation ---------------------------------------------------------------

def test_ready_program_passes(monkeypatch):
    monkeypatch.setenv(ENV_TOKEN_A, USERS["user_a"].token)
    monkeypatch.setenv(ENV_TOKEN_B, USERS["user_b"].token)
    report = validate_policy(build_simulator_manager())
    assert report.ready is True and not report.needs_human_review


def test_real_template_not_ready():
    from bbagent.config.loader import load_program
    report = validate_policy(ProgramManager(load_program(REAL_TEMPLATE)))
    assert report.ready is False
    assert report.dry_run_only is True
    assert report.needs_human_review  # every program-specific rule flagged


def test_missing_budget_is_ambiguous():
    report = validate_policy(_base(request_budget=None))
    assert report.ready is False
    assert any("request_budget" in a for a in report.ambiguities)


def test_empty_allowed_tools_is_ambiguous():
    report = validate_policy(_base(allowed_tools=[]))
    assert report.ready is False
    assert any("allowed_tools" in a for a in report.ambiguities)


def test_empty_vuln_classes_is_ambiguous():
    report = validate_policy(_base(allowed_vulnerability_classes=[]))
    assert report.ready is False
    assert any("allowed_vulnerability_classes" in a for a in report.ambiguities)


def test_unknown_tool_is_conflict():
    report = validate_policy(_base(allowed_tools=["http", "nmap"]))
    assert report.ready is False
    assert any("nmap" in c for c in report.conflicts)


def test_unknown_vuln_class_is_conflict():
    report = validate_policy(_base(allowed_vulnerability_classes=["idor", "rce"]))
    assert any("rce" in c for c in report.conflicts)


def test_in_scope_also_excluded_is_conflict():
    report = validate_policy(_base(scope=ScopeConfig(
        in_scope=[ScopeRule(kind=ScopeKind.DOMAIN, value="127.0.0.1")],
        excluded=[ScopeRule(kind=ScopeKind.DOMAIN, value="127.0.0.1")],
    )))
    assert any("both in-scope and excluded" in c for c in report.conflicts)


def test_active_method_without_active_testing_is_ambiguous():
    report = validate_policy(_base(
        restrictions=TestingRestrictions(allowed_methods=["GET", "POST"], allow_active_testing=False)))
    assert any("active" in a.lower() for a in report.ambiguities)


def test_auth_required_without_identities_is_conflict():
    report = validate_policy(_base(allow_unauthenticated=False, test_accounts=[]))
    assert any("no authorized test identities" in c for c in report.conflicts)


def test_needs_human_review_blocks_ready():
    report = validate_policy(_base(needs_human_review=["scope"]))
    assert report.ready is False and "scope" in report.needs_human_review


# --- dry-run simulation (no network) ------------------------------------------

def test_simulation_decisions_and_no_execution(monkeypatch):
    monkeypatch.setenv(ENV_TOKEN_A, USERS["user_a"].token)
    monkeypatch.setenv(ENV_TOKEN_B, USERS["user_b"].token)
    program = build_simulator_manager()
    program.config.dry_run_only = True   # permanent dry-run

    actions = [
        {"tool": "http", "method": "GET", "url": "http://127.0.0.1:8000/products?id=1", "identity": "user_a"},
        {"tool": "http", "method": "GET", "url": "http://example.com/x"},                # out of scope
        {"tool": "http", "method": "GET", "url": "http://127.0.0.1:8000/excluded/y"},     # excluded path
        {"tool": "http", "method": "POST", "url": "http://127.0.0.1:8000/z"},             # forbidden method
        {"tool": "http", "method": "GET", "url": "http://127.0.0.1:8000/z", "identity": "ghost"},  # bad id
        {"tool": "http", "method": "GET", "url": "http://127.0.0.1:8000/z", "vuln_class": "rce"},  # bad class
        {"tool": "shell", "method": "GET", "url": "http://127.0.0.1:8000/z"},             # bad tool
        {"tool": "http", "method": "GET", "url": "notaurl"},                              # malformed
    ]
    decisions = simulate(program, actions)
    assert len(decisions) == len(actions)
    # The first action is allowed by rules, but dry-run means it would NOT execute.
    assert decisions[0].allowed is True and decisions[0].would_execute is False
    # All the rest are denied outright.
    assert all(d.allowed is False for d in decisions[1:])
    # Nothing ever executes in dry-run.
    assert all(d.would_execute is False for d in decisions)


async def test_dry_run_only_blocks_real_execution(monkeypatch):
    """Even when policy ALLOWS, a dry_run_only program never reaches the network."""
    monkeypatch.setenv(ENV_TOKEN_A, USERS["user_a"].token)
    monkeypatch.setenv(ENV_TOKEN_B, USERS["user_b"].token)
    program = build_simulator_manager()
    program.config.dry_run_only = True
    t = CountingTransport()
    async with AuthorizedHTTPClient(program.config, transport=t) as http:
        router = ToolRouter(default_tools(), ProgramPolicyEngine(program),
                            ToolContext(program=program, http=http))
        res = await router.dispatch(ToolRequest(
            tool="http", arguments={"url": "http://127.0.0.1:8000/products?id=1", "method": "GET"},
            identity="user_a"))
    assert res.success is False and "dry-run" in (res.denied_reason or "")
    assert t.calls == 0   # zero real network execution


# --- CLI ----------------------------------------------------------------------

def test_cli_policy_check_ready_vs_not_ready(monkeypatch, capsys):
    monkeypatch.setenv(ENV_TOKEN_A, USERS["user_a"].token)
    monkeypatch.setenv(ENV_TOKEN_B, USERS["user_b"].token)
    assert cli.main(["policy-check", SIM_CONFIG]) == 0
    assert "READY TO RUN" in capsys.readouterr().out

    rc = cli.main(["policy-check", REAL_TEMPLATE])
    assert rc == 1  # fail-closed
    out = capsys.readouterr().out
    assert "NOT READY" in out and "NEEDS_HUMAN_REVIEW" in out


def test_cli_policy_simulate_no_network(tmp_path, capsys):
    actions_file = tmp_path / "actions.yaml"
    actions_file.write_text(
        "actions:\n"
        "  - {tool: http, method: GET, url: 'http://127.0.0.1/x'}\n"
        "  - {tool: http, method: GET, url: 'http://example.com/x'}\n",
        encoding="utf-8",
    )
    rc = cli.main(["policy-simulate", REAL_TEMPLATE, "--actions", str(actions_file)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Dry-run simulation" in out
    assert "NOT-executed" in out   # dry_run_only template never executes
