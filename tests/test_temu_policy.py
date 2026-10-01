"""Temu program adapter: scope from the CSV only, forbidden classes, capability
matrix, fail-closed validation, and the controlled live-pilot gate. No network."""

from __future__ import annotations

from pathlib import Path

import pytest

from bbagent import cli
from bbagent.config.loader import load_program
from bbagent.planner import CapabilityStatus, build_capability_matrix
from bbagent.planner.capabilities import default_capabilities
from bbagent.pilot import preflight
from bbagent.policy.validation import validate_policy
from bbagent.program.manager import ProgramManager
from bbagent.scope.engine import ScopeEngine

TEMU = str(Path(__file__).resolve().parents[1] / "programs" / "temu.yaml")


@pytest.fixture
def temu():
    return ProgramManager(load_program(TEMU))


@pytest.fixture
def scope(temu):
    return ScopeEngine(temu.config.scope)


# --- scope: only the supplied web assets --------------------------------------

@pytest.mark.parametrize("url", [
    "https://www.temu.com/",
    "https://seller.temu.com/x",
    "https://partner.temu.com/x",
    "https://ads.temu.com/x",
])
def test_in_scope_web_assets_allowed(scope, url):
    assert scope.is_allowed(url) is True


@pytest.mark.parametrize("url", [
    "https://temu.com/",                 # apex is NOT www.temu.com
    "https://api.temu.com/x",            # unknown subdomain
    "https://internal.temu.com/x",       # unknown subdomain
    "https://evil.com/x",                # unrelated domain
    "https://www.temu.com.evil.com/x",   # suffix trick
])
def test_unknown_or_unrelated_denied(scope, url):
    assert scope.is_allowed(url) is False


def test_no_wildcard_scope(temu):
    from bbagent.config.models import ScopeKind
    assert all(r.kind is not ScopeKind.WILDCARD for r in temu.config.scope.in_scope)


def test_discovery_cannot_expand_scope(scope):
    # A "discovered" link to an unscoped subdomain is not automatically allowed.
    assert scope.is_allowed("https://cdn.temu.com/assets/app.js") is False
    assert scope.is_allowed("https://www.temu.com/legit") is True


# --- forbidden classes + capability matrix ------------------------------------

def test_forbidden_classes_represented(temu):
    fa = set(temu.config.forbidden_actions)
    for cat in ("reflected-xss", "dom-xss", "self-xss", "account-brute-force", "dos",
                "physical-social-engineering", "clickjacking", "csv-injection-no-vuln",
                "payment-processors", "mass-entity-creation", "mitm-physical-access"):
        assert cat in fa


def test_capability_matrix(temu):
    # Temu's explicit out-of-scope list is authoritative: excluded classes are
    # FORBIDDEN; classes not excluded (of our detectors) are ALLOWED.
    matrix = {r.vulnerability_class: r.status for r in
              build_capability_matrix(temu, default_capabilities())}
    assert matrix["reflected_xss"] is CapabilityStatus.FORBIDDEN
    assert matrix["idor"] is CapabilityStatus.ALLOWED
    assert matrix["privilege_escalation"] is CapabilityStatus.ALLOWED
    assert matrix["sql_injection"] is CapabilityStatus.ALLOWED


def test_required_header_is_env_ref(temu):
    refs = temu.config.required_header_refs
    assert refs["X-HackerOne-Research"] == "BBAGENT_H1_USERNAME"
    assert refs["Cookie"] == "BBAGENT_TEMU_COOKIE"
    assert refs["VerifyAuthToken"] == "BBAGENT_TEMU_VERIFY_AUTH_TOKEN"
    # Header values are env-referenced, never literals in YAML.
    assert not temu.config.required_headers


def test_two_identities_with_separate_profiles(temu):
    labels = {a.label for a in temu.config.test_accounts}
    assert labels == {"researcher", "researcher_b"}
    # Session auth is via browser profiles / Cookie+VerifyAuthToken, never a per-account bearer.
    assert all(a.secret_env is None for a in temu.config.test_accounts)
    # Each identity maps to its OWN persistent browser profile env — never shared.
    envs = [a.profile_dir_env for a in temu.config.test_accounts]
    assert set(envs) == {"BBAGENT_TEMU_PROFILE_A", "BBAGENT_TEMU_PROFILE_B"}
    assert len(envs) == len(set(envs))


# --- validation: NOT READY, fail closed ---------------------------------------

def test_policy_not_ready(temu):
    report = validate_policy(temu)
    assert report.ready is False and report.dry_run_only is True
    joined = " ".join(report.ambiguities)
    # allowed_vulnerability_classes is now populated, so it is no longer ambiguous;
    # the program still fails closed on methods, tools, and budget.
    for token in ("allowed_tools", "allowed_methods", "request_budget"):
        assert token in joined
    assert "allowed_vulnerability_classes" not in joined


def test_cli_policy_check_exit_1():
    assert cli.main(["policy-check", TEMU]) == 1


# --- pilot gate ---------------------------------------------------------------

def test_pilot_live_off_by_default(temu, monkeypatch):
    monkeypatch.delenv("BBAGENT_LIVE", raising=False)
    report = preflight(temu)
    assert report.live_enabled is False
    assert report.may_go_live is False


def test_pilot_reports_enabled_disabled_classes(temu):
    report = preflight(temu)
    assert set(report.enabled_classes) == {"idor", "privilege_escalation", "sql_injection"}
    assert any("reflected_xss(FORBIDDEN)" in d for d in report.disabled_classes)


def test_pilot_blocks_when_not_ready_even_if_live(temu):
    report = preflight(temu, live=True)
    assert report.may_go_live is False
    # All the mandated blockers are present.
    joined = " ".join(report.blockers)
    assert "NOT READY" in joined
    assert "BBAGENT_TEMU_COOKIE" in joined                 # missing session cookie
    assert "BBAGENT_TEMU_VERIFY_AUTH_TOKEN" in joined       # missing verify-auth token
    assert "BBAGENT_H1_USERNAME" in joined                 # missing H1 username
    assert "budget is UNKNOWN" in joined
    assert "allowed HTTP methods are UNDEFINED" in joined
    assert "automation/tooling permission is UNDEFINED" in joined


def test_pilot_refuses_even_with_secrets_because_policy_not_ready(temu, monkeypatch):
    # Providing secrets does NOT make an unready program live-eligible.
    monkeypatch.setenv("BBAGENT_TEMU_TOKEN", "tok")
    monkeypatch.setenv("BBAGENT_H1_USERNAME", "researcher")
    monkeypatch.setenv("BBAGENT_LIVE", "1")
    report = preflight(temu)
    assert report.live_enabled is True
    assert report.may_go_live is False            # still NOT READY (methods/tools/classes/budget)


def test_cli_pilot_live_refused(monkeypatch, capsys):
    monkeypatch.setenv("BBAGENT_TEMU_TOKEN", "tok")
    monkeypatch.setenv("BBAGENT_H1_USERNAME", "researcher")
    rc = cli.main(["pilot", TEMU, "--live", "--yes"])
    assert rc == 2                                # refused, no requests
    assert "REFUSING to go live" in capsys.readouterr().err


def test_dry_run_only_true(temu):
    assert temu.config.dry_run_only is True
