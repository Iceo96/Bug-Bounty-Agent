"""Preflight / readiness checks for `bbagent research`.

Every test runs the checks WITHOUT a browser, without a lab, and without any target
traffic (there is no BackgroundLab fixture here on purpose). Temu stays dry-run and
is never contacted.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bbagent import cli
from bbagent.config.loader import load_program
from bbagent.program.manager import ProgramManager
from bbagent.research import ResearchLimits, research_preflight
from bbagent_lab.agent_config import ENV_TOKEN_A, ENV_TOKEN_B
from bbagent_lab.data import USERS
from bbagent_lab.simulator import build_simulator_manager

TEMU_YAML = str(Path(__file__).resolve().parents[1] / "programs" / "temu.yaml")
SEED = "http://127.0.0.1:9/site"          # in scope (127.0.0.1); never contacted


@pytest.fixture
def creds(monkeypatch):
    monkeypatch.setenv(ENV_TOKEN_A, USERS["user_a"].token)
    monkeypatch.setenv(ENV_TOKEN_B, USERS["user_b"].token)


def _check(report, name):
    return next(c for c in report.checks if c.name == name)


# --- happy path ---------------------------------------------------------------

def test_all_checks_pass_and_would_execute(creds):
    report = research_preflight(
        build_simulator_manager(), seed_urls=[SEED], limits=ResearchLimits(),
        live=True, env_opt_in=True, browser_available=True)
    assert report.ready is True
    assert report.would_execute is True
    assert all(c.ok for c in report.checks)
    # nine checks reported
    assert {c.name for c in report.checks} == {
        "browser_backend_available", "auth_session", "seed_in_scope",
        "policy_valid_ready", "capabilities_available", "run_budget_configured",
        "human_review_no_submission", "explicit_bounds", "live_gate",
    }


def test_ready_but_gate_off_does_not_execute(creds):
    # Ready, but neither/one of the two gate conditions -> no execution.
    for live, opt in [(False, True), (True, False), (False, False)]:
        report = research_preflight(
            build_simulator_manager(), seed_urls=[SEED], limits=ResearchLimits(),
            live=live, env_opt_in=opt, browser_available=True)
        assert report.ready is True
        assert report.would_execute is False


# --- individual check failures ------------------------------------------------

def test_browser_unavailable_fails(creds):
    report = research_preflight(build_simulator_manager(), seed_urls=[SEED],
                                limits=ResearchLimits(), browser_available=False)
    assert _check(report, "browser_backend_available").ok is False
    assert report.ready is False


def test_missing_auth_env_fails(monkeypatch):
    monkeypatch.delenv(ENV_TOKEN_A, raising=False)
    monkeypatch.delenv(ENV_TOKEN_B, raising=False)
    report = research_preflight(build_simulator_manager(), seed_urls=[SEED],
                                limits=ResearchLimits(), browser_available=True)
    chk = _check(report, "auth_session")
    assert chk.ok is False
    # names only, never values
    assert ENV_TOKEN_A in chk.detail and USERS["user_a"].token not in chk.detail
    assert report.ready is False


def test_no_seed_fails(creds):
    report = research_preflight(build_simulator_manager(), seed_urls=[],
                                limits=ResearchLimits(), browser_available=True)
    assert _check(report, "seed_in_scope").ok is False
    assert report.ready is False


def test_out_of_scope_seed_fails(creds):
    report = research_preflight(build_simulator_manager(),
                                seed_urls=["https://evil.example.com/x"],
                                limits=ResearchLimits(), browser_available=True)
    assert _check(report, "seed_in_scope").ok is False
    assert report.ready is False


def test_missing_bounds_fails(creds):
    limits = ResearchLimits(max_rounds=0)     # not a positive bound
    report = research_preflight(build_simulator_manager(), seed_urls=[SEED],
                                limits=limits, browser_available=True)
    assert _check(report, "explicit_bounds").ok is False
    assert report.ready is False


def test_capabilities_and_budget_and_review_pass(creds):
    report = research_preflight(build_simulator_manager(), seed_urls=[SEED],
                                limits=ResearchLimits(), browser_available=True)
    assert _check(report, "capabilities_available").ok is True
    assert _check(report, "run_budget_configured").ok is True
    assert _check(report, "human_review_no_submission").ok is True


# --- Temu stays dry-run and is never contacted --------------------------------

def test_temu_preflight_not_ready_no_contact():
    temu = ProgramManager(load_program(TEMU_YAML))
    report = research_preflight(temu, seed_urls=["https://www.temu.com/"],
                                limits=ResearchLimits(), live=True, env_opt_in=True,
                                browser_available=True)
    assert report.dry_run_only is True
    assert _check(report, "policy_valid_ready").ok is False
    assert report.ready is False
    assert report.would_execute is False       # dry-run can never execute


def test_cli_research_preflight_temu_reports_without_contact(tmp_path, capsys):
    rc = cli.main(["--db", str(tmp_path / "p.db"), "research", TEMU_YAML,
                   "--seed", "https://www.temu.com/", "--preflight"])
    assert rc == 1                              # not ready
    out = capsys.readouterr()
    assert "Research preflight" in out.out
    assert "WOULD EXECUTE:      False" in out.out
    assert "REFUSING" not in out.err            # preflight reports; it does not refuse
