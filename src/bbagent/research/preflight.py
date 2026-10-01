"""Preflight / readiness checks for `bbagent research`.

Verifies everything required for a real research run WITHOUT navigating, launching
a browser, or sending a single byte to the target. It only inspects configuration,
environment presence (never values), limits, and structural invariants.

The nine checks (see the task):
  1. Browser backend available.
  2. Authenticated session establishable without persisting/printing secrets.
  3. Seed URL(s) explicitly supplied and in scope (ScopeEngine).
  4. Program policy loaded and valid (READY, fail-closed).
  5. Required detector capabilities available.
  6. RunBudget configured (and shared by construction).
  7. Human-review / no-submission invariants active.
  8. Explicit loop bounds: max rounds / actions / pages / time / request budget.
  9. No real execution unless BOTH an explicit live flag and env opt-in are present.
"""

from __future__ import annotations

import importlib.util
import inspect
import os
from dataclasses import dataclass, field

from bbagent.planner import default_capabilities
from bbagent.policy.validation import validate_policy
from bbagent.program.manager import ProgramManager
from bbagent.scope.engine import ScopeEngine

LIVE_ENV = "BBAGENT_BROWSER_LIVE"


@dataclass
class Check:
    name: str
    ok: bool
    detail: str


@dataclass
class ResearchPreflightReport:
    program: str
    checks: list[Check] = field(default_factory=list)
    ready: bool = False          # all mandatory checks passed
    live_flag: bool = False
    env_opt_in: bool = False
    dry_run_only: bool = True
    would_execute: bool = False  # ready AND live gate satisfied AND not dry-run

    def render(self) -> str:
        lines = [f"# Research preflight — {self.program}", ""]
        for c in self.checks:
            lines.append(f"[{'PASS' if c.ok else 'FAIL'}] {c.name}: {c.detail}")
        lines += [
            "",
            f"ready (all checks): {self.ready}",
            f"live flag:          {self.live_flag}   env opt-in ({LIVE_ENV}=1): {self.env_opt_in}",
            f"dry_run_only:       {self.dry_run_only}",
            f"WOULD EXECUTE:      {self.would_execute}",
        ]
        if not self.would_execute:
            lines.append("No real execution: preflight only (no navigation, no target traffic).")
        return "\n".join(lines)


def research_preflight(
    program: ProgramManager,
    *,
    seed_urls: list[str],
    limits,
    live: bool = False,
    env_opt_in: bool | None = None,
    browser_available: bool | None = None,
    identity: str = "researcher",
) -> ResearchPreflightReport:
    """Run all readiness checks. Performs NO navigation and NO target requests."""
    cfg = program.config
    checks: list[Check] = []
    report = ResearchPreflightReport(program=cfg.name)

    # 1) Browser backend available (import-only; never launches a browser).
    if browser_available is None:
        browser_available = importlib.util.find_spec("playwright") is not None
    checks.append(Check(
        "browser_backend_available", bool(browser_available),
        "playwright backend importable" if browser_available
        else "playwright not installed (pip install \"bbagent[browser]\")"))

    # 2) Authenticated session establishable without persisting/printing secrets.
    #    We only check env-var PRESENCE (never read or print the values).
    needed: list[str] = []
    for acct in cfg.test_accounts:
        if acct.secret_env:
            needed.append(acct.secret_env)
    for env_var in getattr(cfg, "required_header_refs", {}).values():
        needed.append(env_var)
    missing = [n for n in needed if os.getenv(n) is None]
    if not needed:
        checks.append(Check("auth_session", False,
                            "no identity secret env or required_header_refs configured"))
    elif missing:
        checks.append(Check("auth_session", False,
                            f"missing env (names only, values never read): {', '.join(missing)}"))
    else:
        checks.append(Check("auth_session", True,
                            f"{len(needed)} credential env var(s) present; "
                            "injected server-side, never persisted/printed"))

    # 3) Seed URL(s) explicitly supplied and in scope.
    scope = ScopeEngine(cfg.scope)
    if not seed_urls:
        checks.append(Check("seed_in_scope", False, "no seed URL supplied"))
    else:
        out = [u for u in seed_urls if not scope.is_allowed(u)]
        checks.append(Check("seed_in_scope", not out,
                            "all seeds in scope" if not out
                            else f"out-of-scope seed(s): {', '.join(out)}"))

    # 4) Program policy loaded and valid (READY, fail-closed).
    vp = validate_policy(program)
    report.dry_run_only = cfg.dry_run_only
    checks.append(Check(
        "policy_valid_ready", bool(vp.ready),
        "policy READY" if vp.ready
        else f"NOT READY (dry_run_only={cfg.dry_run_only}); "
             f"{'; '.join((vp.ambiguities + vp.conflicts + list(vp.needs_human_review))[:3])}"))

    # 5) Required detector capabilities available.
    known = {c.vuln_class for c in default_capabilities().all()}
    allowed = list(cfg.allowed_vulnerability_classes)
    unknown = [c for c in allowed if c not in known]
    if not allowed:
        checks.append(Check("capabilities_available", False,
                            "no allowed_vulnerability_classes configured"))
    elif unknown:
        checks.append(Check("capabilities_available", False,
                            f"no capability for: {', '.join(unknown)}"))
    else:
        checks.append(Check("capabilities_available", True,
                            f"capabilities present for: {', '.join(sorted(allowed))}"))

    # 6) RunBudget configured (shared by construction in the loop).
    rb_ok = cfg.request_budget is not None and cfg.request_budget.total >= 1
    checks.append(Check(
        "run_budget_configured", bool(rb_ok),
        f"request_budget.total={cfg.request_budget.total} (one shared RunBudget)" if rb_ok
        else "request_budget not configured (fail-closed)"))

    # 7) Human-review / no-submission invariants active (structural, verified from
    #    the loop's own source: it enqueues to review and never approves/submits).
    from bbagent.research import loop as _loop
    src = inspect.getsource(_loop)
    invariant_ok = ("submit_for_review" in src) and ("APPROVED_FOR_SUBMISSION" not in src)
    checks.append(Check(
        "human_review_no_submission", invariant_ok,
        "verified findings enqueue to HUMAN review; no auto-submission path" if invariant_ok
        else "human-review/no-submission invariant could not be confirmed"))

    # 8) Explicit loop bounds present and finite.
    bounds_ok = True
    detail_bits = []
    try:
        for label, val in (("max_rounds", limits.max_rounds),
                           ("max_seconds", limits.max_seconds),
                           ("exp.max_actions", limits.exploration.max_actions),
                           ("exp.max_pages", limits.exploration.max_pages),
                           ("exp.max_seconds", limits.exploration.max_seconds),
                           ("test.max_requests", limits.test.max_requests)):
            if val is None or val <= 0:
                bounds_ok = False
            detail_bits.append(f"{label}={val}")
    except AttributeError as exc:
        bounds_ok = False
        detail_bits = [f"malformed limits: {exc}"]
    checks.append(Check("explicit_bounds", bounds_ok, ", ".join(detail_bits)))

    # 9) No real execution unless BOTH the live flag and env opt-in are present.
    env_opt_in = (os.getenv(LIVE_ENV) == "1") if env_opt_in is None else bool(env_opt_in)
    report.live_flag = bool(live)
    report.env_opt_in = bool(env_opt_in)
    gate_ok = bool(live) and bool(env_opt_in) and not cfg.dry_run_only
    checks.append(Check(
        "live_gate", True,  # informational: this check always "passes" (reports state)
        f"live={live}, {LIVE_ENV}={'1' if env_opt_in else 'unset'}, "
        f"dry_run_only={cfg.dry_run_only} -> would_execute={gate_ok}"))

    report.checks = checks
    # Mandatory checks are all except the informational live_gate.
    mandatory = [c for c in checks if c.name != "live_gate"]
    report.ready = all(c.ok for c in mandatory)
    report.would_execute = report.ready and gate_ok
    return report
