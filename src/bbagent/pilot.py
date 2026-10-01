"""Controlled real-program pilot gate.

LIVE is OFF by default. A real request can only ever be sent when a human
explicitly enables live mode AND every required permission/configuration is
present. Anything UNKNOWN or missing (policy not ready, credentials, H1 username,
request budget, allowed methods, automation permission) blocks execution. Nothing
is guessed from general knowledge.

This module only reports readiness and decides the gate; it does not itself send
requests. The autonomous pipeline it guards additionally refuses to transmit while
``dry_run_only`` is true.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from bbagent.planner import CapabilityStatus, build_capability_matrix
from bbagent.planner.capabilities import default_capabilities
from bbagent.policy.validation import validate_policy
from bbagent.program.manager import ProgramManager


@dataclass
class PilotReport:
    program: str
    dry_run_only: bool
    live_enabled: bool
    ready: bool
    may_go_live: bool
    blockers: list[str] = field(default_factory=list)
    in_scope: list[str] = field(default_factory=list)
    enabled_classes: list[str] = field(default_factory=list)
    disabled_classes: list[str] = field(default_factory=list)
    identities: list[str] = field(default_factory=list)
    required_header_status: dict = field(default_factory=dict)
    request_budget: int | None = None
    allowed_methods: list[str] = field(default_factory=list)

    def render(self) -> str:
        lines = [
            "================ PILOT PRE-FLIGHT ================",
            f"program:            {self.program}",
            f"in-scope assets:    {', '.join(self.in_scope) or '-'}",
            f"enabled classes:    {', '.join(self.enabled_classes) or '(none)'}",
            f"disabled classes:   {', '.join(self.disabled_classes) or '(none)'}",
            f"request budget:     {self.request_budget if self.request_budget is not None else 'UNKNOWN'}",
            f"allowed methods:    {', '.join(self.allowed_methods) or 'UNKNOWN'}",
            f"identity(ies):      {', '.join(self.identities) or '(none)'}",
            f"required headers:   {self.required_header_status or '-'}",
            f"dry_run_only:       {self.dry_run_only}",
            f"LIVE mode:          {'ON' if self.live_enabled else 'OFF (default)'}",
            f"policy READY:       {self.ready}",
            f"MAY GO LIVE:        {self.may_go_live}",
        ]
        if self.blockers:
            lines.append("blockers:")
            lines += [f"  - {b}" for b in self.blockers]
        lines.append("=================================================")
        return "\n".join(lines)


def live_enabled() -> bool:
    """Live mode is OFF unless the operator sets BBAGENT_LIVE=1."""
    return os.getenv("BBAGENT_LIVE", "0") == "1"


def preflight(program: ProgramManager, *, live: bool | None = None) -> PilotReport:
    cfg = program.config
    live_on = live_enabled() if live is None else bool(live)
    validation = validate_policy(program)

    blockers: list[str] = []
    if not validation.ready:
        blockers.append("policy is NOT READY (see policy-check): "
                        + "; ".join(validation.ambiguities + validation.needs_human_review)[:400])
    # Runtime secrets that must be present before any live request.
    for acct in cfg.test_accounts:
        if acct.secret_env and os.getenv(acct.secret_env) is None:
            blockers.append(f"missing credential env {acct.secret_env!r} for identity {acct.label!r}")
    header_status: dict[str, str] = {}
    for hk, env_var in cfg.required_header_refs.items():
        present = os.getenv(env_var) is not None
        header_status[hk] = f"{env_var}={'set' if present else 'MISSING'}"
        if not present:
            blockers.append(f"missing required-header env {env_var!r} for {hk!r}")
    if cfg.request_budget is None:
        blockers.append("request budget is UNKNOWN")
    if not cfg.restrictions.allowed_methods:
        blockers.append("allowed HTTP methods are UNDEFINED")
    if not cfg.allowed_tools:
        blockers.append("automation/tooling permission is UNDEFINED")

    matrix = build_capability_matrix(program, default_capabilities())
    enabled = [r.vulnerability_class for r in matrix if r.status is CapabilityStatus.ALLOWED]
    disabled = [f"{r.vulnerability_class}({r.status.value})" for r in matrix
                if r.status is not CapabilityStatus.ALLOWED]

    ready = not blockers
    may_go_live = ready and live_on and not cfg.dry_run_only

    return PilotReport(
        program=cfg.name, dry_run_only=cfg.dry_run_only, live_enabled=live_on,
        ready=ready, may_go_live=may_go_live, blockers=blockers,
        in_scope=[f"{r.kind.value}:{r.value}" for r in cfg.scope.in_scope],
        enabled_classes=enabled, disabled_classes=disabled,
        identities=[a.label for a in cfg.test_accounts],
        required_header_status=header_status,
        request_budget=cfg.request_budget.total if cfg.request_budget else None,
        allowed_methods=list(cfg.restrictions.allowed_methods),
    )
