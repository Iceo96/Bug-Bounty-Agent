"""Program policy validation + dry-run simulation.

Validates that a program's rules are explicit and unambiguous BEFORE any run, and
lets an operator inspect "what would the agent attempt to do?" purely from policy
decisions — with no network access whatsoever.

FAIL CLOSED: any ambiguity, conflict, or NEEDS_HUMAN_REVIEW marker makes the
program *not ready*. Permissions are never invented or inferred.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from bbagent.planner import default_capabilities
from bbagent.policy.engine import ProgramPolicyEngine
from bbagent.program.manager import ProgramManager
from bbagent.tools import ToolRequest, default_tools

_ACTIVE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def known_tools() -> set[str]:
    return set(default_tools().names())


def known_vuln_classes() -> set[str]:
    return {c.vuln_class for c in default_capabilities().all()}


@dataclass
class PolicyValidationReport:
    program: str
    ready: bool
    dry_run_only: bool
    summary: dict = field(default_factory=dict)
    conflicts: list[str] = field(default_factory=list)
    ambiguities: list[str] = field(default_factory=list)
    needs_human_review: list[str] = field(default_factory=list)

    def render(self) -> str:
        s = self.summary
        lines = [f"# Policy check: {self.program}",
                 f"ready: {self.ready}   dry_run_only: {self.dry_run_only}", ""]
        lines.append(f"scope (in): {s.get('in_scope', [])}")
        lines.append(f"exclusions (rules): {s.get('excluded', [])}")
        lines.append(f"exclusions (paths): {s.get('forbidden_paths', [])}")
        lines.append(f"allowed methods: {s.get('allowed_methods', [])}")
        lines.append(f"active testing: {s.get('allow_active_testing')}")
        lines.append(f"required headers: {s.get('required_headers', [])}")
        lines.append(f"authorized identities: {s.get('identities', [])}")
        lines.append(f"allowed tools: {s.get('allowed_tools', [])}")
        lines.append(f"allowed vuln classes: {s.get('allowed_vulnerability_classes', [])}")
        lines.append(f"forbidden actions: {s.get('forbidden_actions', [])}")
        lines.append(f"request budget: {s.get('request_budget')}")
        lines.append(f"allow unauthenticated: {s.get('allow_unauthenticated')}")
        if self.conflicts:
            lines += ["", "CONFLICTS:"] + [f"  - {c}" for c in self.conflicts]
        if self.ambiguities:
            lines += ["", "AMBIGUITIES (fail-closed):"] + [f"  - {a}" for a in self.ambiguities]
        if self.needs_human_review:
            lines += ["", "NEEDS_HUMAN_REVIEW:"] + [f"  - {n}" for n in self.needs_human_review]
        lines += ["", "READY TO RUN." if self.ready
                  else "NOT READY — fail closed. Resolve the items above before running."]
        return "\n".join(lines)


def validate_policy(program: ProgramManager) -> PolicyValidationReport:
    cfg = program.config
    conflicts: list[str] = []
    ambiguities: list[str] = []
    review: list[str] = list(cfg.needs_human_review)

    summary = {
        "in_scope": [f"{r.kind.value}:{r.value}" for r in cfg.scope.in_scope],
        "excluded": [f"{r.kind.value}:{r.value}" for r in cfg.scope.excluded],
        "forbidden_paths": list(cfg.restrictions.forbidden_paths),
        "allowed_methods": list(cfg.restrictions.allowed_methods),
        "allow_active_testing": cfg.restrictions.allow_active_testing,
        "required_headers": sorted(set(cfg.required_headers) | set(cfg.required_header_refs)),
        "identities": [a.label for a in cfg.test_accounts],
        "allowed_tools": list(cfg.allowed_tools),
        "allowed_vulnerability_classes": list(cfg.allowed_vulnerability_classes),
        "forbidden_actions": list(cfg.forbidden_actions),
        "request_budget": cfg.request_budget.model_dump() if cfg.request_budget else None,
        "allow_unauthenticated": cfg.allow_unauthenticated,
    }

    # Authorization must be explicit.
    if not cfg.authorized:
        conflicts.append("program is not marked authorized")

    # Tools must be explicitly allowed (fail-closed).
    if not cfg.allowed_tools:
        ambiguities.append("no allowed_tools configured — nothing may run (fail-closed)")
    for t in cfg.allowed_tools:
        if t not in known_tools():
            conflicts.append(f"allowed tool '{t}' is not a known tool {sorted(known_tools())}")

    # Vulnerability classes must be explicit and known.
    if not cfg.allowed_vulnerability_classes:
        ambiguities.append(
            "no allowed_vulnerability_classes configured — must be explicit for a real program")
    for vc in cfg.allowed_vulnerability_classes:
        if vc not in known_vuln_classes():
            conflicts.append(f"allowed vulnerability class '{vc}' is unknown {sorted(known_vuln_classes())}")

    # Allowed HTTP methods must be explicit.
    if not cfg.restrictions.allowed_methods:
        ambiguities.append("no allowed_methods configured — every HTTP method denied (fail-closed)")

    # Budgets must be explicit (unbounded testing is unsafe for a real program).
    if cfg.request_budget is None:
        ambiguities.append("no request_budget configured — unbounded requests (fail-closed)")

    # Scope sanity: an in-scope rule must not also be excluded.
    incl = {(r.kind, r.value) for r in cfg.scope.in_scope}
    for r in cfg.scope.excluded:
        if (r.kind, r.value) in incl:
            conflicts.append(f"rule {r.kind.value}:{r.value} is both in-scope and excluded")

    # Active methods listed while active testing disabled is ambiguous.
    if not cfg.restrictions.allow_active_testing:
        active = sorted(set(cfg.restrictions.allowed_methods) & _ACTIVE_METHODS)
        if active:
            ambiguities.append(
                f"active methods {active} are allowed but allow_active_testing is false")

    # Identity-required programs need at least one authorized identity.
    if not cfg.allow_unauthenticated and not cfg.test_accounts:
        conflicts.append("authentication required but no authorized test identities configured")

    ready = not (conflicts or ambiguities or review)
    return PolicyValidationReport(
        program=cfg.name, ready=ready, dry_run_only=cfg.dry_run_only, summary=summary,
        conflicts=conflicts, ambiguities=ambiguities, needs_human_review=review,
    )


# --- dry-run simulation -------------------------------------------------------

@dataclass
class SimulatedDecision:
    tool: str
    action: str
    target: str | None
    method: str | None
    identity: str | None
    vuln_class: str | None
    allowed: bool
    would_execute: bool
    reason: str
    matched_rule: str
    scope: str = "n/a"   # in_scope | excluded | out_of_scope | n/a (independent check)

    def render(self) -> str:
        verdict = "ALLOW" if self.allowed else "DENY"
        exe = "would-execute" if self.would_execute else "NOT-executed (dry-run/denied)"
        scope = f" scope={self.scope}" if self.scope != "n/a" else ""
        return (f"[{verdict}] {self.tool} {self.method or ''} {self.target or ''} "
                f"identity={self.identity or '-'} class={self.vuln_class or '-'}{scope} "
                f"-> {exe}\n      reason: {self.reason} ({self.matched_rule})")


def simulate(program: ProgramManager, actions: list[dict]) -> list[SimulatedDecision]:
    """Evaluate hypothetical actions against policy WITHOUT executing anything.

    Each action is a dict: {tool, method?, url?, identity?, vuln_class?, reason?}.
    No HTTP client is created; zero network access occurs.
    """
    from bbagent.scope.engine import ScopeEngine

    engine = ProgramPolicyEngine(program)
    scope_engine = ScopeEngine(program.config.scope)
    out: list[SimulatedDecision] = []
    for a in actions:
        tool = a.get("tool", "http")
        method = a.get("method", "GET")
        url = a.get("url")
        args: dict = {}
        if tool == "http":
            args = {"url": url, "method": method}
        elif tool == "recon":
            args = {"action": a.get("recon_action", "scope_hosts"), "host": a.get("host", "")}
        req = ToolRequest(tool=tool, arguments=args, target=url,
                          identity=a.get("identity"), vuln_class=a.get("vuln_class"),
                          reason=a.get("reason", ""))
        decision = engine.evaluate(req)
        would_execute = decision.allowed and not program.config.dry_run_only
        scope = "n/a"
        if tool == "http" and url:
            sd = scope_engine.check(url)
            scope = "in_scope" if sd.allowed else ("excluded" if "exclusion" in sd.reason
                                                   else "out_of_scope")
        out.append(SimulatedDecision(
            tool=tool, action=decision.action,
            target=url, method=method if tool == "http" else None,
            identity=a.get("identity"), vuln_class=a.get("vuln_class"),
            allowed=decision.allowed, would_execute=would_execute,
            reason=decision.reason, matched_rule=decision.matched_rule, scope=scope,
        ))
    return out


def _host(url: str | None) -> str:
    return (urlsplit(url or "").hostname or "") if url else ""
