"""Program Policy Engine — evaluates a ToolRequest and returns ALLOW / DENY.

FAIL CLOSED: if a required policy field is missing or a target/tool/identity is
ambiguous, the request is DENIED rather than guessed. Denied requests never reach
tool execution. Decisions carry no secrets (identities are handles, not tokens).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from bbagent.logging_config import get_logger
from bbagent.program.manager import ProgramManager
from bbagent.scope.engine import ScopeEngine

if TYPE_CHECKING:  # avoid a runtime import cycle (tools -> router -> policy)
    from bbagent.tools.base import ToolRequest

log = get_logger(__name__)

_ACTIVE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    tool: str
    action: str
    target: str | None = None
    matched_rule: str = ""
    identity: str | None = None
    vuln_class: str | None = None

    def to_log(self) -> dict:
        """Secret-free representation for logging/audit."""
        return {
            "allowed": self.allowed, "reason": self.reason, "tool": self.tool,
            "action": self.action, "target": self.target, "matched_rule": self.matched_rule,
            "identity": self.identity, "vuln_class": self.vuln_class,
        }


class ProgramPolicyEngine:
    def __init__(self, program: ProgramManager):
        self.program = program
        self._scope = ScopeEngine(program.config.scope)
        # Policy-level budget counters (independent of the runner's TestBudget).
        self._total = 0
        self._per_target: dict[str, int] = {}
        self._per_tool: dict[str, int] = {}

    # --- evaluation -----------------------------------------------------------

    def _effective_target(self, req: "ToolRequest") -> str | None:
        """The target used for scope and per-target budget accounting."""
        if req.target:
            return req.target
        if req.tool == "http":
            url = req.arguments.get("url")
            return url if isinstance(url, str) else None
        return None

    def evaluate(self, req: "ToolRequest") -> PolicyDecision:
        cfg = self.program.config
        action = req.requested_action or (
            str(req.arguments.get("method", "")) if req.tool == "http" else "")

        def deny(reason: str, rule: str = "") -> PolicyDecision:
            d = PolicyDecision(False, reason, req.tool, action, req.target, rule,
                               req.identity, req.vuln_class)
            log.info("policy.deny", **d.to_log())
            return d

        def allow(reason: str, rule: str) -> PolicyDecision:
            d = PolicyDecision(True, reason, req.tool, action, req.target, rule,
                               req.identity, req.vuln_class)
            log.info("policy.allow", **d.to_log())
            return d

        # 0) Program must be authorized.
        if not cfg.authorized:
            return deny("program is not authorized", "authorized=false")

        # 1) Tool must be explicitly allowed (fail-closed if none configured).
        if not cfg.allowed_tools:
            return deny("no allowed_tools configured (fail-closed)", "allowed_tools:empty")
        if req.tool not in cfg.allowed_tools:
            return deny(f"tool '{req.tool}' not allowed by program", "allowed_tools")

        # 2) Vulnerability-class restriction (when the request declares one).
        if req.vuln_class is not None:
            if not cfg.allowed_vulnerability_classes:
                return deny("no allowed_vulnerability_classes configured (fail-closed)",
                            "allowed_vulnerability_classes:empty")
            if req.vuln_class not in cfg.allowed_vulnerability_classes:
                return deny(f"vulnerability class '{req.vuln_class}' not permitted",
                            "allowed_vulnerability_classes")

        # 3) Explicitly forbidden actions.
        if req.requested_action and req.requested_action in cfg.forbidden_actions:
            return deny(f"action '{req.requested_action}' is forbidden by program",
                        "forbidden_actions")

        # 4) Identity must be an authorized handle (or unauthenticated if allowed).
        if req.identity is not None:
            if req.identity not in {a.label for a in cfg.test_accounts}:
                return deny(f"identity '{req.identity}' is not an authorized test account",
                            "test_accounts")
        elif not cfg.allow_unauthenticated:
            return deny("authentication required but no identity supplied", "allow_unauthenticated")

        # 5) HTTP-specific gates.
        if req.tool == "http":
            http_deny = self._check_http(req, cfg, deny)
            if http_deny is not None:
                return http_deny

        # 6) Budget (stricter of total / per-target / per-tool wins).
        budget = cfg.request_budget
        if budget is not None:
            tgt = self._effective_target(req) or "*"
            if self._total + 1 > budget.total:
                return deny(f"total request budget exhausted ({budget.total})", "request_budget.total")
            if self._per_target.get(tgt, 0) + 1 > budget.per_target:
                return deny(f"per-target budget exhausted ({budget.per_target}) for {tgt}",
                            "request_budget.per_target")
            if self._per_tool.get(req.tool, 0) + 1 > budget.per_tool:
                return deny(f"per-tool budget exhausted ({budget.per_tool}) for {req.tool}",
                            "request_budget.per_tool")

        return allow("request permitted by program policy", "policy.ok")

    def _check_http(self, req: ToolRequest, cfg, deny):
        method = str(req.arguments.get("method", "GET")).upper()
        url = req.target or req.arguments.get("url")
        if not url:
            return deny("missing target URL (fail-closed)", "http.target")

        if method not in cfg.restrictions.allowed_methods:
            return deny(f"HTTP method {method} not allowed", "allowed_methods")
        if method in _ACTIVE_METHODS and not cfg.restrictions.allow_active_testing:
            return deny(f"active method {method} blocked (passive-only program)", "active_testing")

        decision = self._scope.check(url)
        if not decision.allowed:
            rule = "scope.exclusion" if "exclusion" in decision.reason else "scope"
            return deny(f"target out of scope: {decision.reason}", rule)

        path = urlsplit(url).path or "/"
        for frag in cfg.restrictions.forbidden_paths:
            if frag and frag in path:
                return deny(f"target path matches exclusion fragment {frag!r}", "exclusions")

        # The LLM may not override a required header's value.
        req_headers = {k.lower(): v for k, v in (req.arguments.get("headers") or {}).items()}
        for hk, hv in cfg.required_headers.items():
            if hk.lower() in req_headers and req_headers[hk.lower()] != hv:
                return deny(f"cannot override required header {hk!r}", "required_headers")
        return None

    # --- budget accounting ----------------------------------------------------

    def record(self, req: "ToolRequest") -> None:
        """Count an allowed+dispatched request against the policy budget."""
        self._total += 1
        self._per_tool[req.tool] = self._per_tool.get(req.tool, 0) + 1
        tgt = self._effective_target(req) or "*"
        self._per_target[tgt] = self._per_target.get(tgt, 0) + 1

    @property
    def total_used(self) -> int:
        return self._total
