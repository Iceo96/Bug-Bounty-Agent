"""Tool Router — the single choke point between the agent and tool execution.

For every ToolRequest it: (1) checks the tool exists, (2) validates arguments
against the tool's schema, (3) runs the request through the Program Policy Engine,
and only on ALLOW does it (4) record the budget, inject any identity credential
server-side, and execute. Denied or malformed requests never reach a tool.
"""

from __future__ import annotations

from bbagent.logging_config import get_logger
from bbagent.policy.engine import ProgramPolicyEngine
from bbagent.tools.base import ToolError, ToolRequest, ToolResult
from bbagent.tools.context import ToolContext
from bbagent.tools.registry import ToolRegistry

log = get_logger(__name__)


class ToolRouter:
    def __init__(self, registry: ToolRegistry, policy: ProgramPolicyEngine, ctx: ToolContext):
        self._registry = registry
        self._policy = policy
        self._ctx = ctx

    async def dispatch(self, request: ToolRequest) -> ToolResult:
        tool = self._registry.get(request.tool)
        if tool is None:
            log.info("tool.unknown", tool=request.tool)
            return ToolResult.denied(request.tool, "unknown tool", action=request.requested_action)

        # Validate arguments against the tool's schema (reject malformed).
        try:
            args = tool.validate_arguments(request.arguments)
        except Exception as exc:  # noqa: BLE001 — pydantic ValidationError et al.
            return ToolResult.denied(request.tool, f"malformed arguments: {exc}",
                                     action=request.requested_action)

        # Normalize the target for http so the policy engine can evaluate scope.
        req = request
        if req.tool == "http" and not req.target:
            req = request.model_copy(update={"target": request.arguments.get("url")})

        # Policy gate (scope / exclusions / method / headers / identity / class / budget).
        decision = self._policy.evaluate(req)
        if not decision.allowed:
            return ToolResult(tool=req.tool, success=False, action=decision.action,
                              target=req.target, denied_reason=decision.reason,
                              metadata={"matched_rule": decision.matched_rule})

        # ALLOW: count against the policy budget before executing.
        self._policy.record(req)

        # Inject the identity's bearer token server-side (never LLM-visible).
        if req.tool == "http" and req.identity:
            token = self._ctx.program.resolve_account_secret(req.identity)
            if token:
                headers = dict(args.headers)
                headers["Authorization"] = f"Bearer {token}"
                args = args.model_copy(update={"headers": headers})

        try:
            sanitized = await tool.execute(args, self._ctx)
        except ToolError as exc:
            return ToolResult(tool=req.tool, success=False, action=decision.action,
                              target=req.target, error=str(exc))

        return ToolResult(
            tool=req.tool, success=True, action=decision.action, target=req.target,
            sanitized=sanitized,
            metadata={"matched_rule": decision.matched_rule, "identity": req.identity},
        )
