"""Local, deterministic recon tool.

Deliberately limited: it derives candidate hostnames from the *authorized program
scope* and resolves only loopback names. It performs NO Internet-wide enumeration
and NO real DNS. Every host it returns is still checked against the scope engine,
and any subsequent request to it must pass the full policy engine.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from bbagent.config.models import ScopeKind
from bbagent.scope.engine import ScopeEngine
from bbagent.tools.base import Tool, ToolError

# Loopback names/addresses we are willing to "resolve" — no real network calls.
_LOOPBACK = {"localhost": "127.0.0.1", "127.0.0.1": "127.0.0.1", "::1": "::1"}


class ReconArgs(BaseModel):
    model_config = {"extra": "forbid"}

    action: str = Field(pattern="^(scope_hosts|resolve)$")
    host: str = ""


class ReconTool(Tool):
    name = "recon"
    description = "Local, deterministic asset discovery from the authorized scope (loopback only)."
    version = "1.0.0"
    permissions = ["recon:local"]
    args_model = ReconArgs
    output_schema = {
        "action": "str", "hosts": "list[str]", "host": "str", "addresses": "list[str]",
        "in_scope": "bool",
    }

    async def execute(self, args: ReconArgs, ctx) -> dict:
        scope = ScopeEngine(ctx.program.config.scope)

        if args.action == "scope_hosts":
            hosts = _hosts_from_scope(ctx.program.config.scope)
            # Only surface hosts that are themselves in scope (loopback lab).
            in_scope_hosts = [h for h in hosts if scope.is_allowed(f"http://{h}/")]
            return {"action": "scope_hosts", "hosts": sorted(set(in_scope_hosts))}

        if args.action == "resolve":
            host = (args.host or "").strip().lower()
            if not host:
                raise ToolError("resolve requires a 'host' argument")
            addr = _LOOPBACK.get(host)
            in_scope = scope.is_allowed(f"http://{host}/")
            return {
                "action": "resolve",
                "host": host,
                "addresses": [addr] if addr else [],  # loopback-only; no real DNS
                "in_scope": in_scope,
            }

        raise ToolError(f"unknown recon action: {args.action}")


def _hosts_from_scope(scope_cfg) -> list[str]:
    hosts: list[str] = []
    for rule in scope_cfg.in_scope:
        if rule.kind is ScopeKind.DOMAIN:
            hosts.append(rule.value)
        elif rule.kind is ScopeKind.URL_PREFIX:
            h = urlsplit(rule.value).hostname
            if h:
                hosts.append(h)
        elif rule.kind is ScopeKind.WILDCARD:
            hosts.append(rule.value[2:])  # strip "*."
    return hosts
