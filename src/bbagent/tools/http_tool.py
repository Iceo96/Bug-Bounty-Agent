"""HTTP tool — wraps the existing AuthorizedHTTPClient behind the Tool interface.

It does NOT reimplement HTTP. It delegates to AuthorizedHTTPClient, which keeps
enforcing scope, exclusions, allowed methods, required headers, active-testing,
dry-run, rate limits, and request budgets. The reasoning layer never touches the
client — it only receives a sanitized result (secret header values redacted).

Required headers are force-applied last, so a caller can never remove or override
them here (the policy engine also denies override attempts). If an ``identity``
handle is given, its bearer token is resolved from the environment inside this
tool and never exposed to the reasoning layer.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from bbagent.tools.base import Tool, ToolError

_REDACT_HEADERS = {"authorization", "cookie", "set-cookie", "verifyauthtoken",
                   "x-verify-auth-token", "proxy-authorization", "x-api-key", "x-auth-token"}
_REDACTED = "[REDACTED]"


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k: (_REDACTED if k.lower() in _REDACT_HEADERS else v) for k, v in headers.items()}


class HttpArgs(BaseModel):
    model_config = {"extra": "forbid"}

    url: str = Field(min_length=1)
    method: str = "GET"
    params: dict = Field(default_factory=dict)
    headers: dict = Field(default_factory=dict)


class HttpTool(Tool):
    name = "http"
    description = "Perform a scope- and policy-enforced HTTP request via AuthorizedHTTPClient."
    version = "1.0.0"
    permissions = ["network:http:in-scope"]
    args_model = HttpArgs
    output_schema = {
        "status_code": "int", "url": "str", "method": "str", "content_type": "str",
        "body": "str", "response_headers": "dict (secrets redacted)", "elapsed_ms": "float",
        "identity": "str|null (handle only)",
    }

    async def execute(self, args: HttpArgs, ctx) -> dict:
        if ctx.http is None:
            raise ToolError("no HTTP client available in tool context")

        # Build headers: caller-supplied, then force required headers so they can
        # never be removed/overridden here. Any resolved identity bearer token was
        # injected by the router (from the environment) and is never LLM-visible.
        headers: dict[str, str] = dict(args.headers)
        headers.update(ctx.program.required_headers)  # required always wins

        exchange = await ctx.http.request(
            args.method, args.url, headers=headers, params=args.params or None,
        )
        return {
            "status_code": exchange.status_code,
            "url": exchange.url,
            "method": exchange.method,
            "content_type": exchange.response_headers.get("content-type", ""),
            "body": exchange.response_body,
            "response_headers": _redact_headers(exchange.response_headers),
            "elapsed_ms": round(exchange.elapsed_ms, 1),
        }
