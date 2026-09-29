"""Policy-gated HTTP for detector verification.

Detector verifiers must not talk to the HTTP client directly. They use this
gateway, which runs EVERY request through the same Program Policy Engine before
execution:

    verifier -> PolicyGatedHTTP -> policy (vuln-class / identity / scope /
                method / required-headers / forbidden-action / budget / data-scope)
             -> AuthorizedHTTPClient -> transport

A denied request raises ``RequestBlocked`` and never reaches the transport. An
allowed request records the policy budget, injects the identity credential
server-side (never LLM-visible), and returns the raw ``HTTPExchange`` so the
verification engine can store immutable evidence. This is the single gated path;
there is no second bypass.
"""

from __future__ import annotations

from typing import Optional

from bbagent.http.client import AuthorizedHTTPClient, HTTPExchange, RequestBlocked
from bbagent.policy.engine import ProgramPolicyEngine
from bbagent.program.manager import ProgramManager
from bbagent.tools.base import ToolRequest


class PolicyGatedHTTP:
    def __init__(self, program: ProgramManager, policy: ProgramPolicyEngine,
                 http: AuthorizedHTTPClient):
        self._program = program
        self._policy = policy
        self._http = http
        #: set by the verification engine to the hypothesis's vulnerability class.
        self.vuln_class: Optional[str] = None

    async def request(
        self, method: str, url: str, *, headers: Optional[dict] = None,
        params: Optional[dict] = None, content=None, identity: Optional[str] = None,
        requested_action: str = "",
    ) -> HTTPExchange:
        # Policy sees only what the verifier explicitly set (not the injected token).
        req = ToolRequest(
            tool="http",
            arguments={"url": url, "method": method, "headers": dict(headers or {})},
            target=url, identity=identity, vuln_class=self.vuln_class,
            requested_action=requested_action,
        )
        decision = self._policy.evaluate(req)
        if not decision.allowed:
            raise RequestBlocked(f"policy denied [{decision.matched_rule}]: {decision.reason}")
        self._policy.record(req)

        final_headers = dict(headers or {})
        if identity is not None:
            token = self._program.resolve_account_secret(identity)
            if token:
                final_headers["Authorization"] = f"Bearer {token}"
            else:
                final_headers["X-Test-Identity"] = identity  # for local mock targets
        return await self._http.request(method, url, headers=final_headers,
                                        params=params, content=content)

    async def get(self, url: str, **kw) -> HTTPExchange:
        return await self.request("GET", url, **kw)
