"""Capability registry: what each detector/verifier can test.

A capability is metadata + deterministic heuristics over the attack-surface
graph. It decides *whether* an endpoint is worth a candidate test and *how
strongly*, and it describes the test — it never performs one. Execution always
goes through the registered detector/verifier via the verification engine.

Only the existing IDOR / access-control capability is registered here. No new
vulnerability classes are added in this task.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from bbagent.program.manager import ProgramManager
from bbagent.surface.models import AuthObservation, Endpoint, ObjectRef, Parameter


@dataclass
class EndpointView:
    """An endpoint plus the graph facts a capability reasons over."""

    endpoint: Endpoint
    object_refs: list[ObjectRef] = field(default_factory=list)
    parameters: list[Parameter] = field(default_factory=list)
    auth_observations: list[AuthObservation] = field(default_factory=list)

    @property
    def is_api(self) -> bool:
        return self.endpoint.path.startswith("/api")

    @property
    def distinct_identity_count(self) -> int:
        return len({o.identity for o in self.auth_observations})

    @property
    def has_differing_auth(self) -> bool:
        """True when identities were treated differently (observable boundary)."""
        seen = {tuple(o.status_codes) for o in self.auth_observations}
        return len(seen) >= 2


@dataclass
class PlanCandidate:
    """A capability's proposal for one endpoint (pre-dedup, pre-scoring finalize)."""

    vulnerability_class: str
    target_url: str
    method: str
    reasoning: str
    score: int
    required_auth_context: list[str]
    required_inputs: dict
    expected_signal: str
    object_ref_values: list[str]
    active: bool


class Capability(ABC):
    vuln_class: str = "generic"
    title: str = "capability"
    description: str = ""
    active: bool = False  # True => state-changing; gated behind allow_active_testing

    @abstractmethod
    def propose(self, view: EndpointView, program: ProgramManager) -> PlanCandidate | None:
        """Return a candidate if this capability applies to the endpoint, else None."""
        raise NotImplementedError


class AccessControlCapability(Capability):
    """IDOR / broken object-level authorization (read-only, GET)."""

    vuln_class = "idor"
    title = "Authorization boundary (IDOR/BOLA)"
    description = (
        "Detects broken object-level authorization by comparing what two "
        "authorized identities can read for the same object. Read-only."
    )
    active = False

    def _identities(self, program: ProgramManager) -> list[str]:
        accts = program.config.test_accounts
        if len(accts) >= 2:
            return [accts[0].label, accts[1].label]
        return ["identity_a", "identity_b"]

    def propose(self, view: EndpointView, program: ProgramManager) -> PlanCandidate | None:
        # Applicability: an object reference must exist, and we need at least two
        # authorized identities OR the endpoint was observed under multiple ones.
        has_object = bool(view.object_refs)
        enough_identities = len(program.config.test_accounts) >= 2 or view.distinct_identity_count >= 2
        if not (has_object and enough_identities):
            return None

        score = 0
        reasons: list[str] = []
        if has_object:
            score += 50
            kinds = sorted({o.kind for o in view.object_refs})
            reasons.append(f"object reference ({', '.join(kinds)})")
        if len(program.config.test_accounts) >= 2:
            score += 20
            reasons.append("multiple authorized test identities available")
        if view.distinct_identity_count >= 2:
            score += 15
            reasons.append("observed under multiple identity contexts")
        if view.has_differing_auth:
            score += 15
            reasons.append("differing authorization observations across identities")
        if view.endpoint.auth_requirement == "required":
            score += 10
            reasons.append("authentication required")
        if view.is_api:
            score += 10
            reasons.append("API endpoint")
        if view.parameters:
            score += 5
            reasons.append(f"{len(view.parameters)} parameter(s)")

        identities = self._identities(program)
        return PlanCandidate(
            vulnerability_class=self.vuln_class,
            target_url=view.endpoint.url,
            method="GET",
            reasoning="; ".join(reasons),
            score=score,
            required_auth_context=identities,
            required_inputs={"object_url": view.endpoint.url, "identities": identities},
            expected_signal=(
                f"{identities[1]} receives {identities[0]}'s object contents "
                f"(identical body), not 403/404"
            ),
            object_ref_values=[o.value for o in view.object_refs],
            active=self.active,
        )


class PrivilegeEscalationCapability(Capability):
    """Privilege escalation / broken function-level authorization (read-only, GET)."""

    vuln_class = "privilege_escalation"
    title = "Privilege escalation (BFLA)"
    description = (
        "Detects broken function-level authorization: a non-privileged identity "
        "reaching a privileged/admin function and receiving restricted content. "
        "Read-only."
    )
    active = False

    def propose(self, view: EndpointView, program: ProgramManager) -> PlanCandidate | None:
        # Local import avoids a hard module dependency and registers the verifier.
        from bbagent.detectors.privilege import ADMIN_PATH, resolve_admin_regular

        if not ADMIN_PATH.search(view.endpoint.path):
            return None
        admin, regular = resolve_admin_regular(program)
        if admin is None or regular is None:
            return None  # need a privileged and a non-privileged identity

        score = 40
        reasons = ["administrative/privileged endpoint path"]
        if view.endpoint.auth_requirement == "required":
            score += 10
            reasons.append("authentication required")
        if view.is_api:
            score += 10
            reasons.append("API endpoint")
        if view.distinct_identity_count >= 2:
            score += 10
            reasons.append("observed under multiple identity contexts")
        if view.has_differing_auth:
            score += 10
            reasons.append("differing authorization observations across identities")
        if view.parameters:
            score += 5
            reasons.append(f"{len(view.parameters)} parameter(s)")

        return PlanCandidate(
            vulnerability_class=self.vuln_class,
            target_url=view.endpoint.url,
            method="GET",
            reasoning="; ".join(reasons),
            score=score,
            required_auth_context=[admin, regular],
            required_inputs={"privileged_url": view.endpoint.url,
                             "privileged_identity": admin, "test_identity": regular},
            expected_signal=(
                f"'{regular}' should be denied; must NOT receive the restricted content "
                f"that '{admin}' sees"
            ),
            object_ref_values=[],  # function-level: dedup by endpoint template
            active=self.active,
        )


class ReflectedXSSCapability(Capability):
    """Reflected XSS: proposes a test only when an endpoint has an input parameter."""

    vuln_class = "reflected_xss"
    title = "Reflected XSS"
    description = (
        "Detects reflected XSS by injecting a harmless marker payload into a "
        "user-controlled parameter and confirming, via deterministic HTML parsing, "
        "that it reflects as live markup (not encoded text). No browser execution."
    )
    active = False  # GET probe, non-destructive

    def propose(self, view: EndpointView, program: ProgramManager) -> PlanCandidate | None:
        from urllib.parse import urlsplit, urlunsplit

        query_params = [p.name for p in view.parameters if p.location == "query"]
        query_params = query_params or list(view.endpoint.query_params)
        if not query_params:
            return None  # no plausible user-controlled input
        param = sorted(query_params)[0]

        p = urlsplit(view.endpoint.url)
        base = urlunsplit((p.scheme, p.netloc, p.path, "", ""))
        target_url = f"{base}?{param}="

        score = 40
        reasons = [f"user-controlled parameter '{param}'"]
        if len(query_params) > 1:
            score += 10
            reasons.append(f"{len(query_params)} parameters")
        if view.endpoint.method.upper() == "GET":
            score += 10
            reasons.append("GET endpoint")
        if view.is_api:
            score += 5
            reasons.append("API endpoint")

        return PlanCandidate(
            vulnerability_class=self.vuln_class,
            target_url=target_url,
            method="GET",
            reasoning="; ".join(reasons),
            score=score,
            required_auth_context=[],  # reflected XSS needs no identity
            required_inputs={"param": param, "url": base},
            expected_signal="payload reflected as inert encoded text, not as live HTML markup",
            object_ref_values=[param],  # dedup per (endpoint, param)
            active=self.active,
        )


class CapabilityRegistry:
    def __init__(self) -> None:
        self._caps: list[Capability] = []

    def register(self, cap: Capability) -> Capability:
        self._caps.append(cap)
        return cap

    def all(self) -> list[Capability]:
        return list(self._caps)

    def describe(self) -> list[dict]:
        return [
            {"vuln_class": c.vuln_class, "title": c.title, "description": c.description,
             "active": c.active}
            for c in self._caps
        ]


def default_capabilities() -> CapabilityRegistry:
    reg = CapabilityRegistry()
    reg.register(AccessControlCapability())
    reg.register(PrivilegeEscalationCapability())
    reg.register(ReflectedXSSCapability())
    return reg
