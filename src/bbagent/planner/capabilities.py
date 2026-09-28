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
    return reg
