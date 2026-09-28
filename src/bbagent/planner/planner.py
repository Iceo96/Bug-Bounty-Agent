"""Planners: turn the attack-surface graph into a prioritized hypothesis queue.

``DeterministicPlanner`` is the default and is fully testable without any LLM.
``LLMPlanner`` defines the integration boundary: an LLM may only *reorder or
annotate* candidate hypotheses that the deterministic layer already produced from
scope-bounded graph data. The LLM never receives the HTTP client, the database,
or any means to execute — all actions go through registered, scope-enforcing
tools driven by the runner.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

from bbagent.logging_config import get_logger
from bbagent.planner.capabilities import CapabilityRegistry, EndpointView, default_capabilities
from bbagent.planner.models import PlannedHypothesis, compute_plan_key
from bbagent.program.manager import ProgramManager
from bbagent.surface.store import SurfaceStore
from bbagent.urlutils import templatize_path

log = get_logger(__name__)


@dataclass
class PlanContext:
    """Inputs the planner reasons over. All read-only."""

    program: ProgramManager
    surface: SurfaceStore
    capabilities: CapabilityRegistry
    # dedup keys of hypotheses/findings already handled, to avoid regeneration.
    known_plan_keys: set[str]


class Planner(ABC):
    @abstractmethod
    def plan(self, ctx: PlanContext) -> list[PlannedHypothesis]:
        raise NotImplementedError


class DeterministicPlanner(Planner):
    """Rule-based, reproducible planner. No randomness, no network, no LLM."""

    def plan(self, ctx: PlanContext) -> list[PlannedHypothesis]:
        program_name = ctx.program.name
        candidates: dict[str, PlannedHypothesis] = {}

        for ep in ctx.surface.list_endpoints(program_name):
            view = EndpointView(
                endpoint=ep,
                object_refs=ctx.surface.object_refs_for(ep.id),
                parameters=ctx.surface.parameters_for(ep.id),
                auth_observations=ctx.surface.auth_observations_for(ep.id),
            )
            host = urlsplit(ep.url).hostname or ""
            template = templatize_path(urlsplit(ep.url).path or "/")

            for cap in ctx.capabilities.all():
                cand = cap.propose(view, ctx.program)
                if cand is None:
                    continue
                key = compute_plan_key(cand.vulnerability_class, host, template, cand.object_ref_values)
                if key in ctx.known_plan_keys:
                    continue  # already handled in a previous run — reuse, don't regenerate
                ph = PlannedHypothesis(
                    target=host,
                    endpoint=cand.target_url,
                    method=cand.method,
                    vulnerability_class=cand.vulnerability_class,
                    reasoning=cand.reasoning,
                    plan_key=key,
                    priority_score=cand.score,
                    required_auth_context=cand.required_auth_context,
                    required_inputs=cand.required_inputs,
                    expected_signal=cand.expected_signal,
                    parent_observation=f"surface_endpoint:{ep.id}",
                )
                # Keep the highest-scoring candidate per plan_key.
                existing = candidates.get(key)
                if existing is None or ph.priority_score > existing.priority_score:
                    candidates[key] = ph

        # Deterministic ordering: score desc, then plan_key asc for stable ties.
        ordered = sorted(candidates.values(), key=lambda h: (-h.priority_score, h.plan_key))
        log.info("planner.generated", program=program_name, count=len(ordered))
        return ordered


class Reasoner(Protocol):
    """A pluggable LLM-backed reasoner. Receives DATA ONLY, returns an ordering.

    It is handed a list of public candidate dicts and must return a list of
    ``hypothesis_id`` strings in the desired execution order. It has no other
    capabilities — no client, no DB, no execution.
    """

    def rank(self, candidates: list[dict]) -> list[str]:
        ...


class LLMPlanner(Planner):
    """Deterministic candidate generation + optional LLM reordering/annotation.

    The LLM boundary: the reasoner only sees serialized candidate data and only
    influences ORDER. If no reasoner is provided, behavior is identical to the
    deterministic planner. A misbehaving reasoner falls back to deterministic
    order. This class never grants the LLM network, shell, or DB access.
    """

    def __init__(self, reasoner: Reasoner | None = None,
                 base: Planner | None = None) -> None:
        self._reasoner = reasoner
        self._base = base or DeterministicPlanner()

    def plan(self, ctx: PlanContext) -> list[PlannedHypothesis]:
        candidates = self._base.plan(ctx)
        if self._reasoner is None:
            return candidates

        by_id = {c.hypothesis_id: c for c in candidates}
        try:
            order = self._reasoner.rank([c.to_public_dict() for c in candidates])
        except Exception as exc:  # noqa: BLE001 — never let the LLM break the run
            log.warning("planner.reasoner_failed", error=str(exc))
            return candidates

        ranked: list[PlannedHypothesis] = []
        seen: set[str] = set()
        for hid in order:
            c = by_id.get(hid)
            if c is not None and hid not in seen:
                ranked.append(c)
                seen.add(hid)
        # Append any candidates the reasoner omitted, in deterministic order.
        for c in candidates:
            if c.hypothesis_id not in seen:
                ranked.append(c)
        return ranked
