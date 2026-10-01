"""Autonomous browser exploration engine.

Loop: OBSERVE -> UPDATE attack-surface -> ASK chooser for the next safe action ->
POLICY CHECK -> browser action -> capture traffic -> update state -> repeat.

It reuses :class:`BrowserController` (single-step ``act`` + ``ingest_exchanges``),
:class:`NetworkObservationIngestor`, the :class:`SurfaceStore`, and the same
LLM plumbing shape as the hypothesis planner (a completion fn + strict schema +
deterministic fallback). It builds NOTHING that already exists.

Hard guarantees:
  * Only navigate/click/type/scroll, all schema-validated (``ExplorationActionModel``).
  * NO invented URLs: navigation targets come only from observed page links, form
    actions, or previously observed in-scope endpoint URLs. The chooser (LLM or
    deterministic) may only *select a candidate id* the engine generated — it can
    never craft a raw target.
  * Scope is fail-closed (ScopeEngine) for every navigation, checked again at the
    policy step.
  * No vulnerability testing, no direct HTTP, no credential guessing (fields whose
    name looks secret are never typed into).
  * Bounded: max actions, max pages, max wall-clock, and no-progress / repeated-state
    detection all stop the loop.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Callable, Literal, Optional
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, ValidationError, model_validator

from bbagent.browser.affordances import parse_affordances
from bbagent.browser.controller import BrowserController, ExplorationStep
from bbagent.browser.models import ObservedExchange
from bbagent.logging_config import get_logger
from bbagent.surface.models import AuthIdentity
from bbagent.surface.store import SurfaceStore

log = get_logger(__name__)

_ACTIONS = ("goto", "click", "type", "scroll")
# Field names we must never type into (no credential/secret guessing).
_SECRET_HINTS = ("pass", "pwd", "secret", "token", "otp", "cvv", "card", "ssn", "auth", "pin")
# A benign, non-secret value typed into ordinary inputs to exercise them.
_BENIGN_TEXT = "explore"


class ExplorationRejected(Exception):
    """The chooser's response was invalid and must be discarded (-> fallback)."""


# --- schema-validated action --------------------------------------------------

class ExplorationActionModel(BaseModel):
    model_config = {"extra": "forbid"}

    action: Literal["goto", "click", "type", "scroll"]
    target: Optional[str] = None
    text: Optional[str] = None
    amount: int = Field(default=3, ge=1, le=20)

    @model_validator(mode="after")
    def _check(self) -> "ExplorationActionModel":
        if self.action in ("goto", "click", "type") and not self.target:
            raise ValueError(f"{self.action} requires a target")
        if self.action == "type" and self.text is None:
            raise ValueError("type requires text")
        return self

    def to_step(self) -> ExplorationStep:
        return ExplorationStep(action=self.action, target=self.target,
                               text=self.text, amount=self.amount,
                               secret=False)


class ChooserDecision(BaseModel):
    """The only thing a chooser may return: which candidate to run next."""

    model_config = {"extra": "forbid"}

    candidate_id: str = Field(min_length=1)
    rationale: str = Field(default="", max_length=1000)


@dataclass
class Candidate:
    candidate_id: str
    action: ExplorationActionModel
    reason: str

    def sanitized(self) -> dict:
        """What a chooser is allowed to see — never the typed text value."""
        tgt = self.action.target
        safe_target = tgt
        if self.action.action == "goto" and tgt:
            p = urlsplit(tgt)
            safe_target = f"{p.scheme}://{p.hostname}{p.path}"
        return {"candidate_id": self.candidate_id, "action": self.action.action,
                "target": safe_target, "reason": self.reason}


# --- choosers -----------------------------------------------------------------

class DeterministicChooser:
    """Picks the first candidate (engine pre-orders them by exploration priority)."""

    name = "deterministic"

    def choose(self, candidates: list[Candidate]) -> str:
        return candidates[0].candidate_id


_CHOOSER_PROMPT = (
    "You are a web-application EXPLORATION assistant. You are given a JSON array of "
    "candidate browser actions that have ALREADY been scope-checked and are safe. "
    "Your ONLY job is to choose which ONE to perform next to best map the app's "
    "attack surface.\n\n"
    "Rules you must obey:\n"
    "- Choose EXACTLY ONE candidate, by its candidate_id.\n"
    "- Do NOT invent candidates, URLs, selectors, or actions.\n"
    "- Return ONLY JSON: {\"candidate_id\": \"<id>\", \"rationale\": \"<text>\"}\n\n"
    "Candidates:\n"
)


class LLMExplorationChooser:
    """LLM chooser: selects a candidate id. Strictly validated; never trusted to
    produce a target. Any deviation raises and the engine falls back."""

    name = "llm"

    def __init__(self, complete: Callable[[str], str]):
        self._complete = complete

    def choose(self, candidates: list[Candidate]) -> str:
        known = {c.candidate_id for c in candidates}
        prompt = _CHOOSER_PROMPT + json.dumps([c.sanitized() for c in candidates], indent=2)
        raw = self._complete(prompt)
        try:
            start, end = raw.find("{"), raw.rfind("}")
            decision = ChooserDecision.model_validate_json(raw[start:end + 1] if start != -1 else raw)
        except (ValidationError, ValueError) as exc:
            raise ExplorationRejected("malformed chooser response") from exc
        if decision.candidate_id not in known:
            raise ExplorationRejected(f"chose unknown candidate {decision.candidate_id!r}")
        return decision.candidate_id


# --- limits + summary ---------------------------------------------------------

@dataclass
class ExplorationLimits:
    max_actions: int = 40
    max_pages: int = 15
    max_seconds: float = 60.0
    max_no_progress: int = 6


@dataclass
class ExplorationSummary:
    program: str
    actions_performed: int = 0
    pages_visited: int = 0
    navigations_refused: int = 0
    endpoints_discovered: int = 0
    object_refs_discovered: int = 0
    chooser: str = "deterministic"
    fell_back: int = 0
    stop_reason: str = ""
    # --- diagnostics (host-only / counts; NEVER secrets) ---------------------
    exchanges_seen: int = 0
    out_of_scope_dropped: int = 0
    dropped_hosts: list[str] = field(default_factory=list)   # host-only, deduped
    affordances_seen: int = 0            # links + forms + data-explore buttons found
    authenticated_endpoints: int = 0     # endpoints observed under an authenticated identity
    unauthenticated_endpoints: int = 0
    # Sanitized navigation failures (origin + error category/type; never secrets).
    navigation_failures: list[dict] = field(default_factory=list)

    def render(self) -> str:
        return "\n".join([
            f"# Autonomous exploration — {self.program}",
            f"chooser:               {self.chooser} (fallbacks: {self.fell_back})",
            f"actions performed:     {self.actions_performed}",
            f"pages visited:         {self.pages_visited}",
            f"navigations refused:   {self.navigations_refused}",
            f"endpoints discovered:  {self.endpoints_discovered}",
            f"object-ref candidates: {self.object_refs_discovered}",
            f"exchanges seen:        {self.exchanges_seen}",
            f"out-of-scope dropped:  {self.out_of_scope_dropped} "
            f"(hosts: {', '.join(self.dropped_hosts[:20]) or '-'})",
            f"affordances found:     {self.affordances_seen} (links+forms+buttons)",
            f"authenticated eps:     {self.authenticated_endpoints}  "
            f"unauthenticated eps: {self.unauthenticated_endpoints}",
            f"navigation failures:   {len(self.navigation_failures)} "
            f"({', '.join(sorted({f['category'] for f in self.navigation_failures})) or '-'})",
            f"stop reason:           {self.stop_reason}",
        ])


# --- engine -------------------------------------------------------------------

class AutonomousExplorer:
    def __init__(
        self,
        controller: BrowserController,
        surface: SurfaceStore,
        *,
        chooser=None,
        limits: ExplorationLimits | None = None,
    ):
        self.controller = controller
        self.surface = surface
        self.program_name = controller.program.name
        self._chooser = chooser or DeterministicChooser()
        self._fallback = DeterministicChooser()
        self.limits = limits or ExplorationLimits()

        self._visited: set[str] = set()
        self._done: set[str] = set()
        self._discovered_links: set[str] = set()
        self._list_pages: set[str] = set()
        self._scrolled: set[str] = set()
        self._aff_counted: set[str] = set()
        self._unavailable_origins: set[str] = set()   # origins that failed navigation this run
        self._current_url: str | None = None
        self._current_html: str | None = None

    # --- candidate generation from OBSERVED state -----------------------------

    @staticmethod
    def _is_secret_field(selector: str) -> bool:
        s = selector.lower()
        return any(h in s for h in _SECRET_HINTS)

    def _frontier(self) -> list[str]:
        urls: list[str] = []
        # observed links + previously observed in-scope endpoint URLs
        candidates = set(self._discovered_links)
        for ep in self.surface.list_endpoints(self.program_name):
            if ep.method == "GET":
                candidates.add(ep.url)
        for u in sorted(candidates):
            if u in self._visited:
                continue
            if not self.controller.in_scope(u):
                continue
            if _origin(u) in self._unavailable_origins:
                continue  # an origin that failed navigation this run — skip, no retry
            urls.append(u)
        return urls

    def _candidates(self) -> list[Candidate]:
        out: list[Candidate] = []

        def add(action: ExplorationActionModel, reason: str, sig: str) -> None:
            if sig in self._done:
                return
            out.append(Candidate(candidate_id=sig, action=action, reason=reason))

        # 1) interactions on the CURRENT page (types, clicks, scroll)
        if self._current_html and self._current_url:
            aff = parse_affordances(self._current_url, self._current_html)
            for sel in aff.field_selectors:
                if self._is_secret_field(sel):
                    continue  # never type into secret/credential fields
                add(ExplorationActionModel(action="type", target=sel, text=_BENIGN_TEXT),
                    "fill a non-secret input", f"type|{self._current_url}|{sel}")
            for sel in aff.click_selectors:
                add(ExplorationActionModel(action="click", target=sel),
                    "activate a page control", f"click|{self._current_url}|{sel}")
            if self._current_url in self._list_pages and self._current_url not in self._scrolled:
                add(ExplorationActionModel(action="scroll", amount=3),
                    "load more of a paginated list", f"scroll|{self._current_url}")

        # 2) navigations to observed, in-scope, unvisited URLs
        for url in self._frontier():
            add(ExplorationActionModel(action="goto", target=url),
                "visit an observed in-scope URL", f"goto|{url}")

        return out

    # --- policy check (defense-in-depth over the frontier filter) -------------

    def _policy_ok(self, action: ExplorationActionModel) -> bool:
        if action.action not in _ACTIONS:
            return False
        if action.action == "goto":
            return bool(action.target) and self.controller.in_scope(action.target)
        return True

    # --- state update from captured traffic -----------------------------------

    def _update_state(self, step: ExplorationStep, exchanges: list[ObservedExchange]) -> None:
        for ex in exchanges:
            ct = (ex.response_content_type or "").lower()
            if ex.response_body and "html" in ct:
                for link in parse_affordances(ex.url, ex.response_body).links:
                    self._discovered_links.add(link)
                # the main document for a goto becomes the current page
                if step.action == "goto" and ex.url.split("#", 1)[0] == (step.target or "").split("#", 1)[0]:
                    self._current_url = ex.url.split("#", 1)[0]
                    self._current_html = ex.response_body
            if ex.response_body and "json" in ct:
                try:
                    parsed = json.loads(ex.response_body)
                except (json.JSONDecodeError, ValueError):
                    parsed = None
                if _has_list(parsed) and self._current_url:
                    self._list_pages.add(self._current_url)

    def _surface_size(self) -> int:
        n = 0
        for ep in self.surface.list_endpoints(self.program_name):
            n += 1
            n += len(self.surface.object_refs_for(ep.id))
        return n

    # --- main loop ------------------------------------------------------------

    async def run(self, seed_urls: list[str]) -> ExplorationSummary:
        summary = ExplorationSummary(program=self.program_name, chooser=self._chooser.name)
        for u in seed_urls:
            if self.controller.in_scope(u):
                self._discovered_links.add(u)
        started = time.monotonic()
        no_progress = 0

        await self.controller.start()
        try:
            while True:
                if summary.actions_performed >= self.limits.max_actions:
                    summary.stop_reason = "max_actions reached"; break
                if summary.pages_visited >= self.limits.max_pages:
                    summary.stop_reason = "max_pages reached"; break
                if time.monotonic() - started >= self.limits.max_seconds:
                    summary.stop_reason = "max_seconds reached"; break
                if no_progress >= self.limits.max_no_progress:
                    summary.stop_reason = "no new surface (repeated state)"; break

                candidates = self._candidates()
                if not candidates:
                    summary.stop_reason = "frontier exhausted"; break

                cid = self._choose(candidates, summary)
                chosen = next(c for c in candidates if c.candidate_id == cid)

                # POLICY CHECK
                if not self._policy_ok(chosen.action):
                    self._done.add(chosen.candidate_id)
                    continue

                step = chosen.action.to_step()
                before = self._surface_size()
                try:
                    outcome = await self.controller.act(step)
                except Exception as exc:  # noqa: BLE001 - a nav/network failure must not
                    # crash the whole research loop. Record a sanitized diagnostic, mark
                    # the origin unavailable for THIS run, and continue with the rest.
                    self._done.add(chosen.candidate_id)
                    category = _classify_nav_error(exc)
                    origin = _origin(step.target) if step.target else None
                    summary.navigation_failures.append({
                        "action": step.action, "url": step.target, "origin": origin,
                        "category": category, "error_type": type(exc).__name__,
                        "message": _sanitize_error(str(exc)),
                    })
                    if step.action == "goto" and origin:
                        self._unavailable_origins.add(origin)   # skip this origin; no retry
                    log.warning("explorer.navigation_failed", action=step.action,
                                origin=origin, category=category, error_type=type(exc).__name__)
                    no_progress += 1
                    continue
                self._done.add(chosen.candidate_id)

                if outcome.refused_out_of_scope:
                    summary.navigations_refused += 1
                    continue
                if not outcome.performed:
                    continue

                rep = self.controller.ingest_exchanges(outcome.exchanges)
                # Diagnostics: how much traffic was seen vs dropped out-of-scope
                # (host-only — never any URL query, cookie, or token value).
                summary.exchanges_seen += rep.exchanges_seen
                summary.out_of_scope_dropped += rep.out_of_scope_dropped
                for h in rep.dropped_examples:
                    if h not in summary.dropped_hosts:
                        summary.dropped_hosts.append(h)
                if rep.exchanges_seen:
                    log.info("explorer.ingest_diag", action=step.action,
                             seen=rep.exchanges_seen, in_scope=rep.in_scope,
                             dropped=rep.out_of_scope_dropped,
                             dropped_hosts=sorted(set(rep.dropped_examples))[:20])
                if step.action == "goto" and step.target:
                    tgt = step.target.split("#", 1)[0]
                    if tgt not in self._visited:
                        self._visited.add(tgt)
                        summary.pages_visited += 1
                if step.action == "scroll" and self._current_url:
                    self._scrolled.add(self._current_url)
                self._update_state(step, outcome.exchanges)
                summary.actions_performed += 1

                # Affordance diagnostic: count links/forms/buttons the CURRENT page
                # actually exposed in its HTML (pinpoints SPA/dynamic-render gaps).
                if (self._current_url and self._current_html
                        and self._current_url not in self._aff_counted):
                    self._aff_counted.add(self._current_url)
                    aff = parse_affordances(self._current_url, self._current_html)
                    summary.affordances_seen += (len(aff.links) + len(aff.forms)
                                                 + len(aff.click_selectors))
                    log.info("explorer.affordances", host=urlsplit(self._current_url).hostname,
                             links=len(aff.links), forms=len(aff.forms),
                             buttons=len(aff.click_selectors))

                after = self._surface_size()
                no_progress = 0 if after > before else no_progress + 1
        finally:
            await self.controller.close()

        endpoints = self.surface.list_endpoints(self.program_name)
        summary.endpoints_discovered = len(endpoints)
        summary.object_refs_discovered = sum(
            len(self.surface.object_refs_for(ep.id)) for ep in endpoints)
        # Auth diagnostic: how each in-scope endpoint was observed (identity VALUE
        # only, e.g. "identity_a"/"unauthenticated" — never a cookie/token value).
        unauth = AuthIdentity.UNAUTHENTICATED.value
        for ep in endpoints:
            idents = {o.identity for o in self.surface.auth_observations_for(ep.id)}
            if idents - {unauth}:
                summary.authenticated_endpoints += 1
            elif idents:
                summary.unauthenticated_endpoints += 1
        if not summary.stop_reason:
            summary.stop_reason = "completed"
        log.info("explorer.done", program=self.program_name,
                 actions=summary.actions_performed, endpoints=summary.endpoints_discovered,
                 exchanges_seen=summary.exchanges_seen, dropped=summary.out_of_scope_dropped,
                 affordances=summary.affordances_seen,
                 authed_eps=summary.authenticated_endpoints,
                 unauth_eps=summary.unauthenticated_endpoints, stop=summary.stop_reason)
        return summary

    def _choose(self, candidates: list[Candidate], summary: ExplorationSummary) -> str:
        try:
            return self._chooser.choose(candidates)
        except ExplorationRejected as exc:
            log.warning("explorer.chooser_fallback", reason=str(exc))
            summary.fell_back += 1
            return self._fallback.choose(candidates)
        except Exception as exc:  # noqa: BLE001 - any chooser failure -> safe fallback
            log.warning("explorer.chooser_error", error=str(exc))
            summary.fell_back += 1
            return self._fallback.choose(candidates)


def _origin(url: str | None) -> str | None:
    if not url:
        return None
    p = urlsplit(url)
    if not p.scheme or not p.hostname:
        return None
    return f"{p.scheme}://{p.hostname}" + (f":{p.port}" if p.port else "")


def _classify_nav_error(exc: Exception) -> str:
    """Categorize a browser navigation/network error from its message (no secrets)."""
    low = str(exc).lower()
    if "err_connection_reset" in low:
        return "connection_reset"
    if "err_connection_refused" in low:
        return "connection_refused"
    if "err_timed_out" in low or "timeout" in low or "timed out" in low:
        return "timed_out"
    if ("err_name_not_resolved" in low or "err_address_unreachable" in low
            or "err_internet_disconnected" in low or "getaddrinfo" in low):
        return "dns_or_network"
    if "err_cert" in low or "err_ssl" in low or "ssl" in low:
        return "tls_security"   # recorded + skipped; never bypassed
    if "net::" in low or "page.goto" in low or "navigation" in low:
        return "navigation_error"
    return "other"


def _sanitize_error(message: str) -> str:
    """First line only, truncated. Navigation errors carry no auth material, but we
    keep this conservative so nothing unexpected is retained."""
    first = (message or "").splitlines()[0] if message else ""
    return first[:200]


def seed_origins_from_scope(program) -> list[str]:
    """Derive browser seed origins from the program's EXPLICIT in-scope web assets.

    Exact-host (DOMAIN) rules become ``https://<host>/``; URL_PREFIX rules seed at
    their prefix. WILDCARD and CIDR rules are NOT seeded (you cannot browse a
    wildcard or an IP range as an origin), and nothing here widens scope — every
    derived origin already passes the unchanged ScopeEngine. Non-HTTP program
    assets (e.g. mobile package / App Store ids) are not in ``scope.in_scope`` and
    so are never produced here.
    """
    from bbagent.config.models import ScopeKind

    origins: list[str] = []
    for rule in program.config.scope.in_scope:
        if rule.kind is ScopeKind.DOMAIN:
            origins.append(f"https://{rule.value}/")
        elif rule.kind is ScopeKind.URL_PREFIX:
            origins.append(rule.value)
        # WILDCARD / CIDR: intentionally skipped (not a browsable origin).
    seen: dict[str, None] = {}
    for o in origins:
        seen.setdefault(o, None)
    return list(seen.keys())


def _has_list(node) -> bool:
    if isinstance(node, list):
        return True
    if isinstance(node, dict):
        return any(_has_list(v) for v in node.values())
    return False
