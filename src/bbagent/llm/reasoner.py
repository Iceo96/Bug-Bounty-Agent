"""Production LLM Reasoner adapter (prioritization only).

Boundary guarantees:
  * The LLM receives only sanitized candidate data (see ``sanitize``) that has
    already passed the deterministic planner's scope and capability checks.
  * The LLM's response is parsed and validated against a strict Pydantic schema
    and the known candidate set. Any malformed response, unknown/invented
    candidate, or attempt to change target/endpoint/method is rejected.
  * On rejection the reasoner raises; the ``LLMPlanner`` then falls back to
    deterministic ordering (or aborts, if fallback is disabled).
  * The reasoner has no HTTP client, no DB, no filesystem writes, no shell, and
    no credentials. Its only outbound effect is the text completion call it is
    constructed with.
"""

from __future__ import annotations

import json
import os
from typing import Callable

from pydantic import ValidationError

from bbagent.config.models import LLMConfig
from bbagent.llm.sanitize import sanitize_candidates
from bbagent.llm.schema import ReasonerResponse
from bbagent.logging_config import get_logger

log = get_logger(__name__)

# A completion function takes a prompt string and returns raw model text.
CompleteFn = Callable[[str], str]


class ReasonerRejected(Exception):
    """The LLM response was invalid and must be discarded."""


class ReasonerUnavailable(Exception):
    """No usable LLM backend could be constructed (e.g. missing key/SDK)."""


_PROMPT_HEADER = (
    "You are a security-research prioritization assistant. You are given a JSON "
    "array of candidate test hypotheses that have ALREADY been scope- and "
    "capability-checked by a deterministic planner. Your ONLY job is to RANK them "
    "for investigation order and briefly explain why.\n\n"
    "Rules you must obey:\n"
    "- Do NOT invent candidates. Only use the given hypothesis_id values.\n"
    "- Do NOT change any target, endpoint, or method.\n"
    "- Do NOT suggest new URLs, actions, or tests.\n"
    "- Return ONLY JSON matching this shape:\n"
    '  {"ranking": [{"hypothesis_id": "<id>", "rank": <int>, "rationale": "<text>"}], '
    '"overall_reasoning": "<text>"}\n\n'
    "Candidates:\n"
)


def build_prompt(sanitized: list[dict]) -> str:
    return _PROMPT_HEADER + json.dumps(sanitized, indent=2)


def _extract_json(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("{"):
        return raw
    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end != -1 and end > start:
        return raw[start : end + 1]
    return raw  # let the parser fail -> rejection


class LLMReasoner:
    """Implements the planner's ``Reasoner`` protocol: ``rank(candidates) -> ids``."""

    def __init__(self, config: LLMConfig, complete: CompleteFn):
        self._config = config
        self._complete = complete

    def rank(self, candidates: list[dict]) -> list[str]:
        count = len(candidates)
        log.info("llm.candidates", count=count, max=self._config.max_candidates)
        if count == 0:
            return []

        limited = candidates[: self._config.max_candidates]
        known = {c["hypothesis_id"]: c for c in limited}
        prompt = build_prompt(sanitize_candidates(limited))

        log.info("llm.requested", model=self._config.model, candidates=len(limited))
        raw = self._complete(prompt)  # may raise (network/timeout) -> caller falls back

        try:
            resp = ReasonerResponse.model_validate_json(_extract_json(raw))
        except ValidationError as exc:
            log.warning("llm.response_rejected", reason="malformed", detail=str(exc)[:200])
            raise ReasonerRejected("malformed LLM response") from exc

        ordered = self._validate(resp, known)
        log.info("llm.response_validated", ranked=len(ordered))
        return ordered

    def _validate(self, resp: ReasonerResponse, known: dict[str, dict]) -> list[str]:
        seen: set[str] = set()
        for item in resp.ranking:
            if item.hypothesis_id not in known:
                self._reject("unknown or invented candidate", item.hypothesis_id)
            if item.hypothesis_id in seen:
                self._reject("duplicate candidate", item.hypothesis_id)
            seen.add(item.hypothesis_id)

            orig = known[item.hypothesis_id]
            if item.endpoint is not None and item.endpoint != orig.get("endpoint"):
                self._reject("attempted to modify endpoint", item.hypothesis_id)
            if item.target is not None and item.target != orig.get("target"):
                self._reject("attempted to modify target", item.hypothesis_id)
            if item.method is not None and item.method.upper() != str(orig.get("method")).upper():
                self._reject("attempted to modify method", item.hypothesis_id)

        ordered = [it.hypothesis_id for it in sorted(resp.ranking, key=lambda x: x.rank)]
        return ordered

    def _reject(self, reason: str, detail: str) -> None:
        log.warning("llm.response_rejected", reason=reason, detail=detail)
        raise ReasonerRejected(f"{reason}: {detail}")


# --- default backend ----------------------------------------------------------

def anthropic_complete(config: LLMConfig, api_key: str | None = None) -> CompleteFn:
    """Build a completion function backed by the Anthropic API.

    Raises :class:`ReasonerUnavailable` if the SDK or API key is missing. The
    returned callable takes a prompt and returns the model's text. It performs a
    single HTTPS call to the provider — no other network access is granted, and
    no credentials are ever placed into candidate data.
    """
    key = api_key or os.getenv("ANTHROPIC_API_KEY")
    if not key:
        raise ReasonerUnavailable("ANTHROPIC_API_KEY is not set")
    try:
        import anthropic  # type: ignore
    except ImportError as exc:  # pragma: no cover - depends on optional dep
        raise ReasonerUnavailable("anthropic SDK not installed") from exc

    client = anthropic.Anthropic(api_key=key)

    def _complete(prompt: str) -> str:  # pragma: no cover - exercised via live API only
        msg = client.messages.create(
            model=config.model,
            max_tokens=1024,
            timeout=config.timeout_seconds,
            messages=[{"role": "user", "content": prompt}],
        )
        parts = [b.text for b in msg.content if getattr(b, "type", None) == "text"]
        return "\n".join(parts)

    return _complete


def build_reasoner(config: LLMConfig, *, complete: CompleteFn | None = None) -> LLMReasoner:
    """Construct an :class:`LLMReasoner`, defaulting to the Anthropic backend."""
    fn = complete or anthropic_complete(config)
    return LLMReasoner(config, fn)
