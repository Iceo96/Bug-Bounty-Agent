"""Sanitize candidate data before it is ever sent to an LLM.

Two defenses:
  1. Key allow-list — only non-sensitive fields are forwarded; any key that names
     a credential/secret is dropped outright.
  2. Value scrubbing — free-text fields are scrubbed of anything resembling a
     token, bearer credential, or long opaque secret.

The planner's candidate data does not normally contain secrets (tokens live only
in the environment and in verifier request headers, never in a hypothesis), but
this makes that guarantee explicit and enforced.
"""

from __future__ import annotations

import re

# Fields safe to share with the LLM for prioritization reasoning.
_ALLOWED_KEYS = {
    "hypothesis_id",
    "vulnerability_class",
    "target",
    "endpoint",
    "method",
    "reasoning",
    "expected_signal",
    "required_auth_context",
    "priority",
    "priority_score",
    "parent_observation",
}

# Keys that must never be forwarded, regardless of value.
_SECRET_KEYS = {
    "authorization", "token", "secret", "password", "passwd", "api_key", "apikey",
    "cookie", "set-cookie", "credentials", "credential", "bearer", "required_inputs",
    "session", "access_token", "refresh_token",
}

# Free-text fields that get value-level scrubbing.
_TEXT_FIELDS = {"reasoning", "expected_signal"}

_SECRET_RE = re.compile(
    r"(?i)(bearer\s+[A-Za-z0-9._\-]+"        # bearer tokens
    r"|tok_[A-Za-z0-9._\-]+"                  # our test-token style
    r"|[A-Za-z0-9_\-]{32,})"                  # long opaque strings
)

REDACTED = "[REDACTED]"


def scrub_text(text: str) -> str:
    return _SECRET_RE.sub(REDACTED, text)


def sanitize_candidate(candidate: dict) -> dict:
    """Return a copy containing only allow-listed, scrubbed fields."""
    out: dict = {}
    for key, value in candidate.items():
        if key.lower() in _SECRET_KEYS:
            continue
        if key not in _ALLOWED_KEYS:
            continue
        if key in _TEXT_FIELDS and isinstance(value, str):
            value = scrub_text(value)
        elif isinstance(value, list):
            value = [scrub_text(v) if isinstance(v, str) else v for v in value]
        out[key] = value
    return out


def sanitize_candidates(candidates: list[dict]) -> list[dict]:
    return [sanitize_candidate(c) for c in candidates]
