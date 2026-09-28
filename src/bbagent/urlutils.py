"""Shared URL normalization helpers.

Single source of truth for path templating and endpoint keys, used by both the
attack-surface mapper and finding deduplication so they never diverge.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

_NUMERIC = re.compile(r"^\d+$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEXID = re.compile(r"^[0-9a-f]{16,}$", re.I)

# A slug that mixes letters and digits and reads like an object id, e.g.
# "note-a1", "order-2024". Deliberately conservative to avoid collapsing API
# version segments ("v1", "v2") or ordinary words.
_SLUG_ID = re.compile(r"^(?=.*\d)[A-Za-z0-9][A-Za-z0-9._-]*$")
_VERSION = re.compile(r"^v\d+$", re.I)


def looks_like_id(segment: str) -> bool:
    if not segment:
        return False
    if _NUMERIC.match(segment) or _UUID.match(segment) or _HEXID.match(segment):
        return True
    if _VERSION.match(segment):
        return False
    # Slug ids must mix letters and digits and be reasonably long.
    return bool(_SLUG_ID.match(segment)) and len(segment) >= 4 and not segment.isalpha()


def id_kind(segment: str) -> str | None:
    """Classify an id-like path segment, or None if it isn't id-like."""
    if _NUMERIC.match(segment):
        return "numeric"
    if _UUID.match(segment):
        return "uuid"
    if _HEXID.match(segment):
        return "hexid"
    if looks_like_id(segment):
        return "path_id"
    return None


def templatize_path(path: str) -> str:
    """Collapse id-like segments to ``{id}`` so equivalent endpoints dedupe."""
    out = []
    for seg in path.split("/"):
        out.append("{id}" if seg and looks_like_id(seg) else seg)
    return "/".join(out)


def host_port(url: str) -> str:
    """Return ``host`` or ``host:port`` (port omitted when default/absent)."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.port:
        return f"{host}:{parts.port}"
    return host


def endpoint_key(method: str, url: str) -> str:
    """Stable key for an endpoint: METHOD scheme://host[:port]/templated/path."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    templated = templatize_path(parts.path or "/")
    return f"{method.upper()} {scheme}://{host_port(url)}{templated}"


def query_param_names(url: str) -> list[str]:
    """Sorted, de-duplicated query parameter names present in ``url``."""
    parts = urlsplit(url)
    return sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)})
