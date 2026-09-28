"""Finding deduplication.

Two findings are considered the same underlying vulnerability when they share a
normalized (vuln_type, host, path-template, method) signature. Numeric and
UUID-like path segments are collapsed so ``/users/1`` and ``/users/2`` dedupe.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit

_NUMERIC = re.compile(r"^\d+$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEXID = re.compile(r"^[0-9a-f]{16,}$", re.I)


def _templatize(path: str) -> str:
    parts = []
    for seg in path.split("/"):
        if _NUMERIC.match(seg) or _UUID.match(seg) or _HEXID.match(seg):
            parts.append("{id}")
        else:
            parts.append(seg)
    return "/".join(parts)


def compute_dedup_key(vuln_type: str, url: str, method: str) -> str:
    """Return a stable dedup key for a candidate finding."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    template = _templatize(parts.path or "/")
    signature = f"{vuln_type.lower()}|{method.upper()}|{host}|{template}"
    return hashlib.sha256(signature.encode("utf-8")).hexdigest()[:16]


def is_duplicate(existing_keys: set[str], candidate_key: str) -> bool:
    return candidate_key in existing_keys
