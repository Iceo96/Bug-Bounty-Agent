"""HAR (HTTP Archive 1.2) reader.

Parses a HAR export — the standard format that browsers/devtools use to record a
session's network traffic — into :class:`ObservedExchange` objects. We read ONLY
what the browser actually observed; nothing here fabricates or infers endpoints.

The reader is deliberately tolerant: malformed or partial entries are skipped
rather than raising, so a large real-world HAR never aborts ingestion.
"""

from __future__ import annotations

import json
from typing import Iterable

from bbagent.browser.models import ObservedExchange


def _headers_to_dict(items: Iterable[dict]) -> dict[str, str]:
    out: dict[str, str] = {}
    for h in items or []:
        name = h.get("name")
        if not name:
            continue
        # HAR may repeat headers; last value wins (we never persist these anyway).
        out[str(name)] = str(h.get("value", ""))
    return out


def _referer(req_headers: dict[str, str]) -> str | None:
    for k, v in req_headers.items():
        if k.lower() == "referer":
            return v or None
    return None


def parse_har(data: str | bytes | dict) -> list[ObservedExchange]:
    """Parse HAR text/bytes/dict into a list of ObservedExchange.

    A per-entry custom field ``_identity`` (a non-standard extension some capture
    tools add) is honored as the identity label if present.
    """
    if isinstance(data, (str, bytes)):
        try:
            doc = json.loads(data)
        except (json.JSONDecodeError, ValueError):
            return []
    else:
        doc = data

    log = (doc or {}).get("log") or {}
    entries = log.get("entries") or []
    out: list[ObservedExchange] = []

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        req = entry.get("request") or {}
        resp = entry.get("response") or {}
        url = req.get("url")
        method = req.get("method")
        if not url or not method:
            continue

        req_headers = _headers_to_dict(req.get("headers") or [])
        resp_headers = _headers_to_dict(resp.get("headers") or [])

        post = req.get("postData") or {}
        req_body = post.get("text") if isinstance(post, dict) else None

        content = resp.get("content") or {}
        resp_body = content.get("text") if isinstance(content, dict) else None

        status = resp.get("status")
        try:
            status = int(status) if status is not None else None
        except (TypeError, ValueError):
            status = None
        if status == 0:  # HAR uses 0 for failed/aborted requests
            status = None

        source_page = entry.get("pageref") or _referer(req_headers)
        identity_label = entry.get("_identity")

        out.append(ObservedExchange(
            method=str(method).upper(),
            url=str(url),
            status=status,
            request_headers=req_headers,
            request_body=req_body,
            response_headers=resp_headers,
            response_body=resp_body,
            source_page=source_page,
            identity_label=identity_label,
        ))
    return out
