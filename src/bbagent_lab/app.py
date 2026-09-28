"""A tiny deliberately-vulnerable WSGI application (localhost only).

Endpoints
---------
GET /                      Discovery manifest (JSON) listing endpoints + example objects.
GET /api/notes/{id}        VULNERABLE — any authenticated user can read ANY note (broken
                           object-level authorization / IDOR).
GET /api/profile/{id}      CORRECTLY PROTECTED — only the owner may read their profile;
                           others get 403.

Authentication: ``Authorization: Bearer <token>`` using the synthetic tokens in
``data.py``. Missing/invalid token -> 401.

Pure stdlib (wsgiref-compatible). No external calls, ever.
"""

from __future__ import annotations

import json
import re
from typing import Callable, Iterable

from bbagent_lab import data

_JSON = [("Content-Type", "application/json")]

_NOTE_RE = re.compile(r"^/api/notes/(?P<id>[^/]+)$")
_PROFILE_RE = re.compile(r"^/api/profile/(?P<id>[^/]+)$")


def _resp(start_response, status: str, payload: dict) -> Iterable[bytes]:
    body = json.dumps(payload).encode("utf-8")
    start_response(status, _JSON + [("Content-Length", str(len(body)))])
    return [body]


def _authenticate(environ) -> str | None:
    """Return the authenticated user's label, or None."""
    header = environ.get("HTTP_AUTHORIZATION", "")
    if header.lower().startswith("bearer "):
        token = header[7:].strip()
        return data.label_for_token(token)
    return None


def _manifest() -> dict:
    """Discovery document the recon step consumes."""
    return {
        "application": "bbagent-lab",
        "endpoints": [
            {
                "url": "/api/notes/{id}",
                "method": "GET",
                "object_scoped": True,
                "object_param": "id",
                # An example object owned by user_a — the recon step turns this into
                # a concrete, testable target.
                "example_object_url": "/api/notes/note-a1",
                "owner": "user_a",
                "auth_class": "object",
            },
            {
                "url": "/api/profile/{id}",
                "method": "GET",
                "object_scoped": True,
                "object_param": "id",
                "example_object_url": "/api/profile/1001",
                "owner": "user_a",
                "auth_class": "object",
            },
        ],
    }


def create_app() -> Callable:
    def app(environ, start_response) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "/")

        if method != "GET":
            return _resp(start_response, "405 Method Not Allowed", {"error": "method_not_allowed"})

        if path == "/":
            return _resp(start_response, "200 OK", _manifest())

        # Everything under /api requires authentication.
        identity = _authenticate(environ)
        if path.startswith("/api/"):
            if identity is None:
                return _resp(start_response, "401 Unauthorized", {"error": "unauthenticated"})

        # --- VULNERABLE: notes have no per-object authorization check. -----------
        m = _NOTE_RE.match(path)
        if m:
            note = data.NOTES.get(m.group("id"))
            if note is None:
                return _resp(start_response, "404 Not Found", {"error": "not_found"})
            # BUG: returns the note regardless of who owns it.
            return _resp(start_response, "200 OK", {"note": note})

        # --- CORRECTLY PROTECTED: profile checks ownership. ----------------------
        m = _PROFILE_RE.match(path)
        if m:
            profile = data.PROFILES.get(m.group("id"))
            if profile is None:
                return _resp(start_response, "404 Not Found", {"error": "not_found"})
            if profile["owner"] != identity:
                return _resp(start_response, "403 Forbidden", {"error": "forbidden"})
            return _resp(start_response, "200 OK", {"profile": profile})

        return _resp(start_response, "404 Not Found", {"error": "not_found"})

    return app
