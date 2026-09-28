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

import html
import json
import re
from typing import Callable, Iterable
from urllib.parse import parse_qs

from bbagent_lab import data

_JSON = [("Content-Type", "application/json")]

_NOTE_RE = re.compile(r"^/api/notes/(?P<id>[^/]+)$")
_PROFILE_RE = re.compile(r"^/api/profile/(?P<id>[^/]+)$")


def _xss_manifest() -> dict:
    """Separate manifest for the reflected-XSS scenario (keeps others untouched)."""
    return {
        "application": "bbagent-lab-xss",
        "endpoints": [
            {"url": "/search", "method": "GET", "object_scoped": False,
             "example_object_url": "/search?q=probe", "input_param": "q"},
            {"url": "/search-safe", "method": "GET", "object_scoped": False,
             "example_object_url": "/search-safe?q=probe", "input_param": "q"},
            {"url": "/echo", "method": "GET", "object_scoped": False,
             "example_object_url": "/echo?q=probe", "input_param": "q"},
        ],
    }


def _query_param(environ, name: str) -> str:
    return parse_qs(environ.get("QUERY_STRING", "")).get(name, [""])[0]


def _admin_manifest() -> dict:
    """A SEPARATE discovery manifest for the function-level authorization scenario.

    Kept apart from the main manifest so the object-level (IDOR) scenario is
    unaffected. Lists admin/privileged function endpoints.
    """
    return {
        "application": "bbagent-lab-admin",
        "endpoints": [
            {"url": "/api/admin/report", "method": "GET", "object_scoped": False,
             "example_object_url": "/api/admin/report", "auth_class": "function",
             "privileged": True},
            {"url": "/api/admin/settings", "method": "GET", "object_scoped": False,
             "example_object_url": "/api/admin/settings", "auth_class": "function",
             "privileged": True},
            {"url": "/api/admin/ping", "method": "GET", "object_scoped": False,
             "example_object_url": "/api/admin/ping", "auth_class": "function",
             "privileged": True},
        ],
    }

# A small HTML site + JS bundle so the mapper can exercise real crawling and
# JavaScript discovery over the loopback socket.
_SITE_INDEX = """<!doctype html>
<html><head><title>Lab Portal</title>
<script src="/static/app.js"></script></head>
<body>
  <h1>Lab Portal</h1>
  <a href="/site/about">About</a>
  <a href="/site/notes">Notes</a>
  <form action="/api/search" method="get">
    <input name="q"><input name="page"><input name="limit">
  </form>
</body></html>"""

_SITE_ABOUT = """<!doctype html>
<html><head><title>About</title></head>
<body><a href="/site">Home</a><p>About this lab.</p></body></html>"""

_SITE_NOTES = """<!doctype html>
<html><head><title>Notes</title></head>
<body><a href="/site">Home</a></body></html>"""

# The JS references API paths and a parameterized URL — candidates only.
_APP_JS = """
const API_BASE = "/api";
async function loadNote(id) { return fetch(`/api/notes/${id}`).then(r => r.json()); }
async function search(q) { return fetch("/api/v1/users?role=admin&limit=50&sort=name"); }
const profileUrl = "/api/profile/1001";
"""


def _html(start_response, status: str, body_text: str) -> Iterable[bytes]:
    body = body_text.encode("utf-8")
    start_response(status, [("Content-Type", "text/html; charset=utf-8"),
                            ("Content-Length", str(len(body)))])
    return [body]


def _js(start_response, body_text: str) -> Iterable[bytes]:
    body = body_text.encode("utf-8")
    start_response("200 OK", [("Content-Type", "application/javascript"),
                              ("Content-Length", str(len(body)))])
    return [body]


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

        # --- Static HTML site + JS (unauthenticated, for crawl/JS discovery). ----
        if path == "/site":
            return _html(start_response, "200 OK", _SITE_INDEX)
        if path == "/site/about":
            return _html(start_response, "200 OK", _SITE_ABOUT)
        if path == "/site/notes":
            return _html(start_response, "200 OK", _SITE_NOTES)
        if path == "/static/app.js":
            return _js(start_response, _APP_JS)

        # Everything under /api requires authentication.
        identity = _authenticate(environ)
        if path.startswith("/api/"):
            if identity is None:
                return _resp(start_response, "401 Unauthorized", {"error": "unauthenticated"})

        # --- Admin discovery manifest (separate scenario). -----------------------
        if path == "/admin-scope/manifest":
            return _resp(start_response, "200 OK", _admin_manifest())

        # --- Reflected-XSS scenario (separate manifest + endpoints). -------------
        if path == "/xss-scope/manifest":
            return _resp(start_response, "200 OK", _xss_manifest())

        # VULNERABLE: reflects `q` into HTML text context WITHOUT encoding.
        if path == "/search":
            q = _query_param(environ, "q")
            page = f"<!doctype html><html><head><title>Search</title></head>" \
                   f"<body><h1>Search</h1><p>Results for: {q}</p></body></html>"
            return _html(start_response, "200 OK", page)

        # SECURE: reflects `q` but correctly HTML-encodes it (inert text).
        if path == "/search-safe":
            q = html.escape(_query_param(environ, "q"))
            page = f"<!doctype html><html><head><title>Search</title></head>" \
                   f"<body><h1>Search</h1><p>Results for: {q}</p></body></html>"
            return _html(start_response, "200 OK", page)

        # CONTROL: reflects `q` verbatim but in a NON-HTML (text/plain) context —
        # the string appears but cannot execute; must NOT be flagged.
        if path == "/echo":
            body = f"echo: {_query_param(environ, 'q')}".encode("utf-8")
            start_response("200 OK", [("Content-Type", "text/plain; charset=utf-8"),
                                      ("Content-Length", str(len(body)))])
            return [body]

        # --- Function-level authorization scenario (admin endpoints). ------------
        # VULNERABLE: /api/admin/report performs NO role check — any authenticated
        # user receives the restricted admin report (broken function-level authz).
        if path == "/api/admin/report":
            return _resp(start_response, "200 OK", data.ADMIN_REPORT)

        # SECURE: /api/admin/settings correctly requires the admin role.
        if path == "/api/admin/settings":
            if data.role_for_label(identity) != "admin":
                return _resp(start_response, "403 Forbidden", {"error": "forbidden"})
            return _resp(start_response, "200 OK", data.ADMIN_SETTINGS)

        # GENERIC: /api/admin/ping returns a non-privileged 200 to any authenticated
        # user. It has an admin-like path but exposes NO protected data — a
        # detector must NOT flag it (a matching 200 is not proof of disclosure).
        if path == "/api/admin/ping":
            return _resp(start_response, "200 OK", {"ok": True})

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
