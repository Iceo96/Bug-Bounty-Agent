"""Unit tests for pure extraction + URL utilities (no network)."""

from __future__ import annotations

from bbagent.recon import extract
from bbagent.urlutils import endpoint_key, id_kind, looks_like_id, query_param_names, templatize_path


# --- urlutils -----------------------------------------------------------------

def test_looks_like_id_and_kind():
    assert looks_like_id("1001")
    assert looks_like_id("550e8400-e29b-41d4-a716-446655440000")
    assert looks_like_id("note-a1")
    assert not looks_like_id("v1")          # API version, not an id
    assert not looks_like_id("users")       # plain word
    assert id_kind("1001") == "numeric"
    assert id_kind("550e8400-e29b-41d4-a716-446655440000") == "uuid"
    assert id_kind("note-a1") == "path_id"
    assert id_kind("users") is None


def test_templatize_and_endpoint_key():
    assert templatize_path("/api/v1/users/1001") == "/api/v1/users/{id}"
    assert templatize_path("/api/notes/note-a1") == "/api/notes/{id}"
    k1 = endpoint_key("GET", "http://h:8000/api/notes/note-a1")
    k2 = endpoint_key("GET", "http://h:8000/api/notes/note-b1")
    assert k1 == k2  # equivalent endpoints share a key
    assert endpoint_key("POST", "http://h:8000/api/notes/1") != k1


def test_query_param_names():
    assert query_param_names("http://h/x?b=2&a=1&a=9") == ["a", "b"]


# --- HTML ---------------------------------------------------------------------

_HTML = """<html><head><title>Portal</title><script src="/static/app.js"></script></head>
<body><a href="/about">About</a><a href="mailto:x@y.z">mail</a>
<form action="/api/search" method="get"><input name="q"><input name="page"></form></body></html>"""


def test_parse_html():
    p = extract.parse_html(_HTML)
    assert p.title == "Portal"
    assert "/static/app.js" in p.scripts
    assert "/about" in p.links
    assert len(p.forms) == 1
    assert p.forms[0].action == "/api/search"
    assert p.forms[0].params == ["q", "page"]


def test_absolutize_filters_schemes():
    links = extract.absolutize("http://h/base/", ["/a", "b", "mailto:x@y.z", "#frag", "http://h/c#x"])
    assert "http://h/a" in links
    assert "http://h/base/b" in links
    assert "http://h/c" in links
    assert all("mailto" not in l for l in links)


# --- JavaScript ---------------------------------------------------------------

_JS = """
const API_BASE = "/api";
fetch(`/api/notes/note-a1`);
const u = "/api/v1/users?role=admin&limit=50&sort=name";
fetch("http://127.0.0.1:8000/api/profile/1001");
img.src = "/logo.png";
"""


def test_extract_js_urls_and_params():
    urls = extract.extract_js_urls(_JS)
    assert "/api/notes/note-a1" in urls
    assert "/api/v1/users?role=admin&limit=50&sort=name" in urls
    assert any(u.startswith("http://127.0.0.1:8000/api/profile/1001") for u in urls)
    assert "/logo.png" not in urls  # static asset filtered
    params = extract.extract_js_params(_JS)
    assert {"role", "limit", "sort"} <= set(params)


# --- object references --------------------------------------------------------

def test_object_refs_in_path():
    refs = extract.object_refs_in_path("/api/profile/1001")
    kinds = {(r.value, r.kind) for r in refs}
    assert ("1001", "numeric") in kinds


def test_object_refs_in_json():
    obj = {"note": {"id": "note-a1", "owner": "user_a", "meta": {"user_id": "1001"}}}
    refs = extract.object_refs_in_json(obj)
    values = {r.value for r in refs}
    assert "note-a1" in values
    assert "1001" in values
    assert all(r.kind == "json_id" for r in refs)
