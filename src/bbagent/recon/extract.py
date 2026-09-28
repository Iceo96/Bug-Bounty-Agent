"""Pure, side-effect-free extraction helpers for the attack-surface mapper.

Everything here operates on already-fetched content (fetched via the authorized
client elsewhere) and returns *candidates*. Nothing here confirms an endpoint or
a vulnerability — confirmation happens only through verified requests.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit

from bbagent.urlutils import id_kind, query_param_names

# --- HTML ---------------------------------------------------------------------


@dataclass
class FormCandidate:
    action: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)


@dataclass
class HtmlParse:
    title: str | None = None
    links: list[str] = field(default_factory=list)      # <a href>, <link href>
    scripts: list[str] = field(default_factory=list)    # <script src>
    forms: list[FormCandidate] = field(default_factory=list)


class _HTMLCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title: str | None = None
        self._in_title = False
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[FormCandidate] = []
        self._form: FormCandidate | None = None

    def handle_starttag(self, tag: str, attrs):
        d = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "a" and d.get("href"):
            self.links.append(d["href"])
        elif tag == "link" and d.get("href"):
            self.links.append(d["href"])
        elif tag == "script" and d.get("src"):
            self.scripts.append(d["src"])
        elif tag == "form":
            self._form = FormCandidate(action=d.get("action", ""), method=(d.get("method") or "GET").upper())
        elif tag in ("input", "select", "textarea") and self._form is not None:
            name = d.get("name")
            if name:
                self._form.params.append(name)

    def handle_endtag(self, tag: str):
        if tag == "title":
            self._in_title = False
        elif tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def handle_data(self, data: str):
        if self._in_title and data.strip():
            self.title = (self.title or "") + data.strip()


def parse_html(html: str) -> HtmlParse:
    p = _HTMLCollector()
    try:
        p.feed(html)
    except Exception:  # noqa: BLE001 — malformed HTML must never crash the mapper
        pass
    return HtmlParse(title=p.title, links=p.links, scripts=p.scripts, forms=p.forms)


def absolutize(base_url: str, hrefs: list[str]) -> list[str]:
    """Resolve relative hrefs against base_url; drop unusable schemes/anchors."""
    out: list[str] = []
    for href in hrefs:
        h = href.strip()
        if not h or h.startswith(("#", "mailto:", "javascript:", "tel:", "data:")):
            continue
        resolved = urljoin(base_url, h)
        if urlsplit(resolved).scheme in ("http", "https"):
            out.append(resolved.split("#", 1)[0])
    # stable de-dup
    seen: dict[str, None] = {}
    for u in out:
        seen.setdefault(u, None)
    return list(seen.keys())


def is_probably_html(content_type: str) -> bool:
    return "html" in (content_type or "").lower()


def is_probably_js(url: str, content_type: str) -> bool:
    ct = (content_type or "").lower()
    if "javascript" in ct or "ecmascript" in ct:
        return True
    return urlsplit(url).path.lower().endswith((".js", ".mjs"))


# --- JavaScript ---------------------------------------------------------------

_ABS_URL = re.compile(r"""https?://[^\s"'`<>()]+""")
# Quoted path-like strings, incl. query strings: "/api/x?y=1", '/v1/users', `/p/{id}`
_PATH_STR = re.compile(r"""["'`](/[A-Za-z0-9_\-/.{}~%?&=:,]+)["'`]""")
# key=value pairs inside query strings anywhere in the text
_QS_PARAM = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_]*)=")


def extract_js_urls(js_text: str) -> list[str]:
    """Candidate absolute URLs and root-relative paths referenced in JS."""
    found: dict[str, None] = {}
    for m in _ABS_URL.finditer(js_text):
        found.setdefault(m.group(0).rstrip(".,);"), None)
    for m in _PATH_STR.finditer(js_text):
        path = m.group(1)
        # Ignore obvious static asset paths and bare "/".
        if path == "/" or path.lower().endswith((".css", ".png", ".jpg", ".svg", ".gif", ".woff", ".ico")):
            continue
        found.setdefault(path, None)
    return list(found.keys())


def extract_js_params(js_text: str) -> list[str]:
    """Candidate parameter names from query strings embedded in JS."""
    names: dict[str, None] = {}
    for m in _QS_PARAM.finditer(js_text):
        names.setdefault(m.group(1), None)
    # Also pull query names from any full URLs/paths present.
    for url in extract_js_urls(js_text):
        for name in query_param_names(url):
            names.setdefault(name, None)
    return sorted(names.keys())


# --- object references --------------------------------------------------------


@dataclass
class ObjectRefCandidate:
    value: str
    kind: str        # numeric | uuid | hexid | path_id | json_id
    location: str    # "path" | "json:<key>"


def object_refs_in_path(path: str) -> list[ObjectRefCandidate]:
    refs: list[ObjectRefCandidate] = []
    for seg in path.split("/"):
        kind = id_kind(seg) if seg else None
        if kind:
            refs.append(ObjectRefCandidate(value=seg, kind=kind, location="path"))
    return refs


_ID_KEY = re.compile(r"(^id$|_id$|Id$)")


def object_refs_in_json(obj, _prefix: str = "") -> list[ObjectRefCandidate]:
    """Walk a parsed JSON structure for id-like keys/values (candidates only)."""
    refs: list[ObjectRefCandidate] = []

    def walk(node, key_ctx: str | None):
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, (dict, list)):
                    walk(v, k)
                elif _ID_KEY.search(k) and v not in (None, "", True, False):
                    refs.append(ObjectRefCandidate(value=str(v), kind="json_id", location=f"json:{k}"))
                elif isinstance(v, str) and id_kind(v) in ("uuid", "hexid"):
                    refs.append(ObjectRefCandidate(value=v, kind="json_id", location=f"json:{k}"))
        elif isinstance(node, list):
            for item in node:
                walk(item, key_ctx)

    walk(obj, None)
    # de-dup by (value, location)
    seen: dict[tuple, ObjectRefCandidate] = {}
    for r in refs:
        seen.setdefault((r.value, r.location), r)
    return list(seen.values())


def html_title(html: str) -> str | None:
    return parse_html(html).title
