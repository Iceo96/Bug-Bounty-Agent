"""Extract interaction *affordances* from an already-observed HTML page.

Pure and side-effect-free. Given a page's HTML (captured by the browser), it
reports the links, form fields, and explicitly-marked interactive controls the
page actually contains. The autonomous explorer turns these — and nothing else —
into candidate actions, so it can never invent a URL or a control the page did not
present.

Interactive controls are marked with a ``data-explore="<selector>"`` attribute:
the value is the selector the browser backend understands for a click. Form inputs
yield ``#<name>`` type-selectors. This keeps the observed action space explicit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin


@dataclass
class FormAffordance:
    action_url: str
    method: str
    field_selectors: list[str] = field(default_factory=list)


@dataclass
class Affordances:
    links: list[str] = field(default_factory=list)          # absolute hrefs
    forms: list[FormAffordance] = field(default_factory=list)
    click_selectors: list[str] = field(default_factory=list)  # from data-explore
    field_selectors: list[str] = field(default_factory=list)  # union of form fields


class _AffordanceParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self._base = base_url
        self.links: list[str] = []
        self.forms: list[FormAffordance] = []
        self.clicks: list[str] = []
        self.fields: list[str] = []
        self._form: FormAffordance | None = None

    def handle_starttag(self, tag: str, attrs):
        d = {k.lower(): (v or "") for k, v in attrs}
        if "data-explore" in d and d["data-explore"]:
            self.clicks.append(d["data-explore"])
        if tag == "a" and d.get("href"):
            self.links.append(urljoin(self._base, d["href"]))
        elif tag == "form":
            self._form = FormAffordance(
                action_url=urljoin(self._base, d.get("action", "")),
                method=(d.get("method") or "GET").upper(),
            )
        elif tag in ("input", "select", "textarea"):
            name = d.get("name")
            if name:
                sel = f"#{name}"
                self.fields.append(sel)
                if self._form is not None:
                    self._form.field_selectors.append(sel)

    def handle_endtag(self, tag: str):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def parse_affordances(base_url: str, html: str) -> Affordances:
    p = _AffordanceParser(base_url)
    try:
        p.feed(html or "")
    except Exception:  # noqa: BLE001 — malformed HTML must never crash exploration
        pass
    # stable de-dup
    def _dedup(xs: list[str]) -> list[str]:
        seen: dict[str, None] = {}
        for x in xs:
            seen.setdefault(x, None)
        return list(seen.keys())

    return Affordances(
        links=_dedup(p.links),
        forms=p.forms,
        click_selectors=_dedup(p.clicks),
        field_selectors=_dedup(p.fields),
    )
