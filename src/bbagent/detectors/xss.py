"""Reflected XSS detector/verifier (deterministic context analysis; no browser).

What it proves
--------------
This detector confirms that user-controlled input is reflected into an HTML
response as **live markup** (a new element or an injected attribute) rather than
inert, escaped text. That is the deterministic, browser-free criterion for
reflected XSS: the attacker's input crosses from data into HTML structure, which
is exactly what lets an attacker inject ``<script>`` or event handlers.

It does NOT claim JavaScript execution — there is no browser engine here. A
reflection that lands only inside a ``<script>`` block is reported as
INCONCLUSIVE (not VERIFIED), and encoded/plain-text reflection is DISPROVEN.

Verification is NOT based on status code, response length, or the mere presence
of the payload string. A unique, harmless payload (a custom element + attribute,
no JavaScript, no handlers, no callbacks) is injected through the existing
AuthorizedHTTPClient, and the response is parsed with html.parser to see whether
that element/attribute actually materialized.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from bbagent.detectors.base import (
    Detector,
    DetectionContext,
    VerificationContext,
    VerificationResult,
    Verifier,
    registry,
)
from bbagent.storage.models import Hypothesis
from bbagent.verification.dedup import compute_dedup_key


def _nonce(base: str, param: str) -> str:
    return hashlib.sha1(f"{base}|{param}".encode("utf-8")).hexdigest()[:8]


def _strip_query(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, "", ""))


def _first_param(url: str) -> str | None:
    params = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    return params[0][0] if params else None


class _MarkerParser(HTMLParser):
    """Detects whether an injected marker became live markup."""

    def __init__(self, marker_tag: str, marker_attr: str):
        super().__init__(convert_charrefs=True)
        self._tag = marker_tag
        self._attr = marker_attr
        self.tag_created = False
        self.attr_injected = False
        self._script_depth = 0
        self._script_text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == self._tag:
            self.tag_created = True
        for k, _v in attrs:
            if k == self._attr:
                self.attr_injected = True
        if tag == "script":
            self._script_depth += 1

    def handle_endtag(self, tag):
        if tag == "script" and self._script_depth > 0:
            self._script_depth -= 1

    def handle_data(self, data):
        if self._script_depth > 0:
            self._script_text.append(data)

    @property
    def script_text(self) -> str:
        return "".join(self._script_text)


@dataclass
class ReflectionAnalysis:
    verdict: str      # "executable" | "encoded" | "not_reflected" | "script_inconclusive" | "non_html"
    context: str
    detail: str


def analyze_reflection(body: str, content_type: str, tag: str, attr: str, nonce: str,
                       payload: str) -> ReflectionAnalysis:
    """Deterministically classify how the payload was reflected."""
    if "html" not in (content_type or "").lower():
        reflected = nonce in body
        return ReflectionAnalysis(
            "non_html", "non_html",
            f"response is not HTML (content-type={content_type!r}); "
            f"payload {'present as inert text' if reflected else 'absent'}",
        )

    parser = _MarkerParser(tag, attr)
    try:
        parser.feed(body)
    except Exception:  # noqa: BLE001 — malformed HTML must not crash analysis
        pass

    if parser.tag_created or parser.attr_injected:
        ctx = "html_element" if parser.tag_created else "html_attribute"
        return ReflectionAnalysis(
            "executable", ctx,
            f"injected input created live HTML ({ctx}); marker "
            f"<{tag}>/@{attr} present in the parsed response",
        )

    # Reflected inside a <script> block with raw special chars => can't prove
    # execution without a JS engine -> inconclusive, never VERIFIED.
    if nonce in parser.script_text and ('"' in payload and '"' in parser.script_text):
        return ReflectionAnalysis(
            "script_inconclusive", "script",
            "payload reflected inside a <script> block; executability cannot be "
            "confirmed without a browser engine",
        )

    if nonce in body:
        return ReflectionAnalysis(
            "encoded", "encoded_text",
            "payload reflected only as escaped/inert text (no markup created)",
        )
    return ReflectionAnalysis("not_reflected", "none", "payload not reflected in the response")


@registry.register_detector
class ReflectedXSSDetector(Detector):
    vuln_type = "reflected_xss"
    name = "reflected-xss-detector"

    async def detect(self, ctx: DetectionContext) -> list[Hypothesis]:
        hyps: list[Hypothesis] = []
        for obs in ctx.observations:
            if obs.kind != "endpoint":
                continue
            url = obs.data.get("url", "")
            if not _first_param(url):
                continue
            hyps.append(Hypothesis(
                program=ctx.program.name,
                vuln_type=self.vuln_type,
                title=f"Possible reflected XSS at {url}",
                rationale="Endpoint has a user-controlled input parameter reflected into a response.",
                target_url=url,
                detector=self.name,
                observation_ids=[obs.id],
            ))
        return hyps


@registry.register_verifier
class ReflectedXSSVerifier(Verifier):
    vuln_type = "reflected_xss"

    async def verify(self, ctx: VerificationContext) -> VerificationResult:
        url = ctx.hypothesis.target_url
        param = _first_param(url)
        if not param:
            return VerificationResult(
                verified=False,
                reason="malformed hypothesis: no input parameter present in target URL",
            )
        base = _strip_query(url)
        nonce = _nonce(base, param)
        tag = f"bbx{nonce}"
        attr = f"bbxa{nonce}"
        benign = f"canary{nonce}"
        payload = f'{nonce}"><{tag} {attr}=x>'

        # 1) Benign reflection probe (establishes the sink; harmless value).
        baseline = await ctx.http.get(base, params={param: benign})
        if benign not in baseline.response_body:
            return VerificationResult(
                verified=False,
                reason="input parameter is not reflected in the response",
                exchanges=[baseline],
            )

        # 2) Marker payload probe (harmless custom element+attribute; no JS).
        probe = await ctx.http.get(base, params={param: payload})
        content_type = probe.response_headers.get("content-type", "")
        analysis = analyze_reflection(
            probe.response_body, content_type, tag, attr, nonce, payload
        )
        exchanges = [baseline, probe]

        if analysis.verdict != "executable":
            return VerificationResult(
                verified=False,
                reason=f"not reflected XSS ({analysis.verdict}): {analysis.detail}",
                exchanges=exchanges,
            )

        return VerificationResult(
            verified=True,
            reason="user input is reflected as live HTML markup (executable context)",
            exchanges=exchanges,
            expected_behavior=(
                f"the value of '{param}' must be HTML-encoded and appear as inert text "
                f"(e.g. &lt;{tag}&gt;), never as markup."
            ),
            actual_behavior=(
                f"the injected payload created live HTML in {analysis.context}: {analysis.detail}."
            ),
            impact=(
                "Reflected XSS: attacker-controlled input crosses from data into HTML "
                "structure, allowing injection of scripts/event handlers in a victim's browser."
            ),
            test_identity="unauthenticated",
            reproduction=(
                f"1. GET {base}?{param}={benign} — confirm the value is reflected.\n"
                f"2. GET {base}?{param}=<the marker payload> (a harmless <{tag}> element).\n"
                f"3. Observe that <{tag}> appears as a real element in the HTML response "
                f"(context: {analysis.context}), i.e. the input was not encoded."
            ),
            dedup_key=compute_dedup_key("reflected_xss", base, "GET"),
        )
