"""Data models for the passive network-observation layer.

An :class:`ObservedExchange` is a single request/response pair that a browser
already performed. It carries only what the attack-surface graph needs plus the
minimum required to *label* which identity produced it. Authentication material
(the ``Cookie`` / ``Authorization`` / token headers) is intentionally represented
only long enough to classify the identity and is NEVER persisted by the ingestor.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

# Header names that carry authentication material. Their presence is used only to
# infer "this request was authenticated"; their values are never stored.
_AUTH_HEADER_NAMES = {
    "authorization", "cookie", "verifyauthtoken", "x-verify-auth-token",
    "x-api-key", "x-auth-token", "proxy-authorization",
}


def _content_type(headers: dict[str, str]) -> str | None:
    for k, v in headers.items():
        if k.lower() == "content-type":
            return v
    return None


@dataclass
class ObservedExchange:
    """A single request/response pair captured by the browser (already sent)."""

    method: str
    url: str
    status: int | None = None
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str | None = None
    source_page: str | None = None
    # Optional caller-supplied label for which authenticated identity this belongs
    # to (e.g. "researcher"). Mapped to an AuthIdentity by the ingestor.
    identity_label: str | None = None

    # --- derived, non-persisted helpers --------------------------------------

    @property
    def scheme(self) -> str:
        return (urlsplit(self.url).scheme or "").lower()

    @property
    def request_content_type(self) -> str | None:
        return _content_type(self.request_headers)

    @property
    def response_content_type(self) -> str | None:
        return _content_type(self.response_headers)

    def is_http(self) -> bool:
        return self.scheme in ("http", "https")

    def looks_authenticated(self) -> bool:
        """True if the request carried any auth material (value never inspected)."""
        lowered = {k.lower() for k in self.request_headers}
        return bool(lowered & _AUTH_HEADER_NAMES)


@dataclass
class IngestReport:
    """Counts from an ingestion pass. Carries no secret material."""

    program: str
    exchanges_seen: int = 0
    non_http_skipped: int = 0
    out_of_scope_dropped: int = 0
    in_scope: int = 0
    assets: int = 0
    endpoints: int = 0
    parameters: int = 0
    object_refs: int = 0
    js_assets: int = 0
    auth_observations: int = 0
    dropped_examples: list[str] = field(default_factory=list)  # host-only, for transparency

    def render(self) -> str:
        lines = [
            f"# Browser observation ingest — {self.program}",
            f"exchanges seen:        {self.exchanges_seen}",
            f"non-http skipped:      {self.non_http_skipped}",
            f"out-of-scope dropped:  {self.out_of_scope_dropped}",
            f"in-scope recorded:     {self.in_scope}",
            "",
            f"assets:                {self.assets}",
            f"endpoints:             {self.endpoints}",
            f"parameters:            {self.parameters}",
            f"object-ref candidates: {self.object_refs}",
            f"js assets:             {self.js_assets}",
            f"auth observations:     {self.auth_observations}",
        ]
        if self.dropped_examples:
            uniq = sorted(set(self.dropped_examples))
            lines += ["", "dropped out-of-scope hosts (fail-closed):"]
            lines += [f"  - {h}" for h in uniq[:20]]
        return "\n".join(lines)
