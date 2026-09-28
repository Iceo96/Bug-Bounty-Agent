"""Scope engine: the single gate every outbound request must pass.

Design principles (fail-closed):

* Exclusions always win over inclusions.
* If scope cannot be positively determined, the request is DENIED.
* URL parsing is strict; malformed or schemeless targets are DENIED.
* The engine is pure and side-effect free so it can be tested exhaustively.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

from bbagent.config.models import ScopeConfig, ScopeKind, ScopeRule
from bbagent.logging_config import get_logger

log = get_logger(__name__)

_ALLOWED_SCHEMES = {"http", "https"}


class ScopeError(Exception):
    """Raised when a request is not permitted by scope."""


@dataclass(frozen=True)
class ScopeDecision:
    """Result of a scope check."""

    allowed: bool
    reason: str
    matched_rule: ScopeRule | None = None

    def raise_if_denied(self, url: str) -> None:
        if not self.allowed:
            raise ScopeError(f"out of scope: {url} — {self.reason}")


def _host_of(url: str) -> tuple[str, str]:
    """Return ``(scheme, host)`` lowercased, or raise ValueError if unparseable."""
    parts = urlsplit(url)
    if parts.scheme.lower() not in _ALLOWED_SCHEMES:
        raise ValueError(f"unsupported or missing scheme in URL: {url!r}")
    host = parts.hostname
    if not host:
        raise ValueError(f"could not determine host from URL: {url!r}")
    return parts.scheme.lower(), host.lower()


def _as_ip(host: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


class ScopeEngine:
    """Validates URLs against a program's :class:`ScopeConfig`."""

    def __init__(self, scope: ScopeConfig):
        self._scope = scope

    # --- rule matching ---------------------------------------------------------

    @staticmethod
    def _matches(rule: ScopeRule, url: str, scheme: str, host: str) -> bool:
        val = rule.value
        if rule.kind is ScopeKind.DOMAIN:
            return host == val
        if rule.kind is ScopeKind.WILDCARD:
            # "*.example.com" matches any subdomain but NOT the apex "example.com".
            suffix = val[1:]  # ".example.com"
            return host.endswith(suffix) and host != suffix[1:]
        if rule.kind is ScopeKind.URL_PREFIX:
            # Compare on a normalized full URL prefix.
            return _normalize(url).startswith(_normalize(val))
        if rule.kind is ScopeKind.CIDR:
            ip = _as_ip(host)
            if ip is None:
                return False
            try:
                return ip in ipaddress.ip_network(val, strict=False)
            except ValueError:
                return False
        return False

    def _first_match(self, rules: list[ScopeRule], url: str, scheme: str, host: str) -> ScopeRule | None:
        for rule in rules:
            if self._matches(rule, url, scheme, host):
                return rule
        return None

    # --- public API ------------------------------------------------------------

    def check(self, url: str) -> ScopeDecision:
        """Return a :class:`ScopeDecision` for ``url``. Never raises for bad input."""
        try:
            scheme, host = _host_of(url)
        except ValueError as exc:
            return ScopeDecision(False, f"unparseable target ({exc})")

        # 1) Exclusions always win.
        excluded = self._first_match(self._scope.excluded, url, scheme, host)
        if excluded is not None:
            return ScopeDecision(False, f"matched exclusion rule {excluded.kind.value}:{excluded.value}", excluded)

        # 2) Must positively match an in-scope rule.
        included = self._first_match(self._scope.in_scope, url, scheme, host)
        if included is not None:
            return ScopeDecision(True, f"matched in-scope rule {included.kind.value}:{included.value}", included)

        # 3) Otherwise deny (fail-closed).
        return ScopeDecision(False, "no in-scope rule matched (fail-closed)")

    def is_allowed(self, url: str) -> bool:
        return self.check(url).allowed

    def enforce(self, url: str) -> ScopeDecision:
        """Return the decision, raising :class:`ScopeError` if denied."""
        decision = self.check(url)
        if not decision.allowed:
            log.warning("scope.denied", url=url, reason=decision.reason)
        decision.raise_if_denied(url)
        return decision


def _normalize(url: str) -> str:
    """Normalize a URL/prefix for prefix comparison (lowercase scheme+host, keep path)."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = f":{parts.port}" if parts.port else ""
    return f"{scheme}://{host}{port}{parts.path}"
