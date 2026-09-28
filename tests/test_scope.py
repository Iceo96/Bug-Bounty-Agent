"""Scope engine tests: inclusions, wildcards, prefixes, CIDR, exclusions, fail-closed."""

from __future__ import annotations

import pytest

from bbagent.scope.engine import ScopeEngine, ScopeError


@pytest.fixture
def engine(program_config):
    return ScopeEngine(program_config.scope)


@pytest.mark.parametrize(
    "url,allowed",
    [
        ("https://example.com/", True),                     # exact domain
        ("https://www.example.com/", True),                 # wildcard subdomain
        ("https://deep.sub.example.com/x", True),           # nested subdomain
        ("https://api.example.com/v1/users", True),         # url prefix
        ("https://api.example.com/v2/users", True),         # still matches *.example.com
        ("http://10.0.0.5/status", True),                   # CIDR
        ("https://evil.com/", False),                       # unrelated domain
        ("http://10.0.1.5/", False),                        # outside CIDR
        ("https://example.com.evil.com/", False),           # suffix trick
        ("ftp://example.com/", False),                      # bad scheme
        ("not a url", False),                               # unparseable
        ("https://example.com", True),                      # no path
    ],
)
def test_scope_decisions(engine, url, allowed):
    assert engine.is_allowed(url) is allowed


def test_exclusion_beats_inclusion(engine):
    # secret.example.com matches *.example.com but is explicitly excluded.
    assert engine.is_allowed("https://secret.example.com/") is False
    decision = engine.check("https://secret.example.com/")
    assert "exclusion" in decision.reason


def test_url_prefix_does_not_over_match(engine):
    # /v1/ prefix must not match a different path on a host that ISN'T otherwise in scope.
    # api.example.com is in scope via wildcard anyway, so test a prefix-only style host:
    from bbagent.config.models import ScopeConfig, ScopeRule, ScopeKind

    eng = ScopeEngine(
        ScopeConfig(in_scope=[ScopeRule(kind=ScopeKind.URL_PREFIX, value="https://only.test/app/")])
    )
    assert eng.is_allowed("https://only.test/app/x") is True
    assert eng.is_allowed("https://only.test/other") is False
    assert eng.is_allowed("https://only.test/") is False


def test_enforce_raises(engine):
    with pytest.raises(ScopeError):
        engine.enforce("https://evil.com/")


def test_fail_closed_on_empty_host(engine):
    assert engine.is_allowed("https:///path") is False
