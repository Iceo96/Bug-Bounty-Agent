"""The non-secret HackerOne research header is injected into each identity's browser
context (context-level extra_http_headers), while session secrets are NEVER injected
and come only from the persistent profile. No Playwright launch, no network, no Temu.
"""

from __future__ import annotations

import inspect
import json
import logging
from pathlib import Path

import pytest

from bbagent.browser import playwright_backend as pwb
from bbagent.browser.identities import (
    ResearchHeaderUnavailable, build_identity_backends, research_headers,
)
from bbagent.config.loader import load_program
from bbagent.program.manager import ProgramManager

TEMU_YAML = str(Path(__file__).resolve().parents[1] / "programs" / "temu.yaml")
H1_VALUE = "researcher-handle-123"
SECRET_COOKIE = "sid=SECRET_COOKIE_do_not_inject"
SECRET_VAT = "SECRET_VERIFY_AUTH_TOKEN_do_not_inject"
_SECRET_HEADER_KEYS = ("Cookie", "VerifyAuthToken", "AccessToken", "Authorization",
                       "cookie", "verifyauthtoken", "authorization")


@pytest.fixture
def temu(monkeypatch, tmp_path):
    monkeypatch.setenv("BBAGENT_H1_USERNAME", H1_VALUE)
    monkeypatch.setenv("BBAGENT_TEMU_PROFILE_A", str(tmp_path / "A"))
    monkeypatch.setenv("BBAGENT_TEMU_PROFILE_B", str(tmp_path / "B"))
    # Session secrets ARE present in env — to prove they are NOT injected as headers.
    monkeypatch.setenv("BBAGENT_TEMU_COOKIE", SECRET_COOKIE)
    monkeypatch.setenv("BBAGENT_TEMU_VERIFY_AUTH_TOKEN", SECRET_VAT)
    return ProgramManager(load_program(TEMU_YAML))


def test_research_headers_is_identifier_only(temu):
    h = research_headers(temu)
    assert h == {"X-HackerOne-Research": H1_VALUE}          # expected username used
    for bad in _SECRET_HEADER_KEYS:
        assert bad not in h
    blob = json.dumps(h)
    assert SECRET_COOKIE not in blob and SECRET_VAT not in blob


def test_both_identities_receive_research_header_no_secrets(temu):
    backends = build_identity_backends(temu)
    assert set(backends) == {"researcher", "researcher_b"}
    for label, b in backends.items():
        hdrs = b._extra_http_headers
        assert hdrs.get("X-HackerOne-Research") == H1_VALUE   # A and B both get it
        for bad in _SECRET_HEADER_KEYS:
            assert bad not in hdrs
        blob = json.dumps(hdrs)
        assert SECRET_COOKIE not in blob and SECRET_VAT not in blob
    # Identity isolation preserved: distinct profiles, nothing shared.
    assert backends["researcher"].user_data_dir != backends["researcher_b"].user_data_dir


def test_missing_h1_username_fails_closed(monkeypatch, tmp_path):
    monkeypatch.delenv("BBAGENT_H1_USERNAME", raising=False)
    monkeypatch.setenv("BBAGENT_TEMU_PROFILE_A", str(tmp_path / "A"))
    monkeypatch.setenv("BBAGENT_TEMU_PROFILE_B", str(tmp_path / "B"))
    temu = ProgramManager(load_program(TEMU_YAML))
    with pytest.raises(ResearchHeaderUnavailable):
        research_headers(temu)
    with pytest.raises(ResearchHeaderUnavailable):
        build_identity_backends(temu)                         # fail closed, no backends built


def test_header_value_is_never_logged(temu, caplog):
    with caplog.at_level(logging.DEBUG):
        build_identity_backends(temu)
    assert H1_VALUE not in caplog.text


def test_injection_point_is_context_level(temu):
    # Structural: the header reaches requests via context-level extra_http_headers,
    # applied when the Playwright context is created (no Playwright launched here).
    src = inspect.getsource(pwb.PlaywrightBackend.start)
    assert "extra_http_headers=extra" in src
    assert "launch_persistent_context(" in src
    backends = build_identity_backends(temu)
    assert backends["researcher"]._extra_http_headers["X-HackerOne-Research"] == H1_VALUE


def test_secrets_are_denylisted_not_injected(temu):
    # Even though Cookie/VerifyAuthToken are configured required_header_refs with env
    # values set, research_headers skips them (session comes from the profile).
    h = research_headers(temu)
    assert "Cookie" not in h and "VerifyAuthToken" not in h
    assert list(h.keys()) == ["X-HackerOne-Research"]
