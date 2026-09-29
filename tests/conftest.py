"""Shared pytest fixtures."""

from __future__ import annotations

import httpx
import pytest

from bbagent.config.models import (
    PolicyBudget,
    ProgramConfig,
    RateLimit,
    ScopeConfig,
    ScopeKind,
    ScopeRule,
    TestAccount,
    TestingRestrictions,
)
from bbagent.program.manager import ProgramManager
from bbagent.storage.db import Database
from bbagent.storage.evidence import EvidenceStore


@pytest.fixture
def program_config() -> ProgramConfig:
    return ProgramConfig(
        name="Test Program",
        authorized=True,
        scope=ScopeConfig(
            in_scope=[
                ScopeRule(kind=ScopeKind.DOMAIN, value="example.com"),
                ScopeRule(kind=ScopeKind.WILDCARD, value="*.example.com"),
                ScopeRule(kind=ScopeKind.URL_PREFIX, value="https://api.example.com/v1/"),
                ScopeRule(kind=ScopeKind.CIDR, value="10.0.0.0/24"),
            ],
            excluded=[
                ScopeRule(kind=ScopeKind.DOMAIN, value="secret.example.com"),
            ],
        ),
        restrictions=TestingRestrictions(
            allowed_methods=["GET", "HEAD", "POST"],
            forbidden_paths=["/danger"],
        ),
        required_headers={"X-Bug-Bounty": "researcher"},
        rate_limit=RateLimit(requests_per_second=50, max_concurrent=4),
        # Policy-complete so the policy-gated verification path is permitted.
        test_accounts=[TestAccount(label="user_a"), TestAccount(label="user_b")],
        allowed_tools=["http", "recon"],
        allowed_vulnerability_classes=["idor", "privilege_escalation", "reflected_xss", "sql_injection"],
        allow_unauthenticated=True,
        request_budget=PolicyBudget(total=1000, per_target=1000, per_tool=1000),
    )


@pytest.fixture
def program_manager(program_config) -> ProgramManager:
    return ProgramManager(program_config)


@pytest.fixture
def db() -> Database:
    d = Database(":memory:")
    yield d
    d.close()


@pytest.fixture
def evidence_store(db, tmp_path) -> EvidenceStore:
    return EvidenceStore(db, tmp_path / "evidence")


def make_transport(handler) -> httpx.MockTransport:
    """Wrap a request handler in an httpx MockTransport."""
    return httpx.MockTransport(handler)
