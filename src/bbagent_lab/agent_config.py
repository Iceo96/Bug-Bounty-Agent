"""Build the agent's program configuration for the local lab.

Scope is restricted to loopback hosts. Test-account secrets (the synthetic
bearer tokens) are supplied via environment variables, exactly as a real
engagement would resolve them — never hard-coded into a committed program file.
"""

from __future__ import annotations

import os

from bbagent.config.models import (
    ProgramConfig,
    RateLimit,
    ScopeConfig,
    ScopeKind,
    ScopeRule,
    TestAccount,
    TestingRestrictions,
)
from bbagent_lab import data

ENV_TOKEN_A = "BBAGENT_LAB_TOKEN_A"
ENV_TOKEN_B = "BBAGENT_LAB_TOKEN_B"


def export_lab_tokens() -> None:
    """Populate the token env vars from the synthetic lab fixtures.

    Convenience for the demo/integration flow only. The tokens are non-secret
    fixtures for a throwaway localhost app.
    """
    os.environ.setdefault(ENV_TOKEN_A, data.USERS["user_a"].token)
    os.environ.setdefault(ENV_TOKEN_B, data.USERS["user_b"].token)


def build_lab_program() -> ProgramConfig:
    return ProgramConfig(
        name="Local Vulnerable Lab",
        platform="local",
        authorized=True,
        scope=ScopeConfig(
            in_scope=[
                ScopeRule(kind=ScopeKind.DOMAIN, value="127.0.0.1"),
                ScopeRule(kind=ScopeKind.DOMAIN, value="localhost"),
            ],
            excluded=[],
        ),
        restrictions=TestingRestrictions(
            allow_active_testing=False,        # read-only is enough to prove IDOR
            allowed_methods=["GET", "HEAD", "OPTIONS"],
            no_dos=True,
        ),
        required_headers={"X-Bug-Bounty": "local-lab"},
        rate_limit=RateLimit(requests_per_second=50, max_concurrent=8),
        test_accounts=[
            # user_a is an admin identity; user_b is a regular user. Roles drive the
            # function-level (privilege-escalation) capability.
            TestAccount(label="user_a", role="admin", username="alice", secret_env=ENV_TOKEN_A),
            TestAccount(label="user_b", role="user", username="bob", secret_env=ENV_TOKEN_B),
        ],
        notes=["Local lab — loopback only. Synthetic data."],
    )
