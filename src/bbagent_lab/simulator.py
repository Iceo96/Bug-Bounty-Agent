"""A fully local, synthetic Bug Bounty *program simulator*.

Loopback-only scope, an exclusion, a single allowed method, a required research
header, synthetic test identities, request budgets, allowed tools, and allowed
vulnerability classes. Used to exercise the Program Policy Engine and the tool
layer end to end without any real target.
"""

from __future__ import annotations

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
from bbagent_lab.agent_config import ENV_TOKEN_A, ENV_TOKEN_B

SIM_NAME = "local-security-program"
RESEARCH_HEADER = "X-Research-ID"
RESEARCH_VALUE = "local-agent"


def build_simulator_program() -> ProgramConfig:
    return ProgramConfig(
        name=SIM_NAME,
        platform="local-simulator",
        authorized=True,
        scope=ScopeConfig(
            in_scope=[
                ScopeRule(kind=ScopeKind.DOMAIN, value="127.0.0.1"),
                ScopeRule(kind=ScopeKind.DOMAIN, value="localhost"),
            ],
            excluded=[],
        ),
        restrictions=TestingRestrictions(
            allow_active_testing=False,
            allowed_methods=["GET", "HEAD", "OPTIONS"],
            forbidden_paths=["/excluded/"],   # program "exclusions"
        ),
        required_headers={RESEARCH_HEADER: RESEARCH_VALUE},
        rate_limit=RateLimit(requests_per_second=50, max_concurrent=8),
        test_accounts=[
            TestAccount(label="user_a", role="admin", username="alice", secret_env=ENV_TOKEN_A),
            TestAccount(label="user_b", role="user", username="bob", secret_env=ENV_TOKEN_B),
        ],
        allowed_tools=["http", "recon"],
        allowed_vulnerability_classes=[
            "idor", "privilege_escalation", "reflected_xss", "sql_injection",
        ],
        forbidden_actions=[],
        allow_unauthenticated=True,   # XSS/SQLi probes are unauthenticated
        request_budget=PolicyBudget(total=200, per_target=100, per_tool=200),
        notes=["Local simulator — loopback only, synthetic data."],
    )


def build_simulator_manager() -> ProgramManager:
    return ProgramManager(build_simulator_program())
