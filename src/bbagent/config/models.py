"""Pydantic models describing an authorized bug bounty program.

These models are the single source of truth for what the agent is allowed to
touch. The scope engine consumes them; nothing else may widen scope.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class ScopeKind(str, Enum):
    """The kind of pattern a scope rule expresses."""

    DOMAIN = "domain"          # exact host, e.g. "api.example.com"
    WILDCARD = "wildcard"      # "*.example.com" (subdomains, not the apex)
    URL_PREFIX = "url_prefix"  # "https://example.com/app/" prefix match
    CIDR = "cidr"              # IPv4/IPv6 network, e.g. "10.0.0.0/24"


class ScopeRule(BaseModel):
    """A single in-scope or excluded target pattern."""

    model_config = {"extra": "forbid"}

    kind: ScopeKind
    value: str = Field(min_length=1)
    note: Optional[str] = None

    @field_validator("value")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip().lower()

    @model_validator(mode="after")
    def _check_shape(self) -> "ScopeRule":
        if self.kind is ScopeKind.WILDCARD and not self.value.startswith("*."):
            raise ValueError("wildcard rules must start with '*.' (e.g. '*.example.com')")
        if self.kind is ScopeKind.URL_PREFIX and "://" not in self.value:
            raise ValueError("url_prefix rules must include a scheme (e.g. 'https://...')")
        return self


class RateLimit(BaseModel):
    """Outbound request throttling. Enforced by the HTTP client, not optional."""

    model_config = {"extra": "forbid"}

    requests_per_second: float = Field(default=2.0, gt=0, le=100)
    max_concurrent: int = Field(default=4, ge=1, le=64)
    per_host: bool = Field(
        default=True,
        description="Apply the rate limit independently per target host.",
    )


class TestingRestrictions(BaseModel):
    """Program rules constraining how testing may be performed."""

    model_config = {"extra": "forbid"}

    allow_active_testing: bool = Field(
        default=True,
        description="If false, only passive observation is permitted.",
    )
    allowed_methods: list[str] = Field(
        default_factory=lambda: ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
    )
    forbidden_paths: list[str] = Field(
        default_factory=list,
        description="URL path substrings that must never be requested.",
    )
    no_automated_scanning: bool = False
    no_dos: bool = Field(default=True, description="Denial-of-service testing is always forbidden.")
    notes: list[str] = Field(default_factory=list)

    @field_validator("allowed_methods")
    @classmethod
    def _upper(cls, v: list[str]) -> list[str]:
        return [m.strip().upper() for m in v]


class TestAccount(BaseModel):
    """A test identity provided by the program. Secrets come from env, not YAML."""

    model_config = {"extra": "forbid"}

    label: str
    role: str = "user"
    username: Optional[str] = None
    # Reference to an environment variable holding the secret, e.g. "BBAGENT_ACCT_A_PASS".
    # We never store raw credentials in the config file.
    secret_env: Optional[str] = None
    notes: Optional[str] = None


class LLMConfig(BaseModel):
    """Optional LLM reasoning layer. Prioritization only — never execution.

    Disabled by default. The LLM receives only sanitized, already-scope-checked
    candidate data and may only reorder/explain; it has no access to HTTP, shell,
    the filesystem, SQLite, credentials, or the HTTP client.
    """

    model_config = {"extra": "forbid"}

    enabled: bool = False
    provider: str = "anthropic"
    model: str = "claude-sonnet-5-5"
    max_candidates: int = Field(default=20, ge=1, le=200)
    timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    fallback_to_deterministic: bool = True


class ScopeConfig(BaseModel):
    """In-scope and excluded assets. Exclusions always win."""

    model_config = {"extra": "forbid"}

    in_scope: list[ScopeRule] = Field(default_factory=list)
    excluded: list[ScopeRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _non_empty(self) -> "ScopeConfig":
        if not self.in_scope:
            raise ValueError("a program must define at least one in-scope rule")
        return self


class ProgramConfig(BaseModel):
    """Top-level authorized-program configuration."""

    model_config = {"extra": "forbid"}

    name: str = Field(min_length=1)
    platform: Optional[str] = None
    authorized: bool = Field(
        default=False,
        description="Must be explicitly true to confirm the engagement is authorized.",
    )
    scope: ScopeConfig
    restrictions: TestingRestrictions = Field(default_factory=TestingRestrictions)
    required_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Headers the program requires on every request (e.g. an identifying header).",
    )
    rate_limit: RateLimit = Field(default_factory=RateLimit)
    test_accounts: list[TestAccount] = Field(default_factory=list)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    notes: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _must_be_authorized(self) -> "ProgramConfig":
        if not self.authorized:
            raise ValueError(
                "refusing to load a program with 'authorized: false'. "
                "Only load configurations for programs you are explicitly authorized to test."
            )
        return self
