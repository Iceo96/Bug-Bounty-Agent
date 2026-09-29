"""Generic tool abstraction.

The agent/LLM never executes anything directly. It emits a structured
``ToolRequest``; the Tool Router validates the tool exists, validates arguments
against the tool's schema, runs the request through the Program Policy Engine,
and only then executes. Tools return a sanitized ``ToolResult``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from pydantic import BaseModel, Field


class ToolRequest(BaseModel):
    """A structured request to run a tool. The only way the agent acts."""

    model_config = {"extra": "forbid"}

    tool: str = Field(min_length=1)
    arguments: dict = Field(default_factory=dict)
    reason: str = ""
    target: Optional[str] = None
    requested_action: str = ""
    identity: Optional[str] = None      # a test-account *handle*, never a secret
    vuln_class: Optional[str] = None


class ToolResult(BaseModel):
    """The sanitized outcome of a tool request (safe for the reasoning layer)."""

    model_config = {"extra": "forbid"}

    tool: str
    success: bool
    action: str = ""
    target: Optional[str] = None
    sanitized: dict = Field(default_factory=dict)
    metadata: dict = Field(default_factory=dict)
    denied_reason: Optional[str] = None
    error: Optional[str] = None

    @classmethod
    def denied(cls, tool: str, reason: str, *, action: str = "", target: str | None = None) -> "ToolResult":
        return cls(tool=tool, success=False, action=action, target=target, denied_reason=reason)


class ToolError(Exception):
    """Raised by a tool when execution fails (never a policy denial)."""


class Tool(ABC):
    """Base class for controlled tools."""

    name: str = "tool"
    description: str = ""
    version: str = "0.1.0"
    #: capability tags the tool needs (informational; policy governs allow/deny).
    permissions: list[str] = []
    #: pydantic model describing the argument schema.
    args_model: type[BaseModel] = BaseModel
    #: human/LLM-readable description of the output shape.
    output_schema: dict = {}

    def validate_arguments(self, arguments: dict) -> BaseModel:
        """Validate raw arguments against the tool's schema. Raises on mismatch."""
        return self.args_model.model_validate(arguments)

    def describe(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "permissions": list(self.permissions),
            "input_schema": self.args_model.model_json_schema(),
            "output_schema": self.output_schema,
        }

    @abstractmethod
    async def execute(self, args: BaseModel, ctx) -> dict:
        """Run the tool and return a **sanitized** result dict. ``ctx`` is a ToolContext."""
        raise NotImplementedError
