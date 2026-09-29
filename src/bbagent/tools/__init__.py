"""Secure tool abstraction layer."""

from bbagent.tools.base import Tool, ToolError, ToolRequest, ToolResult
from bbagent.tools.context import ToolContext
from bbagent.tools.http_tool import HttpTool
from bbagent.tools.recon_tool import ReconTool
from bbagent.tools.registry import ToolRegistry
from bbagent.tools.router import ToolRouter


def default_tools() -> ToolRegistry:
    """A registry with the built-in controlled tools (http + local recon)."""
    reg = ToolRegistry()
    reg.register(HttpTool())
    reg.register(ReconTool())
    return reg


__all__ = [
    "Tool",
    "ToolError",
    "ToolRequest",
    "ToolResult",
    "ToolContext",
    "ToolRegistry",
    "ToolRouter",
    "HttpTool",
    "ReconTool",
    "default_tools",
]
