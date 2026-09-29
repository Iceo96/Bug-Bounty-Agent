"""Execution context handed to tools (never to the LLM)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from bbagent.http.client import AuthorizedHTTPClient
from bbagent.program.manager import ProgramManager


@dataclass
class ToolContext:
    """Carries the privileged resources tools may use.

    The reasoning layer (LLM) never receives this object; it only sends
    ``ToolRequest`` values and receives sanitized ``ToolResult`` values.
    """

    program: ProgramManager
    http: Optional[AuthorizedHTTPClient] = None
