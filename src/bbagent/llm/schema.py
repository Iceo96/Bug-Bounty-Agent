"""Strict schema for the LLM reasoner's response.

The LLM may only return a *ranking* of candidate hypothesis ids (plus optional
rationale). Any structural deviation fails validation and triggers deterministic
fallback. The optional echo fields (target/endpoint/method) exist ONLY so that a
response attempting to alter them can be detected and rejected — they are never
used to drive execution.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class RankedItem(BaseModel):
    model_config = {"extra": "forbid"}

    hypothesis_id: str = Field(min_length=1)
    rank: int = Field(ge=1)
    rationale: str = Field(default="", max_length=2000)
    # Echo-only; if present they MUST match the known candidate, else reject.
    target: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None


class ReasonerResponse(BaseModel):
    model_config = {"extra": "forbid"}

    ranking: list[RankedItem] = Field(min_length=1)
    overall_reasoning: str = Field(default="", max_length=4000)
