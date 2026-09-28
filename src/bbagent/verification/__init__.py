"""Verification engine and finding deduplication."""

from bbagent.verification.engine import VerificationEngine
from bbagent.verification.dedup import compute_dedup_key, is_duplicate

__all__ = ["VerificationEngine", "compute_dedup_key", "is_duplicate"]
