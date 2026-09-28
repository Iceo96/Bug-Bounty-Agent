"""Structured logging setup using structlog."""

from __future__ import annotations

import logging
import os

import structlog


def configure_logging(level: str | None = None) -> None:
    """Configure process-wide structured logging.

    Idempotent: safe to call more than once.
    """
    lvl = (level or os.getenv("BBAGENT_LOG_LEVEL", "INFO")).upper()
    logging.basicConfig(format="%(message)s", level=getattr(logging, lvl, logging.INFO))
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, lvl, logging.INFO)),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a bound structlog logger."""
    return structlog.get_logger(name)
