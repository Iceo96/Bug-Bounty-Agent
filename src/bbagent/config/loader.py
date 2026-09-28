"""Load and validate program configuration from YAML or JSON."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from pydantic import ValidationError

from bbagent.config.models import ProgramConfig


class ProgramConfigError(Exception):
    """Raised when a program configuration cannot be loaded or is invalid."""


def load_program(path: str | Path) -> ProgramConfig:
    """Load a :class:`ProgramConfig` from a ``.yaml``/``.yml``/``.json`` file.

    Raises :class:`ProgramConfigError` on any problem, including the refusal to
    load a configuration whose ``authorized`` flag is not explicitly ``true``.
    """
    p = Path(path)
    if not p.is_file():
        raise ProgramConfigError(f"program config not found: {p}")

    raw = p.read_text(encoding="utf-8")
    try:
        if p.suffix.lower() in {".yaml", ".yml"}:
            data = yaml.safe_load(raw)
        elif p.suffix.lower() == ".json":
            data = json.loads(raw)
        else:
            raise ProgramConfigError(f"unsupported config extension: {p.suffix}")
    except (yaml.YAMLError, json.JSONDecodeError) as exc:
        raise ProgramConfigError(f"could not parse {p}: {exc}") from exc

    if not isinstance(data, dict):
        raise ProgramConfigError(f"{p} must contain a mapping at the top level")

    try:
        return ProgramConfig.model_validate(data)
    except ValidationError as exc:
        raise ProgramConfigError(f"invalid program config in {p}:\n{exc}") from exc
