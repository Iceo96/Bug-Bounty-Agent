"""Program config loading and manager tests, including the authorization gate."""

from __future__ import annotations

import pytest

from bbagent.config.loader import ProgramConfigError, load_program


def test_loads_example(tmp_path):
    # The shipped example points only at local hosts and is authorized.
    from pathlib import Path

    example = Path(__file__).resolve().parents[1] / "programs" / "example.yaml"
    pm = load_program(example)
    assert pm.name == "Local Test Lab"
    assert pm.authorized is True


def test_refuses_unauthorized(tmp_path):
    cfg = tmp_path / "bad.yaml"
    cfg.write_text(
        "name: X\nauthorized: false\nscope:\n  in_scope:\n    - {kind: domain, value: a.com}\n",
        encoding="utf-8",
    )
    with pytest.raises(ProgramConfigError):
        load_program(cfg)


def test_requires_in_scope(tmp_path):
    cfg = tmp_path / "empty.yaml"
    cfg.write_text("name: X\nauthorized: true\nscope:\n  in_scope: []\n", encoding="utf-8")
    with pytest.raises(ProgramConfigError):
        load_program(cfg)


def test_secret_resolution_from_env(program_manager, monkeypatch):
    # program_manager fixture has no accounts; add one dynamically.
    from bbagent.config.models import TestAccount

    program_manager.config.test_accounts.append(
        TestAccount(label="a", secret_env="BBAGENT_TEST_SECRET")
    )
    monkeypatch.setenv("BBAGENT_TEST_SECRET", "hunter2")
    assert program_manager.resolve_account_secret("a") == "hunter2"
    assert program_manager.resolve_account_secret("missing") is None
