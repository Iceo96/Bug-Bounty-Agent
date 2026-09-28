"""CLI integration: recon into a DB, then read it back via assets/endpoints."""

from __future__ import annotations

from pathlib import Path

import pytest

from bbagent import cli
from bbagent_lab.agent_config import ENV_TOKEN_A, ENV_TOKEN_B
from bbagent_lab.data import USERS
from bbagent_lab.server import BackgroundLab

CONFIG = str(Path(__file__).resolve().parents[1] / "programs" / "lab.yaml")
PROG = "Local Vulnerable Lab"


@pytest.fixture
def lab():
    with BackgroundLab() as server:
        yield server


def test_cli_recon_then_read(tmp_path, monkeypatch, capsys, lab):
    monkeypatch.setenv(ENV_TOKEN_A, USERS["user_a"].token)
    monkeypatch.setenv(ENV_TOKEN_B, USERS["user_b"].token)
    db = str(tmp_path / "surface.db")
    base = lab.base_url.rstrip("/")

    rc = cli.main(["--db", db, "recon", CONFIG, "--manifest", base + "/", "--crawl", base + "/site"])
    assert rc == 0
    assert Path(db).exists()

    rc = cli.main(["--db", db, "assets", PROG])
    assert rc == 0
    out = capsys.readouterr().out
    assert "/site" in out

    rc = cli.main(["--db", db, "endpoints", PROG])
    assert rc == 0
    out = capsys.readouterr().out
    assert "/api/notes/note-a1" in out
    assert "auth-observations" in out

    rc = cli.main(["--db", db, "attack-surface", PROG, "--json"])
    assert rc == 0
    out = capsys.readouterr().out
    assert '"endpoints"' in out and '"relationships"' in out


def test_cli_recon_requires_target(tmp_path, capsys):
    rc = cli.main(["--db", str(tmp_path / "x.db"), "recon", CONFIG])
    assert rc == 2
    assert "needs --manifest" in capsys.readouterr().err


def test_cli_read_without_db_errors(tmp_path, capsys):
    rc = cli.main(["--db", str(tmp_path / "missing.db"), "assets", PROG])
    assert rc == 2
    assert "no database" in capsys.readouterr().err
