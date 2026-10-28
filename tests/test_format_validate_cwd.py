"""Tests that format --validate runs make from the Makefile's directory."""

import os
import shutil
import subprocess
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from mbake.cli import app


def _gnu_make_available() -> bool:
    if os.name == "nt" or shutil.which("make") is None:
        return False
    try:
        version = subprocess.run(
            ["make", "--version"], capture_output=True, text=True, timeout=10
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return "GNU Make" in version


def test_format_validate_runs_make_in_makefile_directory(tmp_path):
    subdir = tmp_path / "sub"
    subdir.mkdir()
    makefile = subdir / "Makefile"
    makefile.write_text("CC=gcc\nall:\n\t@echo hi\n")
    config_path = tmp_path / "bake.toml"
    config_path.write_text("")

    with patch("subprocess.run") as run:
        run.return_value.returncode = 0
        result = CliRunner().invoke(
            app, ["format", "--validate", "--config", str(config_path), str(makefile)]
        )

    assert result.exit_code == 0
    assert run.call_args.args[0] == ["make", "-f", "Makefile", "--dry-run"]
    assert run.call_args.kwargs["cwd"] == subdir


@pytest.mark.skipif(not _gnu_make_available(), reason="GNU make is not available")
def test_format_validate_resolves_relative_include(tmp_path):
    subdir = tmp_path / "sub"
    subdir.mkdir()
    (subdir / "common.mk").write_text("X = 1\n")
    makefile = subdir / "Makefile"
    makefile.write_text("CC=gcc\ninclude common.mk\nall:\n\t@echo $(X)\n")
    config_path = tmp_path / "bake.toml"
    config_path.write_text("")

    result = CliRunner().invoke(
        app, ["format", "--validate", "--config", str(config_path), str(makefile)]
    )

    assert result.exit_code == 0
    assert "syntax errors" not in result.stdout
