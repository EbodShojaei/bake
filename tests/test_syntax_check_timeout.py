"""Tests for the syntax_check_timeout setting and the --timeout option."""

import dataclasses
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from mbake.cli import app
from mbake.config import Config, FormatterConfig


def _write_config(directory: Path, text: str) -> Path:
    path = directory / "bake.toml"
    path.write_text(text)
    return path


def _make_run_result(returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout="", stderr=""
    )


class TestConfigField:
    """syntax_check_timeout is a real Config field."""

    def test_declared_last_so_positional_arguments_keep_their_meaning(self):
        names = [field.name for field in dataclasses.fields(Config)]
        assert names == [
            "formatter",
            "debug",
            "verbose",
            "gnu_error_format",
            "wrap_error_messages",
            "syntax_check_timeout",
        ]

        config = Config(FormatterConfig(), True, True, False, True)
        assert config.gnu_error_format is False
        assert config.wrap_error_messages is True
        assert config.syntax_check_timeout == 10

    def test_accepted_as_keyword_argument(self):
        config = Config(formatter=FormatterConfig(), syntax_check_timeout=5)
        assert config.syntax_check_timeout == 5
        assert config.to_dict()["syntax_check_timeout"] == 5

    def test_default_is_ten_seconds(self):
        assert Config(formatter=FormatterConfig()).syntax_check_timeout == 10


class TestLoad:
    """Config.load reads syntax_check_timeout from the top level of the file."""

    def test_top_level_key_is_read(self, tmp_path):
        path = _write_config(
            tmp_path, "syntax_check_timeout = 3\n\n[formatter]\ntab_width = 4\n"
        )
        config = Config.load(path)
        assert config.syntax_check_timeout == 3
        assert config.formatter.tab_width == 4

    def test_fractional_seconds_are_accepted(self, tmp_path):
        path = _write_config(tmp_path, "syntax_check_timeout = 2.5\n")
        assert Config.load(path).syntax_check_timeout == 2.5

    def test_one_day_is_the_largest_accepted_value(self, tmp_path):
        path = _write_config(tmp_path, "syntax_check_timeout = 86400\n")
        assert Config.load(path).syntax_check_timeout == 86400

    @pytest.mark.parametrize(
        "value", ['"30"', "true", "0", "-5", "nan", "inf", "86401"]
    )
    def test_invalid_value_keeps_default_and_rest_of_file(self, tmp_path, value):
        path = _write_config(
            tmp_path, f"syntax_check_timeout = {value}\n\n[formatter]\ntab_width = 4\n"
        )
        config = Config.load(path)
        assert config.syntax_check_timeout == 10
        assert config.formatter.tab_width == 4

    def test_key_inside_formatter_table_is_ignored(self, tmp_path):
        path = _write_config(tmp_path, "[formatter]\nsyntax_check_timeout = 3\n")
        assert Config.load(path).syntax_check_timeout == 10

    def test_timeout_seconds_key_is_ignored(self, tmp_path):
        path = _write_config(
            tmp_path, "timeout_seconds = 5\n\n[formatter]\ntab_width = 4\n"
        )
        config = Config.load(path)
        assert config.syntax_check_timeout == 10
        assert config.formatter.tab_width == 4

    def test_discovered_config_with_timeout_seconds_is_used(
        self, tmp_path, monkeypatch
    ):
        cwd = tmp_path / "project"
        home = tmp_path / "home"
        cwd.mkdir()
        home.mkdir()
        (cwd / ".bake.toml").write_text(
            "timeout_seconds = 5\nsyntax_check_timeout = 4\n\n"
            "[formatter]\ntab_width = 7\n"
        )
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        with (
            patch.object(Path, "cwd", return_value=cwd),
            patch.object(Path, "home", return_value=home),
        ):
            config = Config.load_or_default()
        assert config.formatter.tab_width == 7
        assert config.syntax_check_timeout == 4


class TestValidateCommand:
    """validate uses the configured timeout for file and stdin input."""

    def test_file_uses_config_timeout(self, tmp_path):
        config_path = _write_config(tmp_path, "syntax_check_timeout = 3\n")
        makefile = tmp_path / "Makefile"
        makefile.write_text("all:\n\t@echo hi\n")

        with patch("subprocess.run", return_value=_make_run_result()) as run:
            result = CliRunner().invoke(
                app, ["validate", "--config", str(config_path), str(makefile)]
            )

        assert result.exit_code == 0
        assert run.call_args.kwargs["timeout"] == 3

    def test_stdin_uses_config_timeout(self, tmp_path):
        config_path = _write_config(tmp_path, "syntax_check_timeout = 3\n")

        with patch("subprocess.run", return_value=_make_run_result()) as run:
            result = CliRunner().invoke(
                app,
                ["validate", "--stdin", "--config", str(config_path)],
                input="all:\n\t@echo hi\n",
            )

        assert result.exit_code == 0
        assert run.call_args.kwargs["timeout"] == 3

    def test_stdin_timeout_is_reported_like_files(self, tmp_path):
        config_path = _write_config(tmp_path, "syntax_check_timeout = 3\n")

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("make", 3)):
            result = CliRunner().invoke(
                app,
                ["validate", "--stdin", "--config", str(config_path)],
                input="all:\n\t@echo hi\n",
            )

        assert result.exit_code == 0
        assert "stdin: Validation timed out" in result.stdout


class TestFormatCommand:
    """format --validate uses --timeout, then the config value, then 10."""

    def _format_and_validate(self, tmp_path, extra_args):
        config_path = _write_config(tmp_path, "syntax_check_timeout = 3\n")
        makefile = tmp_path / "Makefile"
        makefile.write_text("CC=gcc\nall:\n\t@echo hi\n")

        with patch("subprocess.run", return_value=_make_run_result()) as run:
            result = CliRunner().invoke(
                app,
                [
                    "format",
                    "--validate",
                    "--config",
                    str(config_path),
                    *extra_args,
                    str(makefile),
                ],
            )
        return result, run

    def test_validate_uses_config_timeout(self, tmp_path):
        result, run = self._format_and_validate(tmp_path, [])
        assert result.exit_code == 0
        assert run.call_args.kwargs["timeout"] == 3

    def test_timeout_option_overrides_config(self, tmp_path):
        result, run = self._format_and_validate(tmp_path, ["--timeout", "7"])
        assert result.exit_code == 0
        assert run.call_args.kwargs["timeout"] == 7

    def test_timeout_option_accepts_one_day(self, tmp_path):
        result, run = self._format_and_validate(tmp_path, ["--timeout", "86400"])
        assert result.exit_code == 0
        assert run.call_args.kwargs["timeout"] == 86400

    @pytest.mark.parametrize("value", ["0", "-1", "86401"])
    def test_timeout_option_out_of_range_is_a_usage_error(self, tmp_path, value):
        config_path = _write_config(tmp_path, "")
        result = CliRunner().invoke(
            app,
            ["format", "--stdin", "--timeout", value, "--config", str(config_path)],
            input="all:\n\t@echo hi\n",
        )
        assert result.exit_code == 2


def test_config_command_shows_syntax_check_timeout(tmp_path):
    config_path = _write_config(tmp_path, "syntax_check_timeout = 3\n")
    result = CliRunner().invoke(app, ["config", "--config", str(config_path)])
    assert result.exit_code == 0
    assert "syntax_check_timeout: 3" in result.stdout
