"""Tests for CLI functionality."""

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from mbake.cli import app
from mbake.config import Config, FormatterConfig


class TestCLIFormat:
    """Test CLI format command functionality."""

    @pytest.fixture
    def runner(self):
        """Create a CLI runner for testing."""
        return CliRunner()

    @pytest.fixture
    def test_config(self):
        """Create a test configuration with consistent settings."""
        return Config(
            formatter=FormatterConfig(
                space_around_assignment=True,
                group_phony_declarations=False,
                phony_at_top=False,
                auto_insert_phony_declarations=False,
                ensure_final_newline=False,
            )
        )

    def test_format_stdin_basic(self, runner, test_config):
        """Test basic stdin formatting functionality."""
        input_content = "target:\n\techo hello"
        expected_content = (
            "target:\n\techo hello"  # No phony insertion, no final newline
        )

        with patch("mbake.cli.Config.load_or_default", return_value=test_config):
            result = runner.invoke(app, ["format", "--stdin"], input=input_content)

        assert result.exit_code == 0
        assert result.stdout == expected_content

    def test_format_stdin_with_multiple_targets(self, runner, test_config):
        """Test stdin formatting with multiple targets."""
        input_content = "target1:\n\techo hello\ntarget2:\n\techo world"
        expected_content = "target1:\n\techo hello\ntarget2:\n\techo world"  # No phony insertion, no final newline

        with patch("mbake.cli.Config.load_or_default", return_value=test_config):
            result = runner.invoke(app, ["format", "--stdin"], input=input_content)

        assert result.exit_code == 0
        assert result.stdout == expected_content

    def test_format_stdin_with_errors(self, runner, test_config):
        """Test stdin formatting with formatting errors."""
        # This should trigger some formatting rules that might cause errors
        input_content = "target:\necho hello"  # Missing tab for recipe

        with patch("mbake.cli.Config.load_or_default", return_value=test_config):
            result = runner.invoke(app, ["format", "--stdin"], input=input_content)

        # Should still format but might have warnings/errors
        assert result.exit_code == 0
        assert "target:" in result.stdout
        assert "echo hello" in result.stdout

    def test_format_stdin_with_check_flag(self, runner, test_config):
        """Test stdin formatting with --check flag."""
        input_content = "target:\n\techo hello"

        with patch("mbake.cli.Config.load_or_default", return_value=test_config):
            result = runner.invoke(
                app, ["format", "--stdin", "--check"], input=input_content
            )

        # With conservative config, well-formatted input should return exit code 0
        assert result.exit_code == 0
        assert result.stdout == "target:\n\techo hello"

    def test_format_stdin_with_verbose_flag(self, runner, test_config):
        """Test stdin formatting with --verbose flag."""
        input_content = "target:\n\techo hello"
        expected_content = (
            "target:\n\techo hello"  # No phony insertion, no final newline
        )

        with patch("mbake.cli.Config.load_or_default", return_value=test_config):
            result = runner.invoke(
                app, ["format", "--stdin", "--verbose"], input=input_content
            )

        assert result.exit_code == 0
        assert result.stdout == expected_content

    def test_format_stdin_cannot_specify_files(self, runner, test_config):
        """Test that --stdin cannot be used with file arguments."""
        with patch("mbake.cli.Config.load_or_default", return_value=test_config):
            result = runner.invoke(app, ["format", "--stdin", "Makefile"])

        assert result.exit_code == 1
        assert "Cannot specify files when using --stdin" in result.stdout

    def test_format_requires_files_or_stdin(self, runner, test_config):
        """Test that format command requires either files or --stdin."""
        with patch("mbake.cli.Config.load_or_default", return_value=test_config):
            result = runner.invoke(app, ["format"])

        assert result.exit_code == 1
        assert "No files specified" in result.stdout
        assert "Use --stdin" in result.stdout

    def test_format_stdin_preserves_empty_input(self, runner, test_config):
        """Test that stdin formatting handles empty input gracefully."""
        with patch("mbake.cli.Config.load_or_default", return_value=test_config):
            result = runner.invoke(app, ["format", "--stdin"], input="")

        assert result.exit_code == 0
        assert result.stdout == ""

    def test_format_stdin_with_complex_makefile(self, runner, test_config):
        """Test stdin formatting with a complex Makefile."""
        input_content = """# Complex Makefile
CC=gcc
CFLAGS=-Wall

.PHONY: clean
clean:
\trm -f *.o

build: main.o
\t$(CC) $(CFLAGS) -o main main.o

main.o: main.c
\t$(CC) $(CFLAGS) -c main.c
"""

        with patch("mbake.cli.Config.load_or_default", return_value=test_config):
            result = runner.invoke(app, ["format", "--stdin"], input=input_content)

        assert result.exit_code == 0
        # Should format the assignments but not modify PHONY (conservative config)
        assert "CC = gcc" in result.stdout
        assert "CFLAGS = -Wall" in result.stdout
        # Conservative config preserves existing .PHONY without auto-insertion
        assert ".PHONY: clean" in result.stdout
        assert ".PHONY: clean build" not in result.stdout  # No auto-insertion

    def test_format_stdin_error_output_to_stderr(self, runner, test_config):
        """Test that errors from stdin formatting go to stderr."""
        # Create input that might cause errors
        input_content = "target:\necho hello"  # Missing tab

        with patch("mbake.cli.Config.load_or_default", return_value=test_config):
            result = runner.invoke(app, ["format", "--stdin"], input=input_content)

        # Should still succeed but might have warnings
        assert result.exit_code == 0
        # The formatted output should be in stdout
        assert "target:" in result.stdout

    def test_format_stdin_with_diff_flag(self, runner, test_config):
        """Test that --diff flag works with --stdin."""
        input_content = "target:\n\techo hello"

        with patch("mbake.cli.Config.load_or_default", return_value=test_config):
            result = runner.invoke(
                app, ["format", "--stdin", "--diff"], input=input_content
            )

        # --diff should show the diff but not modify the output
        assert result.exit_code == 0
        # The diff should be shown, but the formatted content should still be output
        assert "target:" in result.stdout

    def test_format_stdin_with_backup_flag(self, runner, test_config):
        """Test that --backup flag is ignored with --stdin."""
        input_content = "target:\n\techo hello"
        expected_content = (
            "target:\n\techo hello"  # No phony insertion, no final newline
        )

        with patch("mbake.cli.Config.load_or_default", return_value=test_config):
            result = runner.invoke(
                app, ["format", "--stdin", "--backup"], input=input_content
            )

        assert result.exit_code == 0
        assert result.stdout == expected_content

    def test_format_stdin_with_validate_flag(self, runner, test_config):
        """Test that --validate flag is ignored with --stdin."""
        input_content = "target:\n\techo hello"
        expected_content = (
            "target:\n\techo hello"  # No phony insertion, no final newline
        )

        with patch("mbake.cli.Config.load_or_default", return_value=test_config):
            result = runner.invoke(
                app, ["format", "--stdin", "--validate"], input=input_content
            )

        assert result.exit_code == 0
        assert result.stdout == expected_content


# Note: Help text tests removed due to ANSI color code issues in CI
# The core --stdin functionality is tested in TestCLIFormat class


class TestCLIQuietSilentFlags:
    """Test --quiet and --silent flag functionality."""

    @pytest.fixture
    def runner(self):
        """Create a CLI runner for testing."""
        return CliRunner()

    @pytest.fixture
    def test_config(self):
        """Create a test configuration with consistent settings."""
        return Config(
            formatter=FormatterConfig(
                space_around_assignment=True,
                group_phony_declarations=False,
                phony_at_top=False,
                auto_insert_phony_declarations=False,
                ensure_final_newline=False,
            )
        )

    def test_quiet_flag_suppresses_non_diagnostics(self, runner, test_config):
        """Test that --quiet suppresses non-diagnostic output like summary."""
        input_content = "target:\n\techo hello"

        with patch("mbake.cli.Config.load_or_default", return_value=test_config):
            result = runner.invoke(
                app, ["format", "--stdin", "--quiet"], input=input_content
            )

        assert result.exit_code == 0
        assert result.stdout == input_content

    def test_quiet_flag_short_form(self, runner, test_config):
        """Test that -q short form works the same as --quiet."""
        input_content = "target:\n\techo hello"

        with patch("mbake.cli.Config.load_or_default", return_value=test_config):
            result = runner.invoke(
                app, ["format", "--stdin", "-q"], input=input_content
            )

        assert result.exit_code == 0
        assert result.stdout == input_content

    def test_silent_flag_suppresses_all_output(self, runner, test_config):
        """Test that --silent suppresses all output."""
        input_content = "target:\n\techo hello"

        with patch("mbake.cli.Config.load_or_default", return_value=test_config):
            result = runner.invoke(
                app, ["format", "--stdin", "--silent"], input=input_content
            )

        assert result.exit_code == 0
        assert result.stdout == input_content

    def test_silent_flag_short_form(self, runner, test_config):
        """Test that -s short form works the same as --silent."""
        input_content = "target:\n\techo hello"

        with patch("mbake.cli.Config.load_or_default", return_value=test_config):
            result = runner.invoke(
                app, ["format", "--stdin", "-s"], input=input_content
            )

        assert result.exit_code == 0
        assert result.stdout == input_content

    def test_silent_still_exits_with_error_on_check_failure(
        self, runner, test_config
    ):
        """Test that --silent still exits with code 1 when check finds reformattable files."""
        # Input that needs formatting (unspaced assignment)
        input_content = "VAR=value\ntarget:\n\techo hello"

        with patch("mbake.cli.Config.load_or_default", return_value=test_config):
            result = runner.invoke(
                app,
                ["format", "--stdin", "--check", "--silent"],
                input=input_content,
            )

        # Should exit 1 (would reformat) but with no output
        assert result.exit_code == 1
        assert result.stdout == ""

    def test_quiet_still_exits_with_error_on_check_failure(
        self, runner, test_config
    ):
        """Test that --quiet still exits with code 1 when check finds reformattable files."""
        # Input that needs formatting (unspaced assignment)
        input_content = "VAR=value\ntarget:\n\techo hello"

        with patch("mbake.cli.Config.load_or_default", return_value=test_config):
            result = runner.invoke(
                app,
                ["format", "--stdin", "--check", "--quiet"],
                input=input_content,
            )

        # Should exit 1 (would reformat) and print the diagnostic
        assert result.exit_code == 1
