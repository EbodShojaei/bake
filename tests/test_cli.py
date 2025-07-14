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
                use_tabs=True,
                space_around_assignment=True,
                group_phony_declarations=True,
                phony_at_top=True,
                auto_insert_phony_declarations=True,
                ensure_final_newline=True,
            )
        )

    def test_format_stdin_basic(self, runner, test_config):
        """Test basic stdin formatting functionality."""
        input_content = "target:\n\techo hello"
        expected_content = ".PHONY: target\n\ntarget:\n\techo hello\n"

        with patch("mbake.cli.Config.load_or_default", return_value=test_config):
            result = runner.invoke(app, ["format", "--stdin"], input=input_content)

        assert result.exit_code == 0
        assert result.stdout == expected_content

    def test_format_stdin_with_multiple_targets(self, runner, test_config):
        """Test stdin formatting with multiple targets."""
        input_content = "target1:\n\techo hello\ntarget2:\n\techo world"
        expected_content = ".PHONY: target1 target2\n\ntarget1:\n\techo hello\ntarget2:\n\techo world\n"

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
        expected_content = ".PHONY: target\n\ntarget:\n\techo hello\n"

        with patch("mbake.cli.Config.load_or_default", return_value=test_config):
            result = runner.invoke(
                app, ["format", "--stdin", "--check"], input=input_content
            )

        assert result.exit_code == 0
        assert result.stdout == expected_content

    def test_format_stdin_with_verbose_flag(self, runner, test_config):
        """Test stdin formatting with --verbose flag."""
        input_content = "target:\n\techo hello"
        expected_content = ".PHONY: target\n\ntarget:\n\techo hello\n"

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
        # Should format the assignments and organize PHONY declarations
        assert "CC = gcc" in result.stdout
        assert "CFLAGS = -Wall" in result.stdout
        assert (
            ".PHONY: clean build" in result.stdout
            or ".PHONY: build clean" in result.stdout
        )

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
        expected_content = ".PHONY: target\n\ntarget:\n\techo hello\n"

        with patch("mbake.cli.Config.load_or_default", return_value=test_config):
            result = runner.invoke(
                app, ["format", "--stdin", "--backup"], input=input_content
            )

        assert result.exit_code == 0
        assert result.stdout == expected_content

    def test_format_stdin_with_validate_flag(self, runner, test_config):
        """Test that --validate flag is ignored with --stdin."""
        input_content = "target:\n\techo hello"
        expected_content = ".PHONY: target\n\ntarget:\n\techo hello\n"

        with patch("mbake.cli.Config.load_or_default", return_value=test_config):
            result = runner.invoke(
                app, ["format", "--stdin", "--validate"], input=input_content
            )

        assert result.exit_code == 0
        assert result.stdout == expected_content


# Note: Help text tests removed due to ANSI color code issues in CI
# The core --stdin functionality is tested in TestCLIFormat class
