"""Tests for shell completion script generation."""

import io
import sys
from collections.abc import Generator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mbake.cli import app
from mbake.completions import ShellType, get_completion_script, write_completion_script


@pytest.fixture
def temp_completion_file(tmp_path) -> Generator[Path, None, None]:
    """Fixture to create a temporary file for completion script testing."""
    yield tmp_path / "completion_script"


def test_completions_command_stdout():
    """Test completions command outputs to stdout."""
    runner = CliRunner()

    # Test bash completions
    result = runner.invoke(app, ["completions", "bash"])
    assert result.exit_code == 0
    assert "_mbake_completion" in result.stdout
    assert "complete -F _mbake_completion mbake" in result.stdout

    # Test zsh completions
    result = runner.invoke(app, ["completions", "zsh"])
    assert result.exit_code == 0
    assert "#compdef mbake" in result.stdout
    assert "_mbake()" in result.stdout

    # Test fish completions
    result = runner.invoke(app, ["completions", "fish"])
    assert result.exit_code == 0
    assert "complete -c mbake" in result.stdout


def test_completions_command_file_output(temp_completion_file: Path):
    """Test completions command outputs to stdout (no file output option)."""
    runner = CliRunner()

    # Test bash completions output to stdout
    result = runner.invoke(app, ["completions", "bash"])
    assert result.exit_code == 0
    assert "_mbake_completion" in result.stdout
    assert "complete -F _mbake_completion mbake" in result.stdout


def test_completions_invalid_shell():
    """Test completions command with invalid shell."""
    runner = CliRunner()
    # Using an invalid value should fail
    result = runner.invoke(app, ["completions", "invalid"])
    assert result.exit_code == 1  # Custom error handling returns exit code 1
    assert "Unsupported shell" in result.stdout


def test_get_completion_script():
    """Test get_completion_script function."""
    # Test bash completion script
    bash_script = get_completion_script(ShellType.BASH)
    assert "_mbake_completion" in bash_script
    assert "complete -F _mbake_completion mbake" in bash_script
    assert "--version" in bash_script
    assert "--help" in bash_script
    assert "format" in bash_script
    assert "validate" in bash_script

    # Test zsh completion script
    zsh_script = get_completion_script(ShellType.ZSH)
    assert "#compdef mbake" in zsh_script
    assert "_mbake()" in zsh_script
    assert "--version" in zsh_script
    assert "--help" in zsh_script

    # Test fish completion script
    fish_script = get_completion_script(ShellType.FISH)
    assert "complete -c mbake" in fish_script
    assert "format" in fish_script
    assert "validate" in fish_script
    assert "completions" in fish_script


def test_write_completion_script_stdout():
    """Test write_completion_script writes to stdout."""
    # Capture stdout
    stdout = io.StringIO()
    sys.stdout = stdout
    try:
        write_completion_script(ShellType.BASH)
        output = stdout.getvalue()
        assert "_mbake_completion" in output
        assert "complete -F _mbake_completion mbake" in output
    finally:
        sys.stdout = sys.__stdout__


def test_write_completion_script_file(temp_completion_file: Path):
    """Test write_completion_script writes to file."""
    write_completion_script(ShellType.BASH, temp_completion_file)
    assert temp_completion_file.exists()
    content = temp_completion_file.read_text()
    assert "_mbake_completion" in content
    assert "complete -F _mbake_completion mbake" in content


def test_completion_script_content():
    """Test completion script content includes all commands and options."""
    # Get bash completion script
    bash_script = get_completion_script(ShellType.BASH)

    # Check for main commands
    main_commands = ["format", "validate", "init", "config", "update", "completions"]
    for cmd in main_commands:
        assert cmd in bash_script

    # Check for format command options
    format_options = [
        "--check",
        "--diff",
        "--backup",
        "--validate",
        "--verbose",
        "--config",
        "--stdin",
    ]
    for opt in format_options:
        assert opt in bash_script

    # Check for validate command options
    validate_options = ["--verbose", "--config"]
    for opt in validate_options:
        assert opt in bash_script

    # Check for shell options in completions command
    shell_options = ["bash", "zsh", "fish"]
    for shell in shell_options:
        assert shell in bash_script


def test_completion_script_handles_errors():
    """Test completion script generation handles errors gracefully."""
    runner = CliRunner()

    # Test with invalid shell
    result = runner.invoke(app, ["completions", "invalid"])
    assert result.exit_code == 1
    assert "Unsupported shell" in result.stdout

    # Test writing to invalid file (direct function call)
    with pytest.raises(OSError, match="No such file or directory"):
        write_completion_script(ShellType.BASH, Path("/nonexistent/path/completions"))


def test_stdin_flag_in_completions():
    """Test that --stdin flag is included in all shell completion scripts."""
    # Test bash completion script
    bash_script = get_completion_script(ShellType.BASH)
    assert "--stdin" in bash_script
    assert "format" in bash_script  # Ensure it's in the format command context

    # Test zsh completion script
    zsh_script = get_completion_script(ShellType.ZSH)
    assert "--stdin" in zsh_script
    assert "Read from stdin and write to stdout" in zsh_script

    # Test fish completion script (Fish uses -l stdin, not --stdin)
    fish_script = get_completion_script(ShellType.FISH)
    assert "-l stdin" in fish_script
    assert "Read from stdin and write to stdout" in fish_script

    # Verify --stdin is only in format command context, not in other commands
    assert "validate.*--stdin" not in bash_script
    assert "init.*--stdin" not in bash_script
