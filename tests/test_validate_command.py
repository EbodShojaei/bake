"""Tests for the validate command."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from mbake.cli import app


class TestValidateCommand:
    """Test the validate command functionality."""

    @pytest.fixture
    def runner(self):
        """Create a CLI runner for testing."""
        return CliRunner()

    def test_validate_simple_makefile(self, runner):
        """Test validation of a simple Makefile."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mk", delete=False) as f:
            f.write("test_target:\n\techo 'hello'\n")
            makefile_path = f.name

        try:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                mock_run.return_value.stderr = ""

                result = runner.invoke(app, ["validate", makefile_path])

                assert result.exit_code == 0
                assert "Valid" in result.stdout
                assert "syntax" in result.stdout
                mock_run.assert_called_once()

                # Check that the command was called with the correct arguments
                call_args = mock_run.call_args
                assert call_args[0][0] == [
                    "make",
                    "-f",
                    Path(makefile_path).name,
                    "--dry-run",
                    "--just-print",
                ]
                assert call_args[1]["cwd"] == Path(makefile_path).parent
        finally:
            Path(makefile_path).unlink()

    def test_validate_makefile_with_relative_include(self, runner):
        """Test validation of a Makefile with relative include paths."""
        # Create a temporary directory structure
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create a common Makefile in the parent directory
            common_mk = temp_path / "common.mk"
            common_mk.write_text("COMMON_VAR = 'from common'\n")

            # Create a subdirectory
            subdir = temp_path / "subdir"
            subdir.mkdir()

            # Create a Makefile in the subdirectory that includes the common file
            makefile_mk = subdir / "Makefile"
            makefile_mk.write_text(
                "include ../common.mk\ntest_target:\n\techo $(COMMON_VAR)\n"
            )

            with patch("subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                mock_run.return_value.stderr = ""

                # Test validation from parent directory
                result = runner.invoke(app, ["validate", str(makefile_mk)])

                assert result.exit_code == 0
                assert "Valid" in result.stdout
                assert "syntax" in result.stdout
                mock_run.assert_called_once()

                # Check that the command was called with the correct working directory
                call_args = mock_run.call_args
                assert call_args[1]["cwd"] == subdir
                assert call_args[0][0] == [
                    "make",
                    "-f",
                    "Makefile",
                    "--dry-run",
                    "--just-print",
                ]

    def test_validate_makefile_with_syntax_error(self, runner):
        """Test validation of a Makefile with syntax errors."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".mk", delete=False) as f:
            f.write("test_target:\necho 'missing tab'\n")  # Missing tab
            makefile_path = f.name

        try:
            result = runner.invoke(app, ["validate", makefile_path])

            # The actual behavior is exit code 2 for syntax errors
            assert result.exit_code == 2
            assert "Invalid" in result.stdout
            assert "syntax" in result.stdout
        finally:
            Path(makefile_path).unlink()

    def test_validate_nonexistent_file(self, runner):
        """Test validation of a non-existent file."""
        result = runner.invoke(app, ["validate", "nonexistent.mk"])

        assert result.exit_code == 2
        assert "File not found" in result.stdout

    def test_validate_multiple_files(self, runner):
        """Test validation of multiple files."""
        with (
            tempfile.NamedTemporaryFile(mode="w", suffix=".mk", delete=False) as f1,
            tempfile.NamedTemporaryFile(mode="w", suffix=".mk", delete=False) as f2,
        ):
            f1.write("target1:\n\techo 'hello'\n")
            f2.write("target2:\n\techo 'world'\n")
            makefile1_path = f1.name
            makefile2_path = f2.name

        try:
            with patch("subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                mock_run.return_value.stderr = ""

                result = runner.invoke(
                    app, ["validate", makefile1_path, makefile2_path]
                )

                assert result.exit_code == 0
                assert "Valid" in result.stdout
                assert "syntax" in result.stdout
                assert mock_run.call_count == 2
        finally:
            Path(makefile1_path).unlink()
            Path(makefile2_path).unlink()
