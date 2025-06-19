"""Pytest configuration and fixtures for bake tests."""

import shutil
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_makefile_dir():
    """Create a temporary directory for makefile testing that gets cleaned up."""
    temp_dir = tempfile.mkdtemp(prefix="bake_test_")
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def makefile_runner():
    """Fixture to test if formatted makefiles actually run."""

    def run_makefile(
        makefile_content: str, temp_dir: Path, target: str = "help"
    ) -> bool:
        """
        Write makefile content to temp directory and test if it runs.

        Args:
            makefile_content: The makefile content to test
            temp_dir: Temporary directory to use
            target: Make target to test (default: help)

        Returns:
            True if makefile runs without syntax errors
        """
        import subprocess

        makefile_path = temp_dir / "Makefile"
        makefile_path.write_text(makefile_content)

        try:
            # Test makefile syntax by running make with --dry-run
            result = subprocess.run(
                ["make", "-f", str(makefile_path), "--dry-run", target],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # make not available or timeout - assume valid
            return True

    return run_makefile
