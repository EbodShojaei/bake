"""Tests for the line numbers in 'Invalid target syntax' warnings.

TargetValidationRule enumerates its input from 1 and must report that number
unchanged, so that the warning names the line it quotes. GNU make attributes a
variable definition to the same physical line: 'make -p' prints
"# makefile (from 'Makefile', line N)" above it. Line numbers in docstrings
refer to the GNU make 4.4.1 manual.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mbake.cli import app
from mbake.config import Config, FormatterConfig
from mbake.core.formatter import MakefileFormatter
from mbake.core.rules.target_validation import TargetValidationRule

FIXTURES = Path(__file__).resolve().parent / "fixtures"
FIXTURE_NAMES = sorted(path.parent.name for path in FIXTURES.glob("*/input.mk"))

INVALID_TARGET = re.compile(r"^(\d+): Warning: Invalid target syntax: (.*)$", re.S)
# 'make -p' origin line; make 3.81 opens the quote with a backtick.
MAKE_ORIGIN = re.compile(r"^# makefile \(from [`'][^']*', line (\d+)\)$")

# make runs with a minimal environment so that no inherited variable changes
# what it reads.
_MAKE_ENV = {"PATH": os.defpath, "LC_ALL": "C"}

FIRST_LINE = "X=a:b\nall:\n\t@echo $(X)\n"
LAST_LINE = "# c\n\nX=a:b\n"
BEFORE_REGION = "X=a:b\n# bake-format off\njunk   =   1\nmore   =   2\n"


def _runner() -> CliRunner:
    """Return a CliRunner that keeps stdout and stderr apart."""
    try:
        return CliRunner(mix_stderr=False)  # click < 8.2
    except TypeError:
        return CliRunner()  # click >= 8.2 always captures stderr separately


def _invalid_target_warnings(text, check_only=False, gnu_error_format=True):
    """Return the 'Invalid target syntax' warnings for text."""
    formatter = MakefileFormatter(
        Config(formatter=FormatterConfig(), gnu_error_format=gnu_error_format)
    )
    _, _, warnings = formatter.format_lines(text.splitlines(), check_only, text)
    return [warning for warning in warnings if "Invalid target syntax" in warning]


@pytest.fixture(scope="module")
def gnu_make():
    """Return (make, true) paths, or skip when GNU make cannot run here."""
    if os.name == "nt":
        pytest.skip("GNU make checks do not run on Windows")
    make = shutil.which("make")
    true = shutil.which("true")
    if make is None or true is None:
        pytest.skip("make or true is not installed")
    try:
        version = subprocess.run(
            [make, "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            env=_MAKE_ENV,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        pytest.skip("make --version failed")
    if "GNU Make" not in version:
        pytest.skip("make is not GNU make")
    return make, true


def _definition_line(gnu_make, tmp_path, text, name):
    """Return the line to which make attributes the definition of name.

    The return code is not checked: a makefile without targets exits 2 but
    still prints its database.
    """
    make, true = gnu_make
    (tmp_path / "Makefile").write_text(text, encoding="utf-8")
    proc = subprocess.run(
        [make, "-r", "-R", "-f", "Makefile", "-p", "-n", f"SHELL={true}"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        env=_MAKE_ENV,
    )
    lines = proc.stdout.splitlines()
    for origin, definition in zip(lines, lines[1:]):
        match = MAKE_ORIGIN.match(origin)
        if match and definition.split(" ", 1)[0] == name:
            return int(match.group(1))
    pytest.fail(f"make -p did not say where {name} is defined:\n{proc.stdout}")


class TestRuleNumbering:
    """The rule reports the 1-based number of the line it quotes."""

    def test_rule_reports_the_line_it_quotes(self):
        """Direct call: the only line is line 1, not line 2."""
        result = TargetValidationRule().format(
            ["X=a:b"], {"_global": {"gnu_error_format": True}}
        )
        assert result.warnings == ["1: Warning: Invalid target syntax: X=a:b"]

    def test_traditional_format_reports_the_same_line(self):
        """The '(line N)' form carries the same number."""
        result = TargetValidationRule().format(
            ["X=a:b"], {"_global": {"gnu_error_format": False}}
        )
        assert result.warnings == ["Warning: Invalid target syntax: X=a:b (line 1)"]

    @pytest.mark.parametrize("check_only", [False, True])
    def test_first_line_in_both_modes(self, check_only):
        """format_lines reports line 1 in format mode and in check mode."""
        assert _invalid_target_warnings(FIRST_LINE, check_only) == [
            "1: Warning: Invalid target syntax: X=a:b"
        ]
        assert _invalid_target_warnings(FIRST_LINE, check_only, False) == [
            "Warning: Invalid target syntax: X=a:b (line 1)"
        ]

    def test_last_line_is_not_reported_past_the_end(self):
        """A flagged last line is line 3 of a 3-line file, not line 4."""
        assert _invalid_target_warnings(LAST_LINE) == [
            "3: Warning: Invalid target syntax: X=a:b"
        ]

    def test_line_before_a_disabled_region(self):
        """A flagged line right before '# bake-format off' is still line 1."""
        assert _invalid_target_warnings(BEFORE_REGION) == [
            "1: Warning: Invalid target syntax: X=a:b"
        ]

    @pytest.mark.parametrize("check_only", [False, True])
    @pytest.mark.parametrize("name", FIXTURE_NAMES)
    def test_every_fixture_warning_names_the_line_it_quotes(self, name, check_only):
        """For every fixture, input line N (stripped) is the text the warning
        'N: Warning: Invalid target syntax: ...' quotes."""
        text = (FIXTURES / name / "input.mk").read_text(encoding="utf-8")
        lines = text.splitlines()
        for warning in _invalid_target_warnings(text, check_only):
            match = INVALID_TARGET.match(warning)
            assert match is not None, warning
            number = int(match.group(1))
            assert 1 <= number <= len(lines), warning
            assert lines[number - 1].strip() == match.group(2), warning

    @pytest.mark.parametrize(
        ("name", "expected"),
        [("invalid_targets", [4, 27]), ("edge_cases_and_quirks", [77, 78])],
    )
    def test_known_fixture_lines(self, name, expected):
        """The two fixtures that trigger the lint report the lines holding the
        quoted text; each was reported one line too high before the fix."""
        text = (FIXTURES / name / "input.mk").read_text(encoding="utf-8")
        matches = map(INVALID_TARGET.match, _invalid_target_warnings(text, True))
        assert [int(match.group(1)) for match in matches if match] == expected


class TestAgainstGnuMake:
    """The reported line is the one make attributes the assignment to."""

    @pytest.mark.parametrize(
        "text", [FIRST_LINE, LAST_LINE], ids=["first-line", "last-line"]
    )
    def test_warning_names_the_line_make_reads_the_assignment_from(
        self, gnu_make, tmp_path, text
    ):
        """make reads 'X=a:b' as a plain assignment on its own line
        (GNU 1225-1227, 4577-4580); the warning must name that line."""
        expected = _definition_line(gnu_make, tmp_path, text, "X")
        assert _invalid_target_warnings(text) == [
            f"{expected}: Warning: Invalid target syntax: X=a:b"
        ]
        assert _invalid_target_warnings(text, gnu_error_format=False) == [
            f"Warning: Invalid target syntax: X=a:b (line {expected})"
        ]


class TestCli:
    """'mbake format --check' prints FILE:LINE for the flagged line."""

    def test_check_prints_the_flagged_line(self, tmp_path, monkeypatch):
        """The CLI prefixes the file name to the rule's own line number."""
        (tmp_path / "Makefile").write_text(FIRST_LINE, encoding="utf-8")
        (tmp_path / "bake.toml").write_text("", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COLUMNS", "200")  # keep Rich from wrapping the line
        result = _runner().invoke(
            app, ["format", "--config", "bake.toml", "--check", "Makefile"]
        )
        assert "Makefile:1: Warning: Invalid target syntax: X=a:b" in result.stdout
        assert "Makefile:2: Warning: Invalid target syntax" not in result.stdout
