"""Tests for recipe repair when make's recipe prefix differs from the rules' reading.

The rules read .RECIPEPREFIX line by line, from plain '.RECIPEPREFIX = X' and
':=' lines they can see. make also reads '+=' and 'define' assignments, the
lines that '# bake-format off' hides, and values it computes (GNU make
manual 16.2, lines 5158-5169). RecipeValidationRule must never add a TAB to a
line that make already reads as a recipe line under its prefix: the TAB
turns the recipe line into makefile text and make stops with "missing
separator". The make-backed tests run only with a GNU make 4.x, which has
.RECIPEPREFIX; make 3.81 does not.
"""

import os
import re
import shutil
import subprocess

import pytest

from mbake.config import Config, FormatterConfig
from mbake.core.formatter import MakefileFormatter

# make runs with a minimal environment so that no inherited variable (such as
# MAKEFLAGS) changes what it reads.
_MAKE_ENV = {"PATH": os.defpath, "LC_ALL": "C"}

# A rule hidden in a region, its '>'-prefixed recipe visible after the
# marker, and a prefix that the rules do not see: set inside the region, with
# '+=', or with 'define'. make 4.x accepts every one of these as written.
HIDDEN_RULE_PREFIX = {
    "prefix_inside_region": (
        "# bake-format off\n.RECIPEPREFIX = >\nbuild:\n# bake-format on\n"
        ">@echo build\n"
    ),
    "prefix_appended": (
        ".RECIPEPREFIX += >\n# bake-format off\nall:\n# bake-format on\n>@echo a\n"
    ),
    "prefix_defined": (
        "define .RECIPEPREFIX\n>\nendef\n# bake-format off\nall:\n# bake-format on\n"
        ">@echo a\n"
    ),
    "prefix_computed": (
        "GT := >\n.RECIPEPREFIX := $(GT)\n# bake-format off\nall:\n# bake-format on\n"
        ">@echo a\n"
    ),
}

# The same shape with a prefix the rules do see: unchanged before and after.
VISIBLE_PREFIX = (
    ".RECIPEPREFIX = >\n# bake-format off\nall:\n# bake-format on\n>@echo a\n"
)


def _formatter(**kwargs):
    return MakefileFormatter(Config(formatter=FormatterConfig(**kwargs)))


@pytest.fixture(scope="module", params=["make", "gmake"])
def gnu_make_4(request):
    """Return (make, true) for a GNU make 4.x, or skip."""
    if os.name == "nt":
        pytest.skip("GNU make checks do not run on Windows")
    make = shutil.which(request.param)
    true = shutil.which("true")
    if make is None or true is None:
        pytest.skip(f"{request.param} or true is not installed")
    plain_make = shutil.which("make")
    if (
        request.param != "make"
        and plain_make is not None
        and os.path.realpath(plain_make) == os.path.realpath(make)
    ):
        pytest.skip("gmake is the same program as make")
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
    match = re.match(r"GNU Make (\d+)\.", version)
    if match is None:
        pytest.skip("make is not GNU make")
    if int(match.group(1)) < 4:
        pytest.skip("this make has no .RECIPEPREFIX")
    return make, true


def _dry_run(gnu_make_4, tmp_path, name, text):
    """Write text to tmp_path/name and return make's dry-run output and status.

    Nothing is appended after the text's last line.
    """
    make, true = gnu_make_4
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    proc = subprocess.run(
        [make, "-r", "-R", "-n", "-f", name, f"SHELL={true}"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        env=_MAKE_ENV,
    )
    return proc.returncode, proc.stdout


class TestHiddenRuleKeepsItsPrefixedRecipe:
    """A recipe line that starts with make's prefix is left alone, whatever
    line sets that prefix."""

    @pytest.mark.parametrize("name", sorted(HIDDEN_RULE_PREFIX))
    def test_output_is_unchanged(self, name):
        text = HIDDEN_RULE_PREFIX[name]
        assert _formatter().format(text).content == text

    @pytest.mark.parametrize("name", sorted(HIDDEN_RULE_PREFIX))
    def test_check_mode_reports_nothing(self, name):
        """Check mode must agree: no missing-TAB error and no change."""
        text = HIDDEN_RULE_PREFIX[name]
        lines, errors, warnings = _formatter().format_lines(
            text.splitlines(), True, text
        )
        assert lines == text.splitlines()
        assert errors == []
        assert not [w for w in warnings if "Missing required tab" in w]

    @pytest.mark.parametrize("name", sorted(HIDDEN_RULE_PREFIX))
    def test_no_error_without_repair(self, name):
        """With fix_missing_recipe_tabs off, the line is not reported either."""
        text = HIDDEN_RULE_PREFIX[name]
        result = _formatter(fix_missing_recipe_tabs=False).format(text)
        assert result.content == text
        assert result.errors == []

    @pytest.mark.parametrize("name", sorted(HIDDEN_RULE_PREFIX))
    def test_make_reads_the_output_as_the_input(self, gnu_make_4, tmp_path, name):
        """make 4.x runs the input; the output must run the same way."""
        text = HIDDEN_RULE_PREFIX[name]
        before = _dry_run(gnu_make_4, tmp_path, "input.mk", text)
        assert before[0] == 0, before
        after = _dry_run(
            gnu_make_4, tmp_path, "output.mk", _formatter().format(text).content
        )
        assert after == before

    def test_visible_prefix_still_unchanged(self):
        assert _formatter().format(VISIBLE_PREFIX).content == VISIBLE_PREFIX


class TestRepairStillApplies:
    """Lines that lack the TAB that make needs still get it."""

    def test_column0_command_after_rule(self):
        assert _formatter().format("all:\necho hi\n").content == "all:\n\techo hi\n"

    def test_hidden_rule_with_the_default_prefix(self):
        """The rule may be hidden in a region; with the TAB prefix the
        column-0 command after the marker is still repaired (GNU 2881-2884)."""
        text = "# bake-format off\nall:\n# bake-format on\necho c\n"
        expected = "# bake-format off\nall:\n# bake-format on\n\techo c\n"
        assert _formatter().format(text).content == expected

    def test_visible_prefix_behaves_as_before(self):
        """With a prefix the rules see, nothing changes: a column-0 command
        after a '>'-prefixed recipe is left alone, as before."""
        text = ".RECIPEPREFIX = >\nall:\n>@echo a\necho b\n"
        assert _formatter().format(text).content == text

    def test_appended_prefix_keeps_the_old_repair_of_a_column0_line(self):
        """A column-0 command whose line starts with no prefix at all is
        still repaired with a TAB, as before; make rejects the input either
        way (GNU 11283-11290)."""
        text = ".RECIPEPREFIX += >\nall:\necho b\n"
        expected = ".RECIPEPREFIX += >\nall:\n\techo b\n"
        assert _formatter().format(text).content == expected
