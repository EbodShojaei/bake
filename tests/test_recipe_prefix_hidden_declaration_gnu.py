"""A recipe prefix set inside a '# bake-format off' region is respected.

The rules read '.RECIPEPREFIX' line by line from the lines they can see. When
the assignment is hidden by a '# bake-format off' region, RecipeValidationRule
used to add a TAB in front of a recipe line that already starts with that
prefix, and GNU make 4.x then rejected the file ("missing separator"): with
'.RECIPEPREFIX = >', a line that begins with a TAB is not a recipe line (GNU
make manual 16.2, lines 5158-5169). make 3.81 has no .RECIPEPREFIX, so the
make-backed check runs with make 4.x only. A prefix set with '+=' or 'define'
outside a region is still read line by line, as before (README backlog).
"""

import os
import re
import shutil
import subprocess

import pytest

from mbake.config import Config, FormatterConfig
from mbake.core.formatter import MakefileFormatter

_MAKE_ENV = {"PATH": os.defpath, "LC_ALL": "C"}

HIDDEN_PREFIX = (
    "# bake-format off\n.RECIPEPREFIX = >\n# bake-format on\nall:\n>@echo a\n"
)
HIDDEN_APPEND = (
    "# bake-format off\n.RECIPEPREFIX += >\n# bake-format on\nall:\n>@echo a\n"
)


@pytest.fixture(scope="module")
def gnu_make4():
    """Return the path of a GNU make 4.x, or skip."""
    if os.name == "nt":
        pytest.skip("GNU make checks do not run on Windows")
    if shutil.which("true") is None:
        pytest.skip("true is not installed")
    for name in ("gmake", "make"):
        make = shutil.which(name)
        if make is None:
            continue
        try:
            version = subprocess.run(
                [make, "--version"],
                capture_output=True,
                text=True,
                timeout=30,
                env=_MAKE_ENV,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        match = re.search(r"GNU Make (\d+)\.", version)
        if match and int(match.group(1)) >= 4:
            return make
    pytest.skip("no GNU make 4.x is installed")


def _format(text, check_only=False):
    formatter = MakefileFormatter(Config(formatter=FormatterConfig()))
    lines, errors, warnings = formatter.format_lines(
        text.splitlines(), check_only, text
    )
    return "\n".join(lines).rstrip("\n") + "\n", errors, warnings


@pytest.mark.parametrize("text", [HIDDEN_PREFIX, HIDDEN_APPEND])
def test_recipe_line_with_the_real_prefix_gets_no_tab(text):
    """The line already starts with the prefix make reads, so it is left."""
    content, errors, _ = _format(text)
    assert content == text
    assert errors == []
    _, check_errors, check_warnings = _format(text, check_only=True)
    assert check_errors == []
    assert not any("tab separator" in message for message in check_warnings)


@pytest.mark.parametrize("text", [HIDDEN_PREFIX, HIDDEN_APPEND])
def test_make_runs_input_and_output_the_same(gnu_make4, tmp_path, text):
    """GNU make 4.x prints 'a' for the input and for the output."""
    content, _, _ = _format(text)

    def run(makefile):
        (tmp_path / "p.mk").write_text(makefile, encoding="utf-8")
        proc = subprocess.run(
            [gnu_make4, "-r", "-R", "-s", "-f", "p.mk", "all"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            timeout=60,
            env=_MAKE_ENV,
        )
        return proc.returncode, proc.stdout

    assert run(text) == (0, "a\n")
    assert run(content) == (0, "a\n")


def test_tab_prefix_is_still_repaired():
    """A space-led recipe line under the default prefix still gets its TAB."""
    content, _, _ = _format("all:\n    @echo a\n")
    assert content == "all:\n\t@echo a\n"
