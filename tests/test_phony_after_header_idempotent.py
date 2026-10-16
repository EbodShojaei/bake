"""Tests for running the formatter again over a grouped .PHONY declaration.

With auto_insert_phony_declarations and group_phony_declarations, the first
run puts the .PHONY line, followed by a blank line, after the header comments
or before the first rule (phony_at_top), or at the top of the file. The next
run removed the line, left its blank line behind and inserted the line again
after it, so formatting a formatted file changed it again: below the header a
blank line appeared before the declaration, also as the first line of a file
that began with it, and with normalize_empty_lines off every run added one
more blank line. make ignores those blank lines (GNU make manual 3.1, lines
733-734; 5.1, lines 2884-2886), so only the layout drifted. A declaration that
is already where the insertion puts it now stays where it is, and the first
run is unchanged.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from mbake.config import Config, FormatterConfig
from mbake.core.formatter import MakefileFormatter

# make runs with a minimal environment so that no inherited variable (such as
# MAKEFLAGS) changes what it reads.
_MAKE_ENV = {"PATH": os.defpath, "LC_ALL": "C"}

_GROUPED = {"auto_insert_phony_declarations": True, "group_phony_declarations": True}
CONFIGS = {
    "after_header": {**_GROUPED, "phony_at_top": True},
    "top": {**_GROUPED, "phony_at_top": False},
    "after_header_blank_lines_kept": {
        **_GROUPED,
        "phony_at_top": True,
        "normalize_empty_lines": False,
    },
    "top_blank_lines_kept": {
        **_GROUPED,
        "phony_at_top": False,
        "normalize_empty_lines": False,
    },
}
NORMALIZED = ("after_header", "top")
BLANK_LINES_KEPT = ("after_header_blank_lines_kept", "top_blank_lines_kept")

# Makefiles without a .PHONY line, each with the one phony target 'all'.
LAYOUTS = {
    # Nested '# bake-format off' lines leave a stray '# bake-format on'
    # comment right before the rule.
    "nested_markers": (
        "# bake-format off\nX=1\n# bake-format off\nY=2\n# bake-format on\nZ=3\n"
        "# bake-format on\nall:\n\t@echo $(X)$(Y)$(Z)\n"
    ),
    "assignment": "CC = cc\nall:\n\t@echo $(CC)\n",
    "section_comment": "CC = cc\n# Targets\nall:\n\t@echo $(CC)\n",
    "include": "-include config.mk\nall:\n\t@echo all\n",
    "rule_first": "all:\n\t@echo all\n",
    # A region after the declaration, whose '# bake-format off' line moves
    # when the declaration is taken out and put back.
    "region_after_rule": (
        "X = 1\nall:\n\t@echo $(X)\n# bake-format off\ndefine V\nv\nendef\n"
        "# bake-format on\n"
    ),
    "header": "# Build all\nall:\n\t@echo all\n",
    "header_blank_line": "# Build all\n\nall:\n\t@echo all\n",
    "header_then_assignment": "# Build all\n\nCC = cc\nall:\n\t@echo $(CC)\n",
    "assignment_blank_line": "CC = cc\n\nall:\n\t@echo $(CC)\n",
    "region_before_rule": (
        "# bake-format off\nX=1\n# bake-format on\nall:\n\t@echo $(X)\n"
    ),
    "whitespace_line": "CC = cc\n\t\nall:\n\t@echo $(CC)\n",
}

# The first run puts the declaration right below a line that is neither blank
# nor a header comment, or on the first line: the next run added a blank line
# above it.
BELOW_A_LINE = (
    "nested_markers",
    "assignment",
    "section_comment",
    "include",
    "rule_first",
    "region_after_rule",
)
# The first run puts the declaration after the header comments or after a
# blank line: with blank lines normalized, the next run left it alone.
AFTER_A_BREAK = (
    "header",
    "header_blank_line",
    "header_then_assignment",
    "assignment_blank_line",
    "region_before_rule",
    "whitespace_line",
)

# The first run, which this change leaves as it was.
FIRST_RUN = {
    "after_header": {
        "nested_markers": (
            "# bake-format off\nX=1\n# bake-format off\nY=2\n# bake-format on\n"
            "Z = 3\n# bake-format on\n.PHONY: all\n\nall:\n\t@echo $(X)$(Y)$(Z)\n"
        ),
        "assignment": "CC = cc\n.PHONY: all\n\nall:\n\t@echo $(CC)\n",
        "section_comment": "CC = cc\n# Targets\n.PHONY: all\n\nall:\n\t@echo $(CC)\n",
        "include": "-include config.mk\n.PHONY: all\n\nall:\n\t@echo all\n",
        "rule_first": ".PHONY: all\n\nall:\n\t@echo all\n",
        "region_after_rule": (
            "X = 1\n.PHONY: all\n\nall:\n\t@echo $(X)\n# bake-format off\n"
            "define V\nv\nendef\n# bake-format on\n"
        ),
        "header": "# Build all\n.PHONY: all\n\nall:\n\t@echo all\n",
        "header_blank_line": "# Build all\n.PHONY: all\n\nall:\n\t@echo all\n",
        "header_then_assignment": (
            "# Build all\n.PHONY: all\n\nCC = cc\nall:\n\t@echo $(CC)\n"
        ),
        "assignment_blank_line": "CC = cc\n\n.PHONY: all\n\nall:\n\t@echo $(CC)\n",
        "region_before_rule": (
            "# bake-format off\nX=1\n# bake-format on\n.PHONY: all\n\nall:\n"
            "\t@echo $(X)\n"
        ),
        "whitespace_line": "CC = cc\n\n.PHONY: all\n\nall:\n\t@echo $(CC)\n",
    },
    "top": {
        "nested_markers": (
            ".PHONY: all\n\n# bake-format off\nX=1\n# bake-format off\nY=2\n"
            "# bake-format on\nZ = 3\n# bake-format on\nall:\n\t@echo $(X)$(Y)$(Z)\n"
        ),
        "assignment": ".PHONY: all\n\nCC = cc\nall:\n\t@echo $(CC)\n",
        "section_comment": ".PHONY: all\n\nCC = cc\n# Targets\nall:\n\t@echo $(CC)\n",
        "include": ".PHONY: all\n\n-include config.mk\nall:\n\t@echo all\n",
        "rule_first": ".PHONY: all\n\nall:\n\t@echo all\n",
        "region_after_rule": (
            ".PHONY: all\n\nX = 1\nall:\n\t@echo $(X)\n# bake-format off\n"
            "define V\nv\nendef\n# bake-format on\n"
        ),
        "header": ".PHONY: all\n\n# Build all\nall:\n\t@echo all\n",
        "header_blank_line": ".PHONY: all\n\n# Build all\n\nall:\n\t@echo all\n",
        "header_then_assignment": (
            ".PHONY: all\n\n# Build all\n\nCC = cc\nall:\n\t@echo $(CC)\n"
        ),
        "assignment_blank_line": ".PHONY: all\n\nCC = cc\n\nall:\n\t@echo $(CC)\n",
        "region_before_rule": (
            ".PHONY: all\n\n# bake-format off\nX=1\n# bake-format on\nall:\n"
            "\t@echo $(X)\n"
        ),
        "whitespace_line": ".PHONY: all\n\nCC = cc\n\nall:\n\t@echo $(CC)\n",
    },
}
# Without normalize_empty_lines the first run is the same, except that the
# header's own blank line stays after the inserted one.
FIRST_RUN["after_header_blank_lines_kept"] = {
    **FIRST_RUN["after_header"],
    "header_blank_line": "# Build all\n.PHONY: all\n\n\nall:\n\t@echo all\n",
    "header_then_assignment": (
        "# Build all\n.PHONY: all\n\n\nCC = cc\nall:\n\t@echo $(CC)\n"
    ),
}
FIRST_RUN["top_blank_lines_kept"] = FIRST_RUN["top"]

# Formatted files whose declaration is already where the insertion puts it.
# 'top_of_file' is the shape of the repository's own Makefile and of
# tests/verilator/Makefile; with phony_at_top a run put a blank line above it.
IN_PLACE = {
    "top_of_file": ".PHONY: all\n\nall:\n\t@echo all\n",
    "after_assignment": "CC = cc\n.PHONY: all\n\nall:\n\t@echo $(CC)\n",
    "after_section_comment": (
        "CC = cc\n# Targets\n.PHONY: all\n\nall:\n\t@echo $(CC)\n"
    ),
    "after_stray_marker": (
        "Z = 3\n# bake-format on\n.PHONY: all\n\nall:\n\t@echo $(Z)\n"
    ),
}
# With phony_at_top off, only a declaration on the first line is in place.
IN_PLACE_CASES = [
    (case, config_name)
    for case in sorted(IN_PLACE)
    for config_name in ("after_header", "after_header_blank_lines_kept")
] + [("top_of_file", "top_blank_lines_kept")]

# Declarations that are not where the insertion puts them; they move.
MOVED = {
    "at_the_end": "CC = cc\n\nall:\n\t@echo $(CC)\n\n.PHONY: all\n",
    "two_declarations": (
        "CC = cc\n.PHONY: all\n\nall:\n\t@echo all\n.PHONY: clean\n"
        "clean:\n\trm -f *.o\n"
    ),
    # A comment that ends with a backslash continues on the next line (GNU
    # make manual 3.1, lines 730-733), so the declaration below it is part of
    # the comment. It goes after a blank line, as before, where make reads it.
    "after_continued_comment": (
        "CC = cc\n\n# note \\\n.PHONY: all\n\nall:\n\t@echo $(CC)\n"
    ),
}
# The phony targets make reads in each input and in every formatted output.
MOVED_DECLARED = {
    "at_the_end": (["all"], ["all"]),
    "two_declarations": (["all", "clean"], ["all", "clean"]),
    "after_continued_comment": ([], ["all"]),
}
MOVED_FIRST_RUN = {
    "after_header": {
        "at_the_end": "CC = cc\n\n.PHONY: all\n\nall:\n\t@echo $(CC)\n",
        "two_declarations": (
            "CC = cc\n\n.PHONY: all clean\n\nall:\n\t@echo all\nclean:\n"
            "\trm -f *.o\n"
        ),
        "after_continued_comment": (
            "CC = cc\n\n# note \\\n\n.PHONY: all\n\nall:\n\t@echo $(CC)\n"
        ),
    },
    "top": {
        "at_the_end": ".PHONY: all\n\nCC = cc\n\nall:\n\t@echo $(CC)\n",
        "two_declarations": (
            ".PHONY: all clean\n\nCC = cc\n\nall:\n\t@echo all\nclean:\n"
            "\trm -f *.o\n"
        ),
        "after_continued_comment": (
            ".PHONY: all\n\nCC = cc\n\n# note \\\n\nall:\n\t@echo $(CC)\n"
        ),
    },
}
MOVED_FIRST_RUN["after_header_blank_lines_kept"] = MOVED_FIRST_RUN["after_header"]
MOVED_FIRST_RUN["top_blank_lines_kept"] = MOVED_FIRST_RUN["top"]

# A header comment that ends with a backslash continues on the next line (GNU
# make manual 3.1, lines 730-733), so make reads the declaration right below it
# as part of the comment. Inserting the declaration again puts it back there,
# and with normalize_empty_lines off every run added a blank line below it.
CONTINUED_HEADER = {
    "blank_line_below": "# Usage: make all \\\n\nall:\n\t@echo all\n",
    "declaration_below": "# Usage: make all \\\n.PHONY: all\n\nall:\n\t@echo all\n",
}

PHONY_TARGETS_INPUT = Path(__file__).parent / "fixtures" / "phony_targets" / "input.mk"
PHONY_TARGETS_HEADER = "# Test phony target formatting with scattered declarations\n"
PHONY_TARGETS_DECLARATION = ".PHONY: all clean test install help\n"
PHONY_TARGETS_RULES = (
    'all: $(TARGET)\n\t@echo "Build complete"\n\nclean:\n\trm -f *.o $(TARGET)\n'
    "\ntest: $(TARGET)\n\t./run_tests.sh\n\ninstall: $(TARGET)\n"
    "\tcp $(TARGET) /usr/local/bin/\n\nhelp:\n"
    '\t@echo "Available targets: all, clean, test, install, help"\n'
)


def _format(config_name, text):
    config = Config(formatter=FormatterConfig(**CONFIGS[config_name]))
    return MakefileFormatter(config).format(text).content


def _phony_targets_expected(config_name):
    if config_name.startswith("top"):
        head = PHONY_TARGETS_DECLARATION + "\n" + PHONY_TARGETS_HEADER
    else:
        head = PHONY_TARGETS_HEADER + PHONY_TARGETS_DECLARATION + "\n"
    return head + PHONY_TARGETS_RULES


@pytest.fixture(scope="module", params=["make", "gmake"])
def gnu_make(request):
    """Return (make, true) paths for each GNU make found, or skip."""
    if os.name == "nt":
        pytest.skip("GNU make checks do not run on Windows")
    make = shutil.which(request.param)
    true = shutil.which("true")
    if make is None or true is None:
        pytest.skip(f"{request.param} or true is not installed")
    try:
        version = subprocess.run(
            [make, "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            env=_MAKE_ENV,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        pytest.skip(f"{request.param} --version failed")
    if "GNU Make" not in version:
        pytest.skip(f"{request.param} is not GNU make")
    return make, true


def _make_reads(gnu_make, tmp_path, name, text):
    """Return the .PHONY targets, the variables and the dry run of 'all'.

    The database goal lives in a second makefile, so nothing is appended
    after the text's last line.
    """
    make, true = gnu_make
    (tmp_path / name).write_text(text, encoding="utf-8")
    (tmp_path / "goal.mk").write_text("__g: ;\n", encoding="utf-8")
    database = subprocess.run(
        [make, "-r", "-R", "-p", "-q", "-f", name, "-f", "goal.mk"]
        + [f"SHELL={true}", "__g"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        env=_MAKE_ENV,
    ).stdout.splitlines()
    phony = []
    variables = []
    origin = re.compile(r"^# makefile \(from [`']" + re.escape(name) + "'")
    for index, line in enumerate(database):
        match = re.match(r"^\.PHONY:\s*(.*)$", line)
        if match:
            phony = sorted(match.group(1).split())
        if origin.match(line) and index + 1 < len(database):
            variables.append(database[index + 1])
    dry_run = subprocess.run(
        [make, "-r", "-R", "-n", "-f", name, f"SHELL={true}", "all"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        env=_MAKE_ENV,
    )
    return phony, sorted(variables), dry_run.returncode, dry_run.stdout


class TestFirstRun:
    """The first run places the declaration as before."""

    @pytest.mark.parametrize("config_name", sorted(CONFIGS))
    @pytest.mark.parametrize("layout", BELOW_A_LINE + AFTER_A_BREAK)
    def test_first_run_is_unchanged(self, layout, config_name):
        expected = FIRST_RUN[config_name][layout]
        assert _format(config_name, LAYOUTS[layout]) == expected

    @pytest.mark.parametrize("config_name", sorted(CONFIGS))
    @pytest.mark.parametrize("case", sorted(MOVED))
    def test_declaration_elsewhere_moves_as_before(self, case, config_name):
        expected = MOVED_FIRST_RUN[config_name][case]
        assert _format(config_name, MOVED[case]) == expected

    @pytest.mark.parametrize("config_name", sorted(CONFIGS))
    def test_phony_targets_fixture_is_grouped_as_before(self, config_name):
        text = PHONY_TARGETS_INPUT.read_text(encoding="utf-8")
        assert _format(config_name, text) == _phony_targets_expected(config_name)


class TestSecondRun:
    """Formatting the formatted file again changes nothing."""

    @pytest.mark.parametrize("layout", BELOW_A_LINE)
    def test_second_run_changes_nothing(self, layout):
        """The reproducer is 'nested_markers': the second run put a blank
        line between the stray '# bake-format on' and the declaration."""
        once = _format("after_header", LAYOUTS[layout])
        assert _format("after_header", once) == once

    @pytest.mark.parametrize("config_name", BLANK_LINES_KEPT)
    @pytest.mark.parametrize("layout", BELOW_A_LINE + AFTER_A_BREAK)
    def test_blank_lines_do_not_pile_up(self, layout, config_name):
        once = _format(config_name, LAYOUTS[layout])
        twice = _format(config_name, once)
        assert twice == once
        assert _format(config_name, twice) == once

    @pytest.mark.parametrize("config_name", BLANK_LINES_KEPT)
    @pytest.mark.parametrize("case", sorted(MOVED))
    def test_moved_declaration_stays(self, case, config_name):
        once = _format(config_name, MOVED[case])
        assert _format(config_name, once) == once

    @pytest.mark.parametrize("config_name", BLANK_LINES_KEPT)
    def test_phony_targets_fixture_keeps_its_blank_lines(self, config_name):
        text = PHONY_TARGETS_INPUT.read_text(encoding="utf-8")
        once = _format(config_name, text)
        assert _format(config_name, once) == once

    @pytest.mark.parametrize("case", sorted(CONTINUED_HEADER))
    def test_continued_header_comment_gains_no_blank_line(self, case):
        once = _format("after_header_blank_lines_kept", CONTINUED_HEADER[case])
        twice = _format("after_header_blank_lines_kept", once)
        assert twice == once
        assert _format("after_header_blank_lines_kept", twice) == once

    @pytest.mark.parametrize(
        ("layout", "config_name"),
        [(layout, "after_header") for layout in AFTER_A_BREAK]
        + [(layout, "top") for layout in BELOW_A_LINE + AFTER_A_BREAK],
    )
    def test_stable_layouts_stay_stable(self, layout, config_name):
        once = _format(config_name, LAYOUTS[layout])
        assert _format(config_name, once) == once

    @pytest.mark.parametrize("config_name", NORMALIZED)
    def test_stable_declarations_stay_stable(self, config_name):
        texts = [*MOVED.values(), PHONY_TARGETS_INPUT.read_text(encoding="utf-8")]
        for text in texts:
            once = _format(config_name, text)
            assert _format(config_name, once) == once

    @pytest.mark.parametrize("config_name", sorted(CONFIGS))
    def test_define_body_gains_no_blank_line_on_later_runs(self, config_name):
        """A blank line in a define body is part of the value (GNU make
        manual 6.8, lines 4795-4799 and 4806-4809): no run adds one there."""
        text = "define HELP_TEXT :=\n\nRun make help\nendef\n\nhelp:\n"
        text += "\t$(info $(HELP_TEXT))\n"
        once = _format(config_name, text)
        for output in (once, _format(config_name, once)):
            lines = output.split("\n")
            start, end = lines.index("define HELP_TEXT :=") + 1, lines.index("endef")
            # With phony_at_top the first run still inserts the declaration
            # into the body (pre-existing, S9); this test guards blank lines only.
            body = [line for line in lines[start:end] if not line.startswith(".PHONY")]
            assert body == ["", "Run make help"]


class TestDeclarationInPlace:
    """A declaration that is already in place is left there."""

    @pytest.mark.parametrize(("case", "config_name"), IN_PLACE_CASES)
    def test_declaration_in_place_is_unchanged(self, case, config_name):
        text = IN_PLACE[case]
        assert _format(config_name, text) == text

    @pytest.mark.parametrize("config_name", ["after_header", *BLANK_LINES_KEPT])
    def test_missing_target_is_added_in_place(self, config_name):
        text = ".PHONY: all\n\nall:\n\t@echo all\nclean:\n\trm -f *.o\n"
        expected = ".PHONY: all clean\n\nall:\n\t@echo all\nclean:\n\trm -f *.o\n"
        once = _format(config_name, text)
        assert once == expected
        assert _format(config_name, once) == once


class TestMakeReadsTheSame:
    """make reads the input and every run the same, apart from the
    declaration that the first run adds."""

    @pytest.mark.parametrize("config_name", sorted(CONFIGS))
    @pytest.mark.parametrize("layout", BELOW_A_LINE + AFTER_A_BREAK)
    def test_runs_keep_what_make_reads(self, gnu_make, tmp_path, layout, config_name):
        text = LAYOUTS[layout]
        once = _format(config_name, text)
        twice = _format(config_name, once)
        phony, variables, status, dry_run = _make_reads(
            gnu_make, tmp_path, "input.mk", text
        )
        assert (phony, status) == ([], 0)
        expected = (["all"], variables, status, dry_run)
        assert _make_reads(gnu_make, tmp_path, "once.mk", once) == expected
        assert _make_reads(gnu_make, tmp_path, "twice.mk", twice) == expected

    @pytest.mark.parametrize(("case", "config_name"), IN_PLACE_CASES)
    def test_declaration_in_place_reads_the_same(
        self, gnu_make, tmp_path, case, config_name
    ):
        text = IN_PLACE[case]
        expected = _make_reads(gnu_make, tmp_path, "input.mk", text)
        assert expected[0] == ["all"]
        output = _format(config_name, text)
        assert _make_reads(gnu_make, tmp_path, "output.mk", output) == expected

    @pytest.mark.parametrize("config_name", sorted(CONFIGS))
    @pytest.mark.parametrize("case", sorted(MOVED))
    def test_moved_declaration_is_read(self, gnu_make, tmp_path, case, config_name):
        """The outputs declare what the input declared, and the declaration
        that a continued comment hid becomes one; the rest reads the same."""
        text = MOVED[case]
        declared_in_input, declared = MOVED_DECLARED[case]
        phony, variables, status, dry_run = _make_reads(
            gnu_make, tmp_path, "input.mk", text
        )
        assert phony == declared_in_input
        once = _format(config_name, text)
        twice = _format(config_name, once)
        expected = (declared, variables, status, dry_run)
        assert _make_reads(gnu_make, tmp_path, "once.mk", once) == expected
        assert _make_reads(gnu_make, tmp_path, "twice.mk", twice) == expected

    @pytest.mark.parametrize("case", sorted(CONTINUED_HEADER))
    def test_continued_header_comment_reads_the_same(self, gnu_make, tmp_path, case):
        """make reads the declaration below the comment as part of it, in the
        input and in every run, so no run declares anything."""
        text = CONTINUED_HEADER[case]
        once = _format("after_header_blank_lines_kept", text)
        twice = _format("after_header_blank_lines_kept", once)
        expected = _make_reads(gnu_make, tmp_path, "input.mk", text)
        assert (expected[0], expected[2]) == ([], 0)
        assert _make_reads(gnu_make, tmp_path, "once.mk", once) == expected
        assert _make_reads(gnu_make, tmp_path, "twice.mk", twice) == expected
