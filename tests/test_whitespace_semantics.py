"""Tests for whitespace that GNU make reads as data.

Whitespace cleanup keeps (line numbers refer to the GNU make 4.4.1 manual):
- a recipe line of only whitespace that gives a rule an empty recipe: "A blank
  line that begins with a tab is not blank: it's an empty recipe" (lines
  2890-2891), and an empty recipe keeps implicit rules away (4040-4055);
- define bodies, which are variable values (4785-4814);
- the trailing whitespace of a variable value (4273-4288).

A line counts wherever make may read it so: in any branch of the conditionals
above it, and with make 3.81 or 4.x.

TestAgainstGnuMake checks with each GNU make on PATH ('make' and 'gmake') that
formatting keeps what make does.
"""

import os
import re
import shutil
import subprocess

import pytest

from mbake.config import Config, FormatterConfig
from mbake.core.formatter import MakefileFormatter
from mbake.core.rules import TargetSpacingRule, WhitespaceRule

BS = "\\"  # one backslash, to keep continuation lines readable
IMPLICIT = "%.x: ; @echo implicit $@"
IMPLICIT_O = "%.o: ; @echo implicit $@"

# PhonyRule configurations that move or split '.PHONY' lines
AUTO_GROUP_TOP = {
    "auto_insert_phony_declarations": True,
    "group_phony_declarations": True,
    "phony_at_top": False,
}
AUTO_GROUP_AFTER = {**AUTO_GROUP_TOP, "phony_at_top": True}
AUTO_UNGROUP = {
    "auto_insert_phony_declarations": True,
    "group_phony_declarations": False,
}

# Tab-led assignments that make 3.81 or 4.x reads as makefile syntax although
# a rule context may reach them (GNU 1217-1219, 2881-2884, 5345-5358)
POSSIBLY_SYNTAX = {
    "conditionals-in-a-row": [
        "ifeq ($(OS),Windows_NT)",
        "\tEXE = .exe ",
        "endif",
        "ifeq ($(DEBUG),)",
        "\tCFLAGS += -g ",
        "endif",
    ],
    "nested-conditionals": [
        "ifeq ($(A),)",
        "\tifeq ($(B),)",
        "\t\tX = 1",
        "\tendif",
        "\tY = a ",
        "endif",
    ],
    "verilator-layout": [
        "ifneq ($(words $(CURDIR)),1)",
        "\t$(error Unsupported: GNU Make cannot build in directories with spaces)",
        "endif",
        "",
        "ifeq ($(VERILATOR_ROOT),)",
        "\tVERILATOR = verilator ",
        "else",
        "\texport VERILATOR_ROOT",
        "\tVERILATOR = $(VERILATOR_ROOT)/bin/verilator ",
        "endif",
    ],
    "after-override": ["all:", "\t@:", "override O = 1", "\tV = a "],
    "after-define": ["all:", "\t@:", "define D", "endef", "\tV = a "],
    "after-include": ["all:", "\t@:", "-include $(DEPS)", "\tV = a "],
    "rule-in-one-branch": ["X = 1", "ifdef A", "foo:", "endif", "\tV = a "],
}

# Makefiles in which the TAB-only line after 'endif' is the empty recipe of
# foo.x with A, and a recipe line of a '.PHONY' line that no rule context
# reaches without A (one that PhonyRule puts there or one of the input)
UNREACHED_PHONY_SHAPES = {
    "inserted-phony": [
        "X = 1",
        "ifdef A",
        "foo.x:",
        "endif",
        "\t",
        IMPLICIT,
        "all: foo.x",
    ],
    "phony-at-top": [".PHONY: all", "ifdef A", "foo.x:", "endif", "\t", IMPLICIT]
    + ["all: foo.x"],
}

AUTOMAKE_IF = ["X ?= c ", "\t ", "if COND", "bar.x:", "\t# shell comment", "endif"]
AUTOMAKE_IF += ["\t"]

# Makefiles in which make may read the TAB-only line as a recipe line of the
# '.PHONY' line that PhonyRule moves or splits, in one branch of a conditional
# only, and the goal to check (GNU 2881-2891, 5345-5358)
BRANCH_SHAPES = {
    "rule-in-branch": (
        [IMPLICIT, "foo.x:", ".PHONY: clean", "ifdef A", "clean:", "\t@echo c"]
        + ["endif", "\t", "all: foo.x"],
        "foo.x",
    ),
    "rule-before-else": (
        [IMPLICIT, "foo.x:", ".PHONY: clean", "ifdef A", "clean:", "\t@echo c"]
        + ["else", "endif", "\t", "all: foo.x"],
        "foo.x",
    ),
    "rule-after-else": (
        [IMPLICIT, "foo.x:", ".PHONY: clean", "ifdef A", "else", "clean:"]
        + ["\t@echo c", "endif", "\t", "all: foo.x"],
        "foo.x",
    ),
    "phony-in-branch": (
        ["t1: ; @:", "t1:", "ifeq (a,a)", ".PHONY: t1", "endif", "\t", "all: t1"],
        "t1",
    ),
    "grouped-split": (
        [IMPLICIT, "foo.x:", ".PHONY: a b", "ifdef A", "a: ; @echo a", "endif"]
        + ["\t", "b: ; @echo b", "all: foo.x"],
        "foo.x",
    ),
}

# Makefiles in which make reads the TAB-only line after 'endif' as the empty
# recipe of foo.x where it reads the branch, and as a recipe line of the
# '.PHONY' line where it skips it, so the '.PHONY' line can neither move nor
# leave the TAB-only line behind (GNU 2881-2891, 4040-4055, 5345-5358)
SHARED_LINE_SHAPES = {
    "ifeq": [IMPLICIT, ".PHONY: t1", "ifeq (a,a)", "foo.x:", "endif", "\t"]
    + ["t1: ; @:"],
    "ifeq-two-targets": [IMPLICIT, ".PHONY: t1 t2", "ifeq (a,a)", "foo.x:"]
    + ["endif", "\t", "t1: ; @:", "t2: ; @:"],
    "ifdef": [IMPLICIT, ".PHONY: t1", "ifdef X", "foo.x:", "endif", "\t"]
    + ["t1: ; @:"],
}

# Makefiles with a line of just '>' after 'endif', and for each the
# command-line settings with which make skips and reads foo.x. Where the prefix
# is '>' (GNU 5158-5169), the line is the empty recipe of foo.x where make
# reads foo.x, and a recipe line of the '.PHONY' line where it skips it (GNU
# 2881-2891, 4040-4055, 5345-5358). The prefix that make uses there depends on
# a branch or on a value that make computes, so scan_makefile's one model
# reads the line as makefile syntax. Whitespace cleanup leaves such a line as
# it is, and so must PhonyRule when it moves or splits the '.PHONY' line. GNU
# make 4.x only: make 3.81 has no .RECIPEPREFIX.
PREFIX_ONLY_SHAPES = {
    "prefix-reset-in-a-branch": (
        [".RECIPEPREFIX = >", IMPLICIT, "all:", "> @echo all", ".PHONY: all"]
        + ["ifeq ($(OS),Windows_NT)", ".RECIPEPREFIX =", "endif"]
        + ["ifdef WITH_FOO", "foo.x:", "endif", ">"],
        [[], ["WITH_FOO=1"]],
    ),
    "prefix-set-in-a-branch": (
        [IMPLICIT, ".RECIPEPREFIX = >", "baz:", ".PHONY: t1", "ifdef Z"]
        + [".RECIPEPREFIX = @", "endif", "ifdef Y", "foo.x:", "endif", ">"]
        + ["t1: ; @:"],
        [[], ["Y=1"]],
    ),
    "computed-prefix": (
        [IMPLICIT, ".RECIPEPREFIX := $(P)", "baz:", ".PHONY: t1", "ifdef Y"]
        + ["foo.x:", "endif", ">", "t1: ; @:"],
        [["P=>"], ["P=>", "Y=1"]],
    ),
}

# PhonyRule configurations that would move or split the '.PHONY' lines of
# SHARED_LINE_SHAPES, with trailing whitespace removed or kept
PHONY_MOVES = {
    f"{name}-{whitespace}": {**config, "remove_trailing_whitespace": remove}
    for name, config in (
        ("group-top", AUTO_GROUP_TOP),
        ("group-after", AUTO_GROUP_AFTER),
        ("ungroup", AUTO_UNGROUP),
    )
    for whitespace, remove in (("strip", True), ("keep", False))
}

# Makefiles in which a '.PHONY:' line that PhonyRule would move owns a line of
# just the recipe prefix '>' (GNU 2878-2891, 5158-5169), followed by a TAB-led
# line that make reads as makefile syntax, because the prefix is not a TAB
PREFIX_LINE_OF_PHONY = {
    "assignment": [IMPLICIT, ".RECIPEPREFIX = >", "foo.x:", ".PHONY: t1 t2", ">"]
    + ["\tV = 1", "t2: ; @:"],
    "include": [IMPLICIT, ".RECIPEPREFIX = >", "foo.x:", ".PHONY: t1 t2", ">"]
    + ["\t-include $(NONE)", "t2: ; @:"],
    "simple-prefix": [IMPLICIT, ".RECIPEPREFIX := >", "foo.x:", ".PHONY: t1 t2"]
    + [">", "\tV = 1", "t2: ; @:"],
}

# Makefiles in which removing the whitespace after a final backslash changes
# how make reads the TAB-only line at the end, and the goal to check: the
# comment or the value goes on over the next line (GNU 762-769)
BACKSLASH_CLEANUP_SHAPES = {
    "comment-over-assignment": (
        [IMPLICIT, "foo.x:", "# note " + BS + " ", "X = 1", "\t"],
        "foo.x",
    ),
    "override-over-export": (
        [IMPLICIT, "t3.x: ; @echo t3", "ifndef X", "t5.x:"]
        + ["override F ?= a " + BS + " ", "export lower := -O2", "endif", "\t"],
        "t5.x",
    ),
}

# Makefiles in which whitespace cleanup removes the whitespace after a final
# backslash above the TAB-only line, and for each the goal to check and the
# configuration. The line above then goes on over the next one (GNU 762-769):
# 'X ?= 2' no longer sets the X that 'ifndef X' tests (GNU 5345-5358), and
# 't2.x:' no longer starts the rule that the TAB-only line belongs to (make
# 3.81 keeps the rule context of t5.x at 'override'). The TAB-only line must
# not become an empty recipe of the goal (GNU 2890-2891, 4040-4055). With
# indentation, ConditionalRule re-indents the line before WhitespaceRule runs.
CLEANUP_ABOVE_SHAPES = {
    "value-over-assignment": (
        [IMPLICIT, "V = src " + BS + " ", "X ?= 2", "all.x:", "ifndef X", "\t"]
        + ["endif"],
        "all.x",
        {},
    ),
    "indented-override-over-rule": (
        [IMPLICIT, "t5.x:", "ifdef X", "override X = a b " + BS + " ", "t2.x:"]
        + ["\t", "endif"],
        "t5.x",
        {"indent_nested_conditionals": True, "tab_width": 2},
    ),
}

# A makefile whose branch, which make skips without X, holds a define line
# that ends in a backslash and a space. Formatted with trailing whitespace kept
# and conditional indentation, it must still read the same without X: the
# re-indented line must not leave an 'endef' of its own (GNU 762-769,
# 4795-4799, 5345-5358).
KEEP_INDENT_DEFINE = [IMPLICIT, "t5.x:", "ifdef X", "override define D " + BS + " "]
KEEP_INDENT_DEFINE += ["endef", "t2.x:", "\t", "endif"]
KEEP_INDENT = {
    "remove_trailing_whitespace": False,
    "indent_nested_conditionals": True,
    "tab_width": 2,
}


def _formatter(**config):
    return MakefileFormatter(Config(formatter=FormatterConfig(**config)))


def _formatted_lines(lines, **config):
    return _formatter(**config).format_lines(lines)[0]


def _whitespace(lines, **context):
    """Run WhitespaceRule alone with the default settings."""
    return WhitespaceRule().format(list(lines), {}, **context).lines


class TestEmptyRecipes:
    """A recipe of only whitespace is an empty recipe (GNU 2890-2891, 4040-4055)."""

    def test_tab_only_line_is_kept_as_empty_recipe(self):
        lines = [IMPLICIT, "foo.x:", "\t"]
        assert _formatted_lines(lines) == [*lines, ""]

    def test_whitespace_only_recipe_line_becomes_one_tab(self):
        """make reads '\\t   ' as an empty recipe too (GNU 4044-4046)."""
        lines = ["foo:", "\t   ", "", "", "bar:"]
        assert _formatted_lines(lines) == ["foo:", "\t", "", "bar:", ""]

    def test_only_the_first_whitespace_line_of_an_empty_recipe_is_kept(self):
        """One line makes the recipe empty; the others are empty commands."""
        assert _formatted_lines(["foo:", "\t", "\t", "bar:"]) == [
            "foo:",
            "\t",
            "",
            "bar:",
            "",
        ]

    def test_tab_only_lines_after_commands_are_still_removed(self):
        """Whitespace-only lines among commands are empty commands, so blank
        lines may replace them (GNU 2884-2886)."""
        lines = ["foo:", "\t@echo a", "\t", "\t", "bar:", "\t@echo b"]
        assert _formatted_lines(lines) == [
            "foo:",
            "\t@echo a",
            "",
            "bar:",
            "\t@echo b",
            "",
        ]

    @pytest.mark.parametrize(
        "lines",
        [
            ["foo.x:", "ifdef X", "\t@echo x", "endif", "\t"],
            ["foo.x:", "\t", "ifdef X", "\t@echo x", "endif"],
            ["foo.x:", "ifdef X", "\t@echo x", "else", "\t", "endif"],
        ],
    )
    def test_tab_only_line_kept_when_conditional_splits_recipe(self, lines):
        """Without X the only recipe line is the tab-only one (GNU 5345-5358);
        make 3.81 and 4.4.1 then report foo.x up to date."""
        assert _formatted_lines(lines) == [*lines, ""]

    @pytest.mark.parametrize(
        "config", [{}, {"remove_trailing_whitespace": False}], ids=["default", "keep"]
    )
    def test_blank_line_before_empty_recipe_line(self, config):
        """Blank lines among recipe lines are ignored (GNU 2884-2886), so the
        tab-only line after one is still the empty recipe of foo."""
        lines = ["foo:", "", "\t", "bar:"]
        assert _formatted_lines(lines, **config) == [*lines, ""]

    def test_tab_only_lines_outside_rule_context_removed(self):
        """Outside a rule context a tab-only line is blank (GNU 1217-1219)."""
        lines = ["\t", "X = 1", "\t", "all:", "\t@echo"]
        assert _formatted_lines(lines) == ["", "X = 1", "", "all:", "\t@echo", ""]

    def test_tab_only_line_after_target_specific_variable_removed(self):
        """A target-specific variable starts no rule context (GNU
        4938-4951)."""
        lines = ["foo: X = 1", "\t", "foo:", "\t@echo $(X)"]
        expected = ["foo: X = 1", "", "foo:", "\t@echo $(X)", ""]
        assert _formatted_lines(lines) == expected

    def test_recipeprefix_empty_recipe(self):
        """With '.RECIPEPREFIX = >' a line of just '>' is the empty recipe
        and a tab-only line is blank (GNU 5158-5169)."""
        lines = [".RECIPEPREFIX = >", "foo:", ">", "bar:", "\t", "baz:"]
        expected = [".RECIPEPREFIX = >", "foo:", ">", "bar:", "", "baz:", ""]
        assert _formatted_lines(lines) == expected

    def test_format_string_api_keeps_empty_recipe(self):
        result = _formatter().format("foo.x:\n\t\n")
        assert result.content == "foo.x:\n\t\n"
        assert not result.changed

    def test_recipeprefix_set_in_a_branch(self):
        """Where make skips the branch, the prefix stays a TAB and the
        tab-only line is the empty recipe of foo.x (GNU 5158-5169, 5345-5358;
        make 4.4.1)."""
        lines = ["ifdef NOPE", ".RECIPEPREFIX = >", "endif", IMPLICIT, "foo.x:"]
        lines += ["\t"]
        assert _whitespace(lines) == lines

    def test_line_kept_for_one_reading_becomes_its_first_character(self):
        """Where make skips the branch the line is the empty recipe of foo.x,
        and one TAB is as well; where make reads it, both lines are blank
        (GNU 2884-2891, 5158-5169; make 3.81 and 4.4.1)."""
        lines = ["ifdef NOPE", ".RECIPEPREFIX = >", "endif", IMPLICIT, "foo.x:"]
        assert _whitespace([*lines, "\t   "]) == [*lines, "\t"]

    def test_line_that_only_phony_may_own_is_not_kept(self):
        """make 3.81 does not know .RECIPEPREFIX and reads the line as a
        recipe line of .PHONY, which it never runs (GNU 2234-2240); make 4.x
        reads it as a blank line."""
        lines = [".RECIPEPREFIX += >", ".PHONY: x"]
        assert _whitespace([*lines, "\t "]) == [*lines, ""]

    def test_include_that_names_no_file(self):
        """make 3.81 skips an include directive that names no file, so the
        rule context goes on to the tab-only line."""
        lines = [IMPLICIT, "foo.x:", "-include", "\t"]
        assert _whitespace(lines) == lines

    @pytest.mark.parametrize("name", sorted(BACKSLASH_CLEANUP_SHAPES))
    def test_line_that_is_an_empty_recipe_only_after_the_cleanup(self, name):
        """make reads the tab-only line as a blank line: 'X = 1' or 'export'
        ends the rule context (GNU 2881-2884). Only once the whitespace after
        the backslash goes does the line above go on over that line (GNU
        762-769), so the tab-only line is not kept as an empty recipe."""
        lines, _goal = BACKSLASH_CLEANUP_SHAPES[name]
        assert _whitespace(lines)[-1] == ""
        assert "\t" not in _formatted_lines(lines)

    @pytest.mark.parametrize(
        "lines",
        [
            [".PHONY: clean", "\t", "clean:", "\t@echo"],
            ["all:", ".PHONY: all", "", "\t   "],
        ],
    )
    def test_empty_recipe_of_phony_is_removed(self, lines):
        """make never runs the recipe of .PHONY (GNU 1442-1446, 2234-2240),
        so the line goes as before."""
        out = _whitespace(lines)
        assert "\t" not in out and "\t   " not in out


class TestDefineBodies:
    """A define body is the value of a variable (GNU 4785-4814)."""

    def test_define_bodies_keep_blank_lines_and_trailing_whitespace(self):
        """The manual's 'define newline' needs its two blank lines (GNU
        4806-4814)."""
        lines = ["define newline", "", "", "endef", "define PAD", "x   ", "endef"]
        lines += ["define T", "$(1):", "\t", "endef"]
        assert _formatted_lines(lines) == [*lines, ""]

    def test_blank_lines_after_endef_are_still_collapsed(self):
        lines = ["define X", "", "", "endef", "", "", "all:"]
        expected = ["define X", "", "", "endef", "", "all:", ""]
        assert _formatted_lines(lines) == expected

    def test_unterminated_body_at_end_of_file_loses_blank_lines(self):
        """make stops at a define that the end of the file cuts off ("missing
        'endef'"), so its trailing blank lines go as for other lines, and a
        second run changes nothing."""
        assert _whitespace(["define X", "x", "", ""]) == ["define X", "x", ""]
        text = "all: ; @echo a\ndefine U\nu\n\n\n\n"
        once = _formatter().format(text).content
        assert once == "all: ; @echo a\ndefine U\nu\n"
        assert _formatter().format(once).content == once

    def test_body_that_make_may_read_is_kept(self):
        """Where make reads '\\tdefine X' as makefile syntax (A undefined), the
        lines after it are the value of X."""
        lines = ["ifdef A", "foo:", "endif", "\tdefine X", "y  ", "", "", "endef"]
        assert _whitespace(lines) == lines

    @pytest.mark.parametrize(
        "config", [{}, {"align_variable_assignments": True}], ids=["default", "align"]
    )
    def test_assignment_rules_leave_bodies_alone(self, config):
        """'X=1' in a body is part of the value of T, not an assignment."""
        lines = ["define T", "X=1", "Y:=a:b", "LONGER_NAME = 2", "  Z  =  2", "endef"]
        lines += ["W=1"]
        out = _formatted_lines(lines, **config)
        assert out[:6] == lines[:6]
        assert out[6] == "W = 1"

    def test_define_and_endef_lines_are_still_cleaned(self):
        """Whitespace after the name and after 'endef' is no part of the value
        (GNU 4795-4799)."""
        assert _whitespace(["define X  ", "x", "endef  "]) == ["define X", "x", "endef"]


class TestValueWhitespace:
    """make keeps the trailing whitespace of a value (GNU 4273-4288)."""

    def test_trailing_whitespace_of_value_is_kept(self):
        lines = ["CC = gcc ", "all:", "\t@echo [$(CC)x]"]
        assert _formatted_lines(lines) == [*lines, ""]

    @pytest.mark.parametrize(
        "line",
        [
            "X = a ",
            "X := a\t",
            "X ::= a ",
            "X += a ",
            "X ?= a ",
            "X != echo a ",
            "override X = a ",
            "export X = a ",
            "foo: X = a ",
            "foo:: X = a  ",
            "%.o: X = a ",
            "foo: override X = a ",
            "foo: X = a;b ",
            "\tX = a ",
        ],
    )
    def test_value_whitespace_kept_for_every_assignment_form(self, line):
        """Every operator and modifier (GNU 4577-4579, 4612-4625, 4942-4944),
        target- and pattern-specific variables (4938-4951, 4994-4999), and a
        TAB-led assignment outside a rule context (1217-1219)."""
        assert _whitespace([line]) == [line]

    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            ("X = a # note  ", "X = a # note"),
            ("X = a   # note", "X = a   # note"),
            ("X =   ", "X ="),
            ("override X =  ", "override X ="),
            ("foo: X =  ", "foo: X ="),
            ("define X  ", "define X"),
            ("ifdef A  ", "ifdef A"),
            ("include a.mk  ", "include a.mk"),
            ("all: dep  ", "all: dep"),
        ],
    )
    def test_whitespace_that_is_no_value_is_still_removed(self, line, expected):
        """Whitespace in a comment (GNU 730-742), an empty value, and lines
        that set no value."""
        assert _whitespace([line]) == [expected]

    def test_last_line_of_continued_value_keeps_whitespace(self):
        """The value ends with the last physical line (GNU 776-781)."""
        lines = ["LIBS = -lm " + BS, "\t-ldl "]
        assert _whitespace(lines) == lines

    def test_whitespace_only_last_line_is_still_removed(self):
        """make condenses it into the space of the backslash/newline (GNU
        776-781), so the value does not change."""
        assert _whitespace(["LIBS = -lm " + BS, "   "]) == ["LIBS = -lm " + BS, ""]

    def test_recipe_lines_are_still_stripped(self):
        """A TAB-led assignment in a rule context is a recipe line (GNU
        2897-2900)."""
        lines = ["all: dep  ", "\techo hi  ", "\tX = 1  "]
        assert _whitespace(lines) == ["all: dep", "\techo hi", "\tX = 1"]

    def test_recipe_line_in_every_branch_is_still_stripped(self):
        """Every branch keeps the rule context (GNU 5315-5333)."""
        lines = ["all:", "ifdef X", "\t@echo x", "endif", "\tV = a "]
        assert _whitespace(lines) == [*lines[:4], "\tV = a"]

    @pytest.mark.parametrize("name", sorted(POSSIBLY_SYNTAX))
    def test_tab_led_assignment_that_make_may_read_as_syntax(self, name):
        """Where a rule context is possible but not certain, make may read the
        line as an assignment, so its value keeps its whitespace; as a recipe
        line the whitespace does not change the command."""
        lines = POSSIBLY_SYNTAX[name]
        assert _whitespace(lines) == lines
        assert _formatted_lines(lines) == [*lines, ""]

    @pytest.mark.parametrize("width", [2, 4])
    def test_conditional_indentation_keeps_value_whitespace(self, width):
        lines = ["ifeq (1,1)", "V = a ", "include x.mk  ", "endif", "X = b "]
        out = _formatted_lines(lines, indent_nested_conditionals=True, tab_width=width)
        indent = " " * width
        assert out == ["ifeq (1,1)", f"{indent}V = a ", f"{indent}include x.mk"] + [
            "endif",
            "X = b ",
            "",
        ]

    def test_alignment_keeps_value_whitespace(self):
        lines = ["CC = gcc ", "CFLAGS = -O2 "]
        assert _formatted_lines(lines, align_variable_assignments=True) == [
            "CC     = gcc ",
            "CFLAGS = -O2 ",
            "",
        ]

    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            ("VPATH = src   # dirs: a:b", "VPATH = src   # dirs: a:b"),
            ("VPATH = a b # x:y", "VPATH = a b # x:y"),
            ("VPATH = a:b  # c", "VPATH = a:b  # c"),
            ("foo: VPATH = a:b   # c", "foo: VPATH = a:b   # c"),
            ("VPATH = src  ", "VPATH = src  "),
            ("VPATH = src   # dirs  ", "VPATH = src   # dirs"),
            ("VPATH=src:lib", "VPATH = src:lib"),
        ],
    )
    def test_vpath_keeps_text_from_end_of_value_through_comment(self, line, expected):
        """The comment holds no directories (GNU 730-742, 1771-1800) and the
        whitespace before it is part of the value (4273-4288)."""
        assert TargetSpacingRule().format([line], {}).lines == [expected]

    def test_kept_trailing_whitespace_with_conditional_indentation(self):
        """With remove_trailing_whitespace off, a re-indented line keeps its
        trailing whitespace only where it is part of a value (GNU 730-742,
        4273-4288)."""
        lines = ["ifeq (1,1)", "  target1: dependency2  ", "V = a  ", "W = b # c  "]
        lines += ["endif"]
        config = {"indent_nested_conditionals": True, "tab_width": 2}
        out = _formatted_lines(lines, remove_trailing_whitespace=False, **config)
        assert out == [
            "ifeq (1,1)",
            "  target1: dependency2",
            "  V = a  ",
            "  W = b # c",
            "endif",
            "",
        ]

    def test_kept_trailing_whitespace_with_alignment(self):
        lines = ["CFLAGS = -Wall   # flags   ", "CC = gcc "]
        config = {"align_variable_assignments": True}
        out = _formatted_lines(lines, remove_trailing_whitespace=False, **config)
        assert out == ["CFLAGS = -Wall   # flags", "CC     = gcc ", ""]

    def test_conditional_indentation_keeps_a_body_line_after_its_backslash(self):
        """The whitespace after the backslash is part of the value of D (GNU
        4795-4799, 762-769)."""
        lines = ["ifdef A", "define D", "x " + BS + " ", "endef", "endif"]
        config = {"indent_nested_conditionals": True, "tab_width": 2}
        assert _formatted_lines(lines, **config)[2].endswith("x " + BS + " ")


class TestIncludeWhitespace:
    """make 4.x ignores whitespace at the end of an include directive (GNU
    848-856), but make 3.81 skips 'include $(NONE)' and keeps the rule
    context there, while 'include $(NONE) ' ends it."""

    @pytest.mark.parametrize(
        "lines",
        [
            ["t2:", "\t", "-include $(EMPTY) ", "\t# rc"],
            ["all:", "sinclude $(A)$(B)\t"],
        ],
    )
    def test_whitespace_that_make_381_reads_is_kept(self, lines):
        assert _whitespace(lines) == lines

    @pytest.mark.parametrize(
        ("lines", "expected"),
        [
            (["X = 1", "-include $(EMPTY) "], ["X = 1", "-include $(EMPTY)"]),
            (["all:", "-include $(EMPTY) # c  "], ["all:", "-include $(EMPTY) # c"]),
            (["all:", "-include $(D).d "], ["all:", "-include $(D).d"]),
            (["all:", "-include $(A) $(B) "], ["all:", "-include $(A) $(B)"]),
        ],
    )
    def test_other_include_whitespace_is_removed(self, lines, expected):
        """Without a rule context, after a comment, or where the file names
        never expand to nothing, both makes read the line the same either
        way."""
        assert _whitespace(lines) == expected


class TestPhonyRuleMoves:
    """PhonyRule moves or splits '.PHONY' lines, which changes the rule that
    the lines after them belong to (GNU 2881-2891)."""

    LINES = [IMPLICIT_O, "prog.o:", ".PHONY: clean", "\t", "clean: ; @echo clean"]

    @pytest.mark.parametrize(
        "config",
        [AUTO_GROUP_TOP, AUTO_GROUP_AFTER, AUTO_UNGROUP],
        ids=["group-top", "group-after", "ungroup"],
    )
    def test_empty_recipe_of_moved_phony_does_not_move(self, config):
        """The tab-only line was the empty recipe of .PHONY. After the move it
        must not become the empty recipe of prog.o, which would keep the
        implicit rule away from prog.o (GNU 4040-4055)."""
        out = _formatted_lines(self.LINES, **config)
        assert "\t" not in out
        assert out[out.index("prog.o:") + 1] != "\t"

    def test_ungroup_split_keeps_no_tab_only_line(self):
        lines = [IMPLICIT_O, "prog.o:", ".PHONY: t1 t2", "\t", "t1:", "\t@echo t1"]
        lines += ["t2: ; @echo t2"]
        out = _formatted_lines(lines, **AUTO_UNGROUP)
        assert "\t" not in out

    def test_inserted_phony_does_not_keep_a_tab_only_line(self):
        """The '.PHONY' line that PhonyRule puts before a conditional would
        get the tab-only line after 'endif' as its recipe, which make never
        runs; the line goes, and a second run changes nothing."""
        text = "R = x\n.PHONY: t1\nX = a\nifdef DEBUG # d: e = 1\n"
        text += "t4: ; @echo t4\nVPATH = src\nendif\n#\n\t\n"
        once = _formatter(**AUTO_UNGROUP).format(text).content
        assert "\n\t\n" not in once
        assert _formatter(**AUTO_UNGROUP).format(once).content == once

    @pytest.mark.parametrize("config", sorted(PHONY_MOVES))
    @pytest.mark.parametrize("name", sorted(SHARED_LINE_SHAPES))
    def test_phony_lines_stay_where_another_rule_may_own_the_line(self, name, config):
        """Moving the '.PHONY' line would make the tab-only line the empty
        recipe of the implicit rule's line before it, and blanking it would
        take the empty recipe from foo.x (GNU 2881-2891, 4040-4055), so the
        '.PHONY' lines stay as they are."""
        lines = SHARED_LINE_SHAPES[name]
        assert _formatted_lines(lines, **PHONY_MOVES[config]) == [*lines, ""]

    @pytest.mark.parametrize("config", sorted(PHONY_MOVES))
    @pytest.mark.parametrize("name", sorted(PREFIX_ONLY_SHAPES))
    def test_line_of_only_a_recipe_prefix_stays(self, name, config):
        """A line of just '>' may be the empty recipe of foo.x, so it is left
        as it is, as whitespace cleanup leaves it (GNU 2890-2891,
        5158-5169)."""
        lines, _settings = PREFIX_ONLY_SHAPES[name]
        out = _formatted_lines(lines, **PHONY_MOVES[config])
        assert out.count(">") == 1
        assert out[out.index(">") - 1] == "endif"

    @pytest.mark.parametrize("config", sorted(PHONY_MOVES))
    @pytest.mark.parametrize("name", sorted(PREFIX_LINE_OF_PHONY))
    def test_phony_line_that_owns_a_prefix_line_stays(self, name, config):
        """The line '>' is the empty recipe of .PHONY. Blanking it would make
        the TAB-led line after it read differently on the next run, and
        keeping it after a moved '.PHONY:' line would give foo.x an empty
        recipe (GNU 2890-2891, 4040-4055), so the '.PHONY:' line stays and a
        second run changes nothing."""
        lines = PREFIX_LINE_OF_PHONY[name]
        text = "\n".join(lines) + "\n"
        once = _formatter(**PHONY_MOVES[config]).format(text).content
        assert once.splitlines()[3:5] == [".PHONY: t1 t2", ">"]
        assert _formatter(**PHONY_MOVES[config]).format(once).content == once

    def test_define_body_gains_no_blank_line(self):
        """A blank line in a define body is part of the value (GNU
        4795-4799). find_phony_insertion_point reads 'define HELP_TEXT :='
        as an assignment, so it may find a line of the body."""
        text = "define HELP_TEXT :=\n\nRun make help\nendef\n\nhelp:\n"
        text += "\t$(info $(HELP_TEXT))\n"
        out = _formatter(**AUTO_GROUP_AFTER).format(text).content.split("\n")
        body = out[out.index("define HELP_TEXT :=") + 1 : out.index("endef")]
        body = [line for line in body if not line.startswith(".PHONY")]
        assert body == ["", "Run make help"]


class TestDisabledRegions:
    """Lines that '# bake-format off' hides count for the lines after them."""

    LINES = ["X = 1", "# bake-format off", "# bake-format on", "\t"]

    def test_hidden_rule_gets_its_empty_recipe(self):
        """The tab-only line is the empty recipe of the hidden rule."""
        hidden = {1: ["foo:"]}
        assert _whitespace(self.LINES, disabled_region_lines=hidden) == self.LINES

    def test_without_hidden_rule_the_tab_only_line_is_blank(self):
        lines = _whitespace(self.LINES, disabled_region_lines={1: []})
        assert lines == [*self.LINES[:3], ""]

    def test_hidden_rule_empty_recipe_through_formatter(self):
        text = f"{IMPLICIT}\n# bake-format off\nfoo.x:\n# bake-format on\n\n\t\n"
        assert _formatter().format(text).content == text

    def test_value_after_region_is_kept_once(self):
        text = "all:\n\t@echo [$(X)]\n# bake-format off\nY = 1\n# bake-format on"
        text += "\n\n\nX = a \n"
        formatted = _formatter().format(text).content
        assert formatted.splitlines().count("X = a ") == 1
        assert formatted == text.replace("\n\n\n", "\n\n")


class TestStability:
    """Formatting the formatted text again changes nothing."""

    @pytest.mark.parametrize(
        "text",
        [
            f"{IMPLICIT}\nfoo.x:\n\t   \n\n\nbar:\n\t@echo bar\n",
            "foo.x:\nifdef X\n\t@echo x\nendif\n\t\n",
            "define newline\n\n\nendef\ndefine PAD\nx   \nendef\n",
            "CC = gcc \nLIBS = -lm " + BS + "\n\t-ldl \nfoo: X = a \n",
            "VPATH = src   # dirs\n",
            "\n".join(POSSIBLY_SYNTAX["conditionals-in-a-row"]) + "\n",
            "\n".join(POSSIBLY_SYNTAX["after-override"]) + "\n",
            "all: ; @echo a\ndefine U\nu\n\n\n\n",
            # A backslash and a space do not continue a line (GNU 762-769);
            # the space still goes, which makes the line continue.
            "R = $(1): ; @echo rule $(1)\nVPATH = src "
            + BS
            + " \n$(call R,r1)\n\n\t \n",
            "bar.x:\n\t# c\nVPATH = src "
            + BS
            + " \ndefine BS\na "
            + BS
            + "\n  b \nendef\n",
            "X = a " + BS + " \nfoo.x:\n\t\n",
            # Removing the space joins 'define U' to the VPATH line, so the
            # assignment after it is no define body any more.
            "VPATH = src " + BS + " \ndefine U\nX ?= c \nendef\n",
            # Without its trailing blank, make 3.81 would read '\t# rc' as a
            # recipe line of t2, and the TAB-only line would not be needed.
            "t2:\n\t\n-include $(EMPTY) \n\t# rc\n",
        ],
    )
    @pytest.mark.parametrize(
        "config",
        [
            {},
            {"align_variable_assignments": True},
            {"indent_nested_conditionals": True, "tab_width": 2},
            AUTO_GROUP_TOP,
            AUTO_UNGROUP,
            {"space_around_assignment": False},
        ],
        ids=["default", "align", "indent", "group-top", "ungroup", "nospace"],
    )
    def test_second_pass_changes_nothing(self, text, config):
        once = _formatter(**config).format(text).content
        assert _formatter(**config).format(once).content == once

    @pytest.mark.parametrize(
        "text",
        [
            "foo.x:\nifdef X\n\t@echo x\nendif\n\t\n",
            "define newline\n\n\nendef\ndefine PAD\nx   \nendef\n",
            "CC = gcc \nLIBS = -lm " + BS + "\n\t-ldl \nfoo: X = a \n",
            # The .PHONY line goes into the body of 'define HELP_TEXT :='.
            "define HELP_TEXT :=\n\nRun make help\nendef\n\nhelp:\n"
            "\t$(info $(HELP_TEXT))\n",
            # The .PHONY line goes right after a kept empty recipe line.
            "Y = \n# bake-format off\nfoo.x:\n# bake-format on\n\t\t \nt1:\n",
            "t1: X = a;b \nt9 " + BS + "\n  t10: t1\n\t\n" + IMPLICIT + "\n",
            "SRCS = a.c b.c\nall: foo "
            + BS
            + "\n     bar\n\t\n\t@echo done\n\nfoo bar:\n\t@echo $@\n",
        ],
    )
    def test_second_pass_changes_nothing_with_phony_after_header(self, text):
        """PhonyRule puts the grouped .PHONY line after the header and
        removes it again on the next run."""
        once = _formatter(**AUTO_GROUP_AFTER).format(text).content
        assert _formatter(**AUTO_GROUP_AFTER).format(once).content == once

    @pytest.mark.parametrize(
        ("lines", "config"),
        [
            # automake input, which make does not read itself: the .PHONY
            # line that the first run puts after the header may own the
            # TAB-only line after 'endif'.
            (AUTOMAKE_IF, AUTO_GROUP_AFTER),
            (AUTOMAKE_IF, AUTO_GROUP_TOP),
            (AUTOMAKE_IF, AUTO_UNGROUP),
            (UNREACHED_PHONY_SHAPES["inserted-phony"], AUTO_GROUP_TOP),
            (UNREACHED_PHONY_SHAPES["inserted-phony"], AUTO_UNGROUP),
            (UNREACHED_PHONY_SHAPES["phony-at-top"], AUTO_GROUP_TOP),
            (UNREACHED_PHONY_SHAPES["phony-at-top"], AUTO_UNGROUP),
        ],
        ids=[
            "automake-if-group-after",
            "automake-if-group-top",
            "automake-if-ungroup",
            "inserted-phony-group-top",
            "inserted-phony-ungroup",
            "phony-at-top-group-top",
            "phony-at-top-ungroup",
        ],
    )
    def test_second_pass_changes_nothing_after_phony_moves(self, lines, config):
        """The .PHONY line that the first run puts in place moves again on
        the second run; the TAB-only line it may own stays. Each makefile has
        one phony target, so the order of targets cannot vary."""
        text = "\n".join(lines) + "\n"
        once = _formatter(**config).format(text).content
        assert _formatter(**config).format(once).content == once

    @pytest.mark.parametrize(
        "text",
        [
            "ifeq (a,a)\nFLAGS := -O2 -g "
            + BS
            + " \n$(R)\n.PHONY: t1 t2\nendif\n\t\nt1: ; @:\nt2: ; @:\n",
            "foo.x:\nifeq (a,a)\nFLAGS := -O2 "
            + BS
            + " \n$(R)\n.PHONY: t1\nendif\n\t\n",
        ],
    )
    @pytest.mark.parametrize(
        "config", [AUTO_GROUP_TOP, AUTO_UNGROUP], ids=["group-top", "ungroup"]
    )
    def test_second_pass_changes_nothing_after_the_backslash_cleanup(
        self, text, config
    ):
        """'$(R)' may start a rule context that reaches the '.PHONY' line,
        which may then own the TAB-only line after 'endif'. Once the
        whitespace after the backslash goes, the value of FLAGS goes on over
        '$(R)' (GNU 762-769) and no rule context reaches the '.PHONY' line.
        Both runs decide alike whether the '.PHONY' line stays. t1 and t2
        have rules, so the grouped '.PHONY' line lists them in the order of
        their rules, which no hash seed changes."""
        once = _formatter(**config).format(text).content
        assert _formatter(**config).format(once).content == once

    @pytest.mark.parametrize(
        ("text", "config"),
        [
            (
                "ifdef X\nfoo.x:\nprivate X = q \nendif\n",
                {"indent_nested_conditionals": True, "tab_width": 2},
            ),
            (
                "R = 1\nVPATH = src " + BS + " \ndefine U\nX ?= c \nendef\n",
                {"align_variable_assignments": True, "normalize_empty_lines": False},
            ),
        ],
        ids=["indent-then-tab", "align-dangling-backslash"],
    )
    def test_second_pass_changes_nothing_with_kept_trailing_whitespace(
        self, text, config
    ):
        """With remove_trailing_whitespace off, conditional indentation and
        alignment decide the same way on their own output: a re-indented
        assignment that TabsRule then indents with a TAB keeps its value
        whitespace, and a backslash followed by whitespace never becomes a
        continuation (GNU 762-769), so the define body stays one."""
        config = {"remove_trailing_whitespace": False, **config}
        once = _formatter(**config).format(text).content
        assert _formatter(**config).format(once).content == once


# make runs with a minimal environment so that no inherited variable (such as
# MAKEFLAGS) changes what it reads.
_MAKE_ENV = {"PATH": os.defpath, "LC_ALL": "C"}


@pytest.fixture(scope="module", params=["make", "gmake"])
def gnu_make(request):
    """Return (make, true) paths, or skip when that GNU make cannot run here.

    'gmake' is often a second GNU make, such as 4.x next to macOS's 3.81.
    """
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
    if "GNU Make" not in version:
        pytest.skip("make is not GNU make")
    return make, true


def _major_version(make):
    """Return the major version of a GNU make, such as 3 or 4, or 0."""
    try:
        version = subprocess.run(
            [make, "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            env=_MAKE_ENV,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return 0
    match = re.match(r"GNU Make (\d+)\.", version)
    return int(match.group(1)) if match else 0


@pytest.fixture(scope="module")
def gnu_make_4():
    """Return (make, true) for a GNU make 4.x, or skip.

    make 3.81 has no .RECIPEPREFIX.
    """
    if os.name == "nt":
        pytest.skip("GNU make checks do not run on Windows")
    true = shutil.which("true")
    if true is None:
        pytest.skip("true is not installed")
    for name in ("gmake", "make"):
        make = shutil.which(name)
        if make is not None and _major_version(make) >= 4:
            return make, true
    pytest.skip("no GNU make 4.x is installed")


def _dry_run(gnu_make, cwd, text, goal, *settings):
    """Return (returncode, stdout) of 'make -n goal' on text.

    make prints the commands it would run, or that the goal is up to date.
    settings are variable assignments for the command line.
    """
    make, true = gnu_make
    proc = subprocess.run(
        [make, "-r", "-R", "-n", "-f", "-", f"SHELL={true}", *settings, goal],
        input=text,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=60,
        env=_MAKE_ENV,
    )
    return proc.returncode, proc.stdout


class TestAgainstGnuMake:
    """make does the same with the formatted file as with the original.

    Every input works with make 3.81 and 4.x.
    """

    @pytest.mark.parametrize("name", sorted(POSSIBLY_SYNTAX))
    def test_tab_led_assignments_keep_their_values(self, gnu_make, tmp_path, name):
        """make 3.81 or 4.x reads these lines as assignments (GNU 1217-1219,
        2881-2884), so their values keep their whitespace (4273-4288)."""
        text = "\n".join(POSSIBLY_SYNTAX[name]) + "\n"
        text += "$(info [$(EXE)][$(CFLAGS)][$(Y)][$(VERILATOR)][$(V)])\nshow: ; @:\n"
        before = _dry_run(gnu_make, tmp_path, text, "show")
        assert before[0] == 0
        formatted = _formatter().format(text).content
        assert _dry_run(gnu_make, tmp_path, formatted, "show") == before

    @pytest.mark.parametrize(
        "config",
        [{}, AUTO_GROUP_TOP, AUTO_GROUP_AFTER, AUTO_UNGROUP],
        ids=["default", "group-top", "group-after", "ungroup"],
    )
    def test_moved_phony_leaves_implicit_rule_alone(self, gnu_make, tmp_path, config):
        """prog.o has no recipe, so the implicit rule makes it (GNU
        4040-4055)."""
        text = "\n".join(TestPhonyRuleMoves.LINES) + "\n"
        before = _dry_run(gnu_make, tmp_path, text, "prog.o")
        assert "implicit prog.o" in before[1]
        formatted = _formatter(**config).format(text).content
        assert _dry_run(gnu_make, tmp_path, formatted, "prog.o") == before

    @pytest.mark.parametrize("setting", [[], ["A=1"]], ids=["no-A", "A"])
    @pytest.mark.parametrize(
        "config",
        [AUTO_GROUP_TOP, AUTO_GROUP_AFTER, AUTO_UNGROUP],
        ids=["group-top", "group-after", "ungroup"],
    )
    @pytest.mark.parametrize("name", sorted(BRANCH_SHAPES))
    def test_moved_phony_leaves_branch_rules_alone(
        self, gnu_make, tmp_path, name, config, setting
    ):
        """make may read the TAB-only line as a recipe line of the .PHONY
        line in one branch only. Once that line moves, the TAB-only line must
        not give the rule before it an empty recipe (GNU 2881-2891,
        4040-4055)."""
        lines, goal = BRANCH_SHAPES[name]
        text = "\n".join(lines) + "\n"
        before = _dry_run(gnu_make, tmp_path, text, goal, *setting)
        assert before[0] == 0
        formatted = _formatter(**config).format(text).content
        assert _dry_run(gnu_make, tmp_path, formatted, goal, *setting) == before

    @pytest.mark.parametrize("setting", [[], ["X=1"]], ids=["no-X", "X"])
    @pytest.mark.parametrize("config", sorted(PHONY_MOVES))
    @pytest.mark.parametrize("name", sorted(SHARED_LINE_SHAPES))
    def test_phony_lines_that_cannot_move_keep_make_behaviour(
        self, gnu_make, tmp_path, name, config, setting
    ):
        """Where make reads foo.x, the tab-only line is its empty recipe, so
        foo.x is up to date (GNU 2890-2891, 4040-4055); where it skips it, the
        line is a recipe line of .PHONY, which make never runs (2234-2240)."""
        text = "\n".join(SHARED_LINE_SHAPES[name]) + "\n"
        before = _dry_run(gnu_make, tmp_path, text, "foo.x", *setting)
        assert before[0] == 0
        formatted = _formatter(**PHONY_MOVES[config]).format(text).content
        assert _dry_run(gnu_make, tmp_path, formatted, "foo.x", *setting) == before

    @pytest.mark.parametrize("which", [0, 1], ids=["foo.x-skipped", "foo.x-read"])
    @pytest.mark.parametrize("config", sorted(PHONY_MOVES))
    @pytest.mark.parametrize("name", sorted(PREFIX_ONLY_SHAPES))
    def test_line_of_only_a_recipe_prefix_keeps_make_behaviour(
        self, gnu_make_4, tmp_path, name, config, which
    ):
        """Where make reads foo.x, the line '>' is its empty recipe, so foo.x
        is up to date (GNU 2890-2891, 4040-4055, 5158-5169); where it skips
        foo.x, the implicit rule makes foo.x."""
        lines, settings = PREFIX_ONLY_SHAPES[name]
        setting = settings[which]
        text = "\n".join(lines) + "\n"
        before = _dry_run(gnu_make_4, tmp_path, text, "foo.x", *setting)
        expected = "up to date" if which else "echo implicit foo.x"
        assert before[0] == 0 and expected in before[1]
        formatted = _formatter(**PHONY_MOVES[config]).format(text).content
        assert _dry_run(gnu_make_4, tmp_path, formatted, "foo.x", *setting) == before

    @pytest.mark.parametrize("config", sorted(PHONY_MOVES))
    @pytest.mark.parametrize("name", sorted(PREFIX_LINE_OF_PHONY))
    def test_phony_line_that_owns_a_prefix_line_keeps_make_behaviour(
        self, gnu_make_4, tmp_path, name, config
    ):
        """foo.x has no recipe, so the implicit rule makes it (GNU 4040-4055),
        on the first run and on the second."""
        text = "\n".join(PREFIX_LINE_OF_PHONY[name]) + "\n"
        before = _dry_run(gnu_make_4, tmp_path, text, "foo.x")
        assert before[0] == 0 and "echo implicit foo.x" in before[1]
        once = _formatter(**PHONY_MOVES[config]).format(text).content
        twice = _formatter(**PHONY_MOVES[config]).format(once).content
        assert _dry_run(gnu_make_4, tmp_path, once, "foo.x") == before
        assert _dry_run(gnu_make_4, tmp_path, twice, "foo.x") == before

    @pytest.mark.parametrize("setting", [[], ["X=1"]], ids=["no-X", "X"])
    @pytest.mark.parametrize("name", sorted(BACKSLASH_CLEANUP_SHAPES))
    def test_backslash_cleanup_gives_no_rule_an_empty_recipe(
        self, gnu_make, tmp_path, name, setting
    ):
        """make reads the tab-only line as a blank line, so the implicit rule
        makes the target (GNU 2881-2884, 4040-4055), also after the
        whitespace after the backslash goes (GNU 762-769)."""
        lines, goal = BACKSLASH_CLEANUP_SHAPES[name]
        text = "\n".join(lines) + "\n"
        before = _dry_run(gnu_make, tmp_path, text, goal, *setting)
        assert before[0] == 0
        assert "implicit" in before[1]
        formatted = _formatter().format(text).content
        assert _dry_run(gnu_make, tmp_path, formatted, goal, *setting) == before

    @pytest.mark.parametrize("setting", [[], ["X=1"]], ids=["no-X", "X"])
    @pytest.mark.parametrize("name", sorted(CLEANUP_ABOVE_SHAPES))
    def test_backslash_cleanup_above_the_line(self, gnu_make, tmp_path, name, setting):
        """make never reads the TAB-only line in the goal's rule context, so
        the implicit rule makes the goal (GNU 4040-4055). The cleanup above
        the line (GNU 762-769) must not give the goal an empty recipe."""
        lines, goal, config = CLEANUP_ABOVE_SHAPES[name]
        text = "\n".join(lines) + "\n"
        before = _dry_run(gnu_make, tmp_path, text, goal, *setting)
        assert before == (0, f"echo implicit {goal}\n")
        formatted = _formatter(**config).format(text).content
        assert _dry_run(gnu_make, tmp_path, formatted, goal, *setting) == before

    def test_kept_whitespace_after_a_backslash_with_conditional_indentation(
        self, gnu_make, tmp_path
    ):
        """Without X make skips the branch, the define line in it included,
        so the implicit rule makes t5.x (GNU 4040-4055, 5345-5358)."""
        text = "\n".join(KEEP_INDENT_DEFINE) + "\n"
        before = _dry_run(gnu_make, tmp_path, text, "t5.x")
        assert before == (0, "echo implicit t5.x\n")
        formatted = _formatter(**KEEP_INDENT).format(text).content
        assert _dry_run(gnu_make, tmp_path, formatted, "t5.x") == before

    def test_line_of_another_rule_after_the_backslash_cleanup(self, gnu_make, tmp_path):
        """With A, make reads the tab-only line as a blank line, as 'X = 1'
        ends the rule context of bar.x (GNU 2881-2884). After the cleanup
        (GNU 762-769) the comment would go on over 'X = 1', and the line
        would be the empty recipe of bar.x, so it is not kept. Without A it is
        the empty recipe of foo.x, which the cleanup changes as it did
        before."""
        lines = [IMPLICIT, "foo.x:", "ifdef A", "bar.x:", "# c " + BS + " ", "X = 1"]
        text = "\n".join([*lines, "endif", "\t"]) + "\n"
        before = _dry_run(gnu_make, tmp_path, text, "bar.x", "A=1")
        assert before == (0, "echo implicit bar.x\n")
        formatted = _formatter().format(text).content
        assert _dry_run(gnu_make, tmp_path, formatted, "bar.x", "A=1") == before

    def test_recipeprefix_after_the_backslash_cleanup(self, gnu_make_4, tmp_path):
        """make 4.x reads the tab-only line as a blank line, as the prefix is
        '>' (GNU 5158-5169). After the cleanup (GNU 762-769) the VPATH value
        would go on over '.RECIPEPREFIX = >', and the line would be the empty
        recipe of foo.x, so it is not kept. make 3.81, which has no
        .RECIPEPREFIX, reads it as the empty recipe of foo.x, which the
        cleanup changes as it did before."""
        lines = [IMPLICIT, "VPATH = src " + BS + " ", ".RECIPEPREFIX = >", "foo.x:"]
        text = "\n".join([*lines, "\t"]) + "\n"
        before = _dry_run(gnu_make_4, tmp_path, text, "foo.x")
        assert before == (0, "echo implicit foo.x\n")
        formatted = _formatter().format(text).content
        assert _dry_run(gnu_make_4, tmp_path, formatted, "foo.x") == before

    @pytest.mark.parametrize("setting", [[], ["A=1"]], ids=["no-A", "A"])
    @pytest.mark.parametrize(
        "config",
        [AUTO_GROUP_TOP, AUTO_GROUP_AFTER, AUTO_UNGROUP],
        ids=["group-top", "group-after", "ungroup"],
    )
    @pytest.mark.parametrize("name", sorted(UNREACHED_PHONY_SHAPES))
    def test_unreached_phony_keeps_branch_empty_recipe(
        self, gnu_make, tmp_path, name, config, setting
    ):
        """No rule context reaches the .PHONY line, so without it the TAB-only
        line is blank where the line was its recipe line, and the empty
        recipe of foo.x with A must stay (GNU 2881-2891, 4040-4055), also
        after a second run."""
        text = "\n".join(UNREACHED_PHONY_SHAPES[name]) + "\n"
        before = _dry_run(gnu_make, tmp_path, text, "foo.x", *setting)
        assert before[0] == 0
        formatted = _formatter(**config).format(text).content
        formatted = _formatter(**config).format(formatted).content
        assert _dry_run(gnu_make, tmp_path, formatted, "foo.x", *setting) == before

    @pytest.mark.parametrize("setting", [[], ["A=1"]], ids=["no-A", "A"])
    @pytest.mark.parametrize(
        ("text", "goal"),
        [
            ("t2:\n\t\n-include $(EMPTY) \n\t# rc\n", "t2"),
            ("t3:\n\nifeq ($(A),1)\nsinclude $(EMPTY) \nendif\n\t\n", "t3"),
        ],
        ids=["tab-line-after-include", "include-in-branch"],
    )
    def test_include_whitespace_keeps_make_behaviour(
        self, gnu_make, tmp_path, text, goal, setting
    ):
        """make 3.81 ends the rule context at an include of ' ' and keeps it
        at an include of nothing (GNU 848-856 for make 4.x)."""
        before = _dry_run(gnu_make, tmp_path, text, goal, *setting)
        assert before[0] == 0
        formatted = _formatter().format(text).content
        assert _dry_run(gnu_make, tmp_path, formatted, goal, *setting) == before

    def test_conditional_indentation_keeps_values(self, gnu_make, tmp_path):
        text = "ifeq (1,1)\nV = a \nendif\nshow: ; @echo [$(V)]\n"
        before = _dry_run(gnu_make, tmp_path, text, "show")
        assert "[a ]" in before[1]
        config = {"indent_nested_conditionals": True, "tab_width": 4}
        formatted = _formatter(**config).format(text).content
        assert _dry_run(gnu_make, tmp_path, formatted, "show") == before

    @pytest.mark.parametrize(
        "config",
        [
            {"indent_nested_conditionals": True, "tab_width": 2},
            {"align_variable_assignments": True},
        ],
        ids=["indent", "align"],
    )
    def test_kept_trailing_whitespace_keeps_values(self, gnu_make, tmp_path, config):
        """With remove_trailing_whitespace off, values keep their trailing
        whitespace as well (GNU 4273-4288)."""
        text = "ifeq (1,1)\nV = a \nendif\nCC = gcc \nCFLAGS = -O2 \n"
        text += "show: ; @echo [$(V)][$(CC)][$(CFLAGS)]\n"
        before = _dry_run(gnu_make, tmp_path, text, "show")
        assert "[a ][gcc ][-O2 ]" in before[1]
        formatter = _formatter(remove_trailing_whitespace=False, **config)
        formatted = formatter.format(text).content
        assert _dry_run(gnu_make, tmp_path, formatted, "show") == before

    @pytest.mark.parametrize(
        "body", [["X=1", "Y:=a:b", "  Z  =  2"], ["A = 1", "LONG_NAME = 2"]]
    )
    @pytest.mark.parametrize(
        "config", [{}, {"align_variable_assignments": True}], ids=["default", "align"]
    )
    def test_define_body_assignments_keep_the_value(
        self, gnu_make, tmp_path, body, config
    ):
        """The body is the value of T (GNU 4795-4799)."""
        text = "\n".join(["define T", *body, "endef"]) + "\n"
        text += "show: ; @echo '[$(subst $(newline),|,$(T))]'\n"
        text = "define newline\n\n\nendef\n" + text
        before = _dry_run(gnu_make, tmp_path, text, "show")
        assert before[0] == 0
        formatted = _formatter(**config).format(text).content
        assert _dry_run(gnu_make, tmp_path, formatted, "show") == before

    @pytest.mark.parametrize(
        "lines",
        [
            ["ifdef NOPE", ".RECIPEPREFIX = >", "endif", IMPLICIT, "foo.x:", "\t"],
            ["ifdef NOPE", ".RECIPEPREFIX = >", "endif", IMPLICIT, "foo.x:", "\t  "],
            [IMPLICIT, "foo.x:", "-include", "\t"],
            [IMPLICIT, "foo.x:", "-include $(NONE)", "\t"],
        ],
        ids=[
            "recipeprefix-in-branch",
            "recipeprefix-in-branch-blanks",
            "include-of-nothing",
            "include-of-a-reference",
        ],
    )
    def test_empty_recipe_that_one_make_reads(self, gnu_make, tmp_path, lines):
        """make 4.x reads the TAB-only line as foo.x's empty recipe in the
        first file, make 3.81 in the second."""
        text = "\n".join(lines) + "\n"
        before = _dry_run(gnu_make, tmp_path, text, "foo.x")
        assert before[0] == 0
        formatted = _formatter().format(text).content
        assert _dry_run(gnu_make, tmp_path, formatted, "foo.x") == before

    @pytest.mark.parametrize(
        ("text", "goal", "printed", "absent"),
        [
            (f"{IMPLICIT}\nfoo.x:\n\t\n", "foo.x", "up to date", "implicit"),
            (
                f"{IMPLICIT}\nfoo.x:\nifdef X\n\t@echo x\nendif\n\t\n",
                "foo.x",
                "up to date",
                "implicit",
            ),
            (
                f"{IMPLICIT}\n# bake-format off\nfoo.x:\n# bake-format on\n\n\t\n",
                "foo.x",
                "up to date",
                "implicit",
            ),
            (
                'define PAD\nx   \nendef\nshow: ; @echo "[$(PAD)]"\n',
                "show",
                "[x   ]",
                "[x]",
            ),
            (
                "define newline\n\n\nendef\nshow: ; @echo [$(newline)]\n",
                "show",
                "[\n]",
                "[]",
            ),
            ("CC = gcc \nshow: ; @echo [$(CC)x]\n", "show", "[gcc x]", "[gccx]"),
            (
                "LIBS = -lm " + BS + "\n\t\t-ldl \nshow: ; @echo [$(LIBS)]\n",
                "show",
                "[-lm -ldl ]",
                "-ldl]",
            ),
            ("show: X = a \nshow: ; @echo [$(X)]\n", "show", "[a ]", "[a]"),
            # make 3.81 reads 'sinclude $(EMPTY) ' as an include of ' ', which
            # ends the rule context of foo.x as in make 4.x (GNU 848-856).
            (
                f"{IMPLICIT}\nfoo.x:\nsinclude $(EMPTY) \n\t\n",
                "foo.x",
                "implicit foo.x",
                "up to date",
            ),
            (
                "all:\n\t@echo [$(X)]\n# bake-format off\nY = 1\n# bake-format on"
                "\n\n\nX = a \n",
                "all",
                "[a ]",
                "[a]",
            ),
        ],
    )
    def test_formatting_keeps_make_behaviour(
        self, gnu_make, tmp_path, text, goal, printed, absent
    ):
        """GNU 2890-2891, 4040-4055: the empty recipe keeps the implicit rule
        away; 4273-4288, 4785-4814: values keep their whitespace."""
        before = _dry_run(gnu_make, tmp_path, text, goal)
        assert before[0] == 0
        assert printed in before[1]
        assert absent not in before[1]
        formatted = _formatter().format(text).content
        assert _dry_run(gnu_make, tmp_path, formatted, goal) == before

    def test_aligned_values_keep_make_behaviour(self, gnu_make, tmp_path):
        text = "CC = gcc \nCFLAGS = -O2 \nshow: ; @echo [$(CC)][$(CFLAGS)]\n"
        before = _dry_run(gnu_make, tmp_path, text, "show")
        assert "[gcc ][-O2 ]" in before[1]
        formatted = _formatter(align_variable_assignments=True).format(text).content
        assert _dry_run(gnu_make, tmp_path, formatted, "show") == before
