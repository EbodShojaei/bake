"""Tests for duplicate-target errors that follow GNU make (issue #106).

A target may appear in several rules: make merges their prerequisites (GNU
make manual 4.11, lines 2545-2548). Only a second recipe for the same
single-colon target replaces the first, and make warns about it (lines
2550-2552; "overriding recipe for target", lines 11331-11337). So
DuplicateTargetRule reports an error only when two such rules for one target
both have a recipe, with its message and Error severity unchanged.

A recipe is made of the lines that start with the recipe prefix in the rule
context, even a TAB-only line, which is an empty recipe (5.1, lines
2878-2891), or an inline recipe after ';', 'foo: ;' included (4.2, lines 1488
and 1499-1503; 5.9, lines 4047-4051). Lines that the formatter turns into
recipe lines count too, so that the errors for the input and for the
formatted lines agree in the cases tested here.

Line numbers refer to the GNU make 4.4.1 manual. TestAgainstGnuMake checks
with GNU make that the errors name the rules that make warns about.
"""

import os
import re
import shutil
import subprocess
import sys
import time
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from mbake.cli import app
from mbake.config import Config, FormatterConfig
from mbake.core.formatter import MakefileFormatter
from mbake.core.rules.duplicate_targets import DuplicateTargetRule
from mbake.core.rules.tabs import TabsRule
from mbake.utils import rule_context
from mbake.utils.line_utils import LineUtils

T = "\t"
BS = "\\"  # one backslash, to keep continuation lines readable


def _error(target, first, second):
    """Return the error for a rule at line second that overrides line first."""
    return (
        f"{second}: Error: Duplicate target '{target}' defined at lines {first} "
        f"and {second}. Second definition will override the first."
    )


def _rule_errors(lines, **config):
    """Return the errors of DuplicateTargetRule alone, in the GNU format."""
    config["_global"] = {"gnu_error_format": True}
    return DuplicateTargetRule().format(list(lines), config).errors


def _formatter(gnu_error_format=True, **config):
    return MakefileFormatter(
        Config(formatter=FormatterConfig(**config), gnu_error_format=gnu_error_format)
    )


def _duplicate_errors(lines, **config):
    """Return the 'Duplicate target' errors of the whole formatter."""
    _, errors, _ = _formatter(**config).format_lines(list(lines))
    return [error for error in errors if "Duplicate target" in error]


class TestPrerequisiteOnlyRules:
    """Rules without a recipe only add prerequisites (GNU 2545-2548)."""

    def test_split_prerequisites_are_not_duplicates(self):
        """The first example of issue #106 (GNU 2560-2573)."""
        assert _duplicate_errors(["foo: bar", "foo: baz"]) == []

    @pytest.mark.parametrize(
        "lines",
        [
            ["foo:", T + "@echo a", "foo: bar"],
            ["foo: bar", "foo:", T + "@echo a"],
            ["foo: ; @echo a", "foo: bar"],
            [
                "ccache-report:",
                T + "@echo report",
                "",
                "# ccache-report runs last",
                "ccache-report: $(VK_OTHER_GOALS)",
            ],
            [
                "ifeq ($(VK_CCACHE),1)",
                "  ccache-report: $(VK_CCACHE_REPORT)",
                T + "@cat $<",
                "",
                "# ccache-report runs last",
                "  ccache-report: $(VK_OTHER_GOALS)",
                "endif",
            ],
        ],
    )
    def test_recipe_and_prerequisite_only_rules_merge(self, lines):
        """Only one of the rules has a recipe, so nothing is overridden
        (GNU 2545-2548, 2585-2587), as in Verilator's verilated.mk."""
        assert _rule_errors(lines) == []
        assert _duplicate_errors(lines) == []

    @pytest.mark.parametrize(
        "target",
        [
            ".PRECIOUS",
            ".SECONDARY",
            ".INTERMEDIATE",
            ".IGNORE",
            ".SILENT",
            ".NOTPARALLEL",
            ".EXPORT_ALL_VARIABLES",
            ".DELETE_ON_ERROR",
            ".POSIX",
        ],
    )
    def test_repeated_special_targets_without_recipes(self, target):
        """Special targets without a recipe may be repeated (GNU 2229-2438)."""
        assert _rule_errors([f"{target}: a", f"{target}: b"]) == []

    def test_override_across_prerequisite_only_rule(self):
        """The recipe at line 4 overrides the one of line 1; the rule in
        between only adds a prerequisite (GNU 2545-2552)."""
        lines = ["foo:", T + "@echo a", "foo: bar", "foo:", T + "@echo b"]
        assert _rule_errors(lines) == [_error("foo", 1, 4)]


class TestNonRuleLines:
    """Lines that are no rule definitions never count (GNU 2881-2884)."""

    def test_target_specific_variables_issue_example(self):
        """The second example of issue #106 (GNU 4938-4951)."""
        assert _duplicate_errors(["foo: bar = 1", "foo: baz"]) == []

    @pytest.mark.parametrize(
        "lines",
        [
            ["prog : CFLAGS = -g", "prog : prog.o foo.o bar.o"],
            ["prog:CFLAGS=-g", "prog:prog.o"],
            ["%.o: cflags = -O", "%.o: x.h"],
            ["lib/%.o: CFLAGS := -fPIC -g", "%.o: CFLAGS := -g"],
        ],
    )
    def test_target_and_pattern_specific_variables(self, lines):
        """GNU 4938-4951, 4994-4999."""
        assert _rule_errors(lines) == []

    @pytest.mark.parametrize("op", ["=", ":=", "::=", ":::=", "?=", "+=", "!="])
    @pytest.mark.parametrize("name", ["CFLAGS", "cflags", "CFlags", "my.var"])
    @pytest.mark.parametrize(
        "modifiers",
        ["", "override", "export", "private", "unexport", "override export"],
    )
    def test_target_specific_variable_forms(self, modifiers, name, op):
        """Any operator, modifier and name case makes a target-specific
        variable (GNU 4091-4092, 4940-4951). It is no rule, so the rules after
        it are compared with each other only."""
        assignment = " ".join(word for word in (modifiers, name, op, "x") if word)
        lines = [f"foo: {assignment}", "foo:", T + "@echo a", "foo:", T + "@echo b"]
        assert _rule_errors(lines) == [_error("foo", 2, 4)]

    @pytest.mark.parametrize(
        "lines",
        [
            ["FOO:=a", "FOO:=b"],
            ["CC:=gcc", "CC:=clang"],
            ["FOO::=a", "FOO::=b"],
            ["FOO:::=a", "FOO:::=b"],
            ["override FOO:=a", "override FOO:=b"],
            ["export FOO:=a", "export FOO:=b"],
        ],
    )
    def test_reassignments_are_not_definitions(self, lines):
        """'NAME:=' is an assignment, not a rule (GNU 4577-4579, 4612-4625)."""
        assert _rule_errors(lines) == []
        assert _duplicate_errors(lines) == []

    @pytest.mark.parametrize(
        "opener",
        ["define TPL", "define TPL =", "override define TPL", "export define TPL"],
    )
    def test_define_bodies_are_not_definitions(self, opener):
        """A define body is the value of a variable (GNU 4776-4781, 4795-4799)."""
        lines = [opener, "foo:", T + "@echo a", "endef", "foo:", T + "@echo b"]
        assert _rule_errors(lines) == []

    def test_only_a_bare_define_nests(self):
        """Inside a body, only a bare 'define' nests (GNU 4823-4827), so the
        first 'endef' ends the outer body here."""
        nested = ["define OUTER", "define INNER", "foo:", T + "@echo a", "endef"]
        nested += ["foo:", T + "@echo b", "endef", "foo:", T + "@echo c"]
        assert _rule_errors(nested) == []
        modified = ["define OUTER", "override define INNER", "endef"]
        modified += ["foo:", T + "@echo a", "foo:", T + "@echo b"]
        assert _rule_errors(modified) == [_error("foo", 4, 6)]

    def test_override_define_body_after_recipe(self):
        """A body line that looks like a rule is part of the value, so the
        rule at line 6 overrides the recipe of line 1 only (GNU 4776-4781,
        4795-4799)."""
        lines = ["all:", T + "@echo a", "override define MSG", "all:", "endef"]
        assert _rule_errors(lines + ["all: ; @true"]) == [_error("all", 1, 6)]
        lines = ["all:", T + "@echo a", "override define MSG", "all:"]
        lines += [T + "@echo body", "endef", "all: extra"]
        assert _rule_errors(lines) == []
        assert _duplicate_errors(lines) == []

    def test_double_colon_rules(self):
        """Each double-colon rule has a recipe of its own (GNU 2721-2737)."""
        lines = ["foo:: a", T + "@echo 1", "foo:: b", T + "@echo 2"]
        assert _rule_errors(lines) == []

    @pytest.mark.parametrize(
        "lines",
        [
            ["%.o:", T + "@echo a", "%.o:", T + "@echo b"],
            ["%.o: x.h", T + "@echo a", "%.o: y.h", T + "@echo b"],
        ],
    )
    def test_pattern_rules(self, lines):
        """A pattern rule replaces or adds an implicit rule (GNU 8006-8007,
        8409-8419)."""
        assert _rule_errors(lines) == []

    @pytest.mark.parametrize(
        "lines",
        [
            ["build:", T + "cc -o x x.c", "build: ## Build it"],
            ["build:", T + "cc -o x x.c", "build: # Build it"],
            ["foo: bar # see; notes", "foo: baz"],
            [
                "out.json: dep.h",
                "out.json: z.zip # bake-format not-phony",
                T + "unzip z.zip",
            ],
        ],
    )
    def test_comments_after_the_colon(self, lines):
        """A comment, also one with ';', adds no recipe (GNU 730-737)."""
        assert _rule_errors(lines) == []

    def test_template_placeholders(self):
        """'$(1)' targets are only instantiated by '$(call ...)'."""
        lines = ["$(1):", T + "@echo a", "$(1):", T + "@echo b"]
        assert _rule_errors(lines) == []

    @pytest.mark.parametrize(
        ("lines", "expected"),
        [
            (["C:/out/a.o: a.c", T + "@echo a", "C:/out/b.o: b.c", T + "@echo b"], []),
            (
                ["C:" + BS + "out" + BS + "a.o: a.c", T + "@echo a"]
                + ["C:" + BS + "out" + BS + "b.o: b.c", T + "@echo b"],
                [],
            ),
            (
                ["C:/out/a.o: a.c", T + "@echo a", "C:/out/a.o: b.c", T + "@echo b"],
                [_error("C:/out/a.o", 1, 3)],
            ),
        ],
    )
    def test_drive_letters_are_part_of_the_target(self, lines, expected):
        """On MS-Windows, make reads 'c:/foo/bar/baz.c' as one path (GNU
        1700-1707), so these are different targets."""
        assert _rule_errors(lines) == expected

    def test_assignment_continuation_lines(self):
        """Continuation lines belong to the assignment (GNU 776-781), so
        'http:' in them is no rule."""
        lines = [
            "URLS = http://a.com/x " + BS,
            "  http://b.com/y " + BS,
            "  http://c.com/z",
        ]
        assert _rule_errors(lines) == []
        assert _duplicate_errors(lines) == []

    def test_eval_line_ends_rule_context(self):
        """A line that only calls '$(eval ...)' ends the rule context of
        'all: x' (GNU 2881-2884), so that rule has no recipe."""
        lines = ["all: x", "$(eval $(call TPL,x))", "all:", T + "@echo b"]
        assert _rule_errors(lines) == []
        assert _duplicate_errors(lines) == []


class TestRecipes:
    """What counts as a recipe."""

    @pytest.mark.parametrize(
        ("lines", "expected"),
        [
            (["foo: ; @echo a", "foo: ; @echo b"], [_error("foo", 1, 2)]),
            (["foo: ;", "foo:", T + "@echo b"], [_error("foo", 1, 2)]),
            (["foo: bar; @echo a", "foo:", T + "@echo b"], [_error("foo", 1, 2)]),
            (["foo: ; @echo a", "foo: bar"], []),
        ],
    )
    def test_inline_recipes(self, lines, expected):
        """GNU 1488, 1499-1503; 'foo: ;' is an empty recipe (4047-4051)."""
        assert _rule_errors(lines) == expected

    @pytest.mark.parametrize(
        ("backslashes", "expected"),
        [(1, [_error("foo", 1, 2)]), (3, []), (5, [_error("foo", 1, 2)])],
    )
    def test_escaped_semicolon_recipes(self, backslashes, expected):
        """make removes half of the backslashes before ';' and scans the
        prerequisites for ';' again, so a ';' after 1 or 5 backslashes starts
        an inline recipe and one after 3 does not (GNU 730-737, 1499-1503)."""
        lines = ["foo: a" + BS * backslashes + ";b", "foo:", T + "@echo b"]
        assert _rule_errors(lines) == expected

    def test_tab_only_line_is_an_empty_recipe(self):
        """GNU 2890-2891, 4048-4055."""
        lines = ["foo:", T, "foo:", T + "@echo b"]
        assert _rule_errors(lines) == [_error("foo", 1, 3)]

    def test_tab_led_comment_is_a_recipe_line(self):
        """A comment in a recipe goes to the shell (GNU 2893-2895)."""
        lines = ["foo:", T + "# just a comment", "foo:", T + "@echo b"]
        assert _rule_errors(lines) == [_error("foo", 1, 3)]

    def test_blank_and_comment_lines_keep_the_rule_context(self):
        """GNU 2884-2886."""
        lines = ["foo:", "", "# c", T + "@echo a", "foo:", T + "@echo b"]
        assert _rule_errors(lines) == [_error("foo", 1, 5)]

    def test_comment_continuation_swallows_the_next_line(self):
        """A backslash at the end of a comment continues it (GNU 730-733),
        so the second 'foo:' is part of the comment."""
        lines = ["foo:", T + "@echo a", "# c " + BS, "foo:", T + "@echo b"]
        assert _rule_errors(lines) == []

    def test_tab_led_conditional_is_recipe_text(self):
        """A TAB-led 'else' in a rule context goes to the shell (GNU
        2902-2905), so it does not start a branch."""
        lines = ["ifeq ($(X),1)", "foo:", T + "@echo a", T + "else", "endif"]
        lines += ["foo:", T + "@echo c"]
        assert _rule_errors(lines) == [_error("foo", 2, 6)]

    def test_recipe_lines_in_conditional_branches(self):
        """Conditional directives keep the rule context (GNU 5315-5333)."""
        lines = ["foo:", "ifeq ($(X),1)", T + "@echo a", "else", T + "@echo b"]
        lines += ["endif", "foo: extra"]
        assert _rule_errors(lines) == []

    @pytest.mark.parametrize("fix_missing_recipe_tabs", [True, False])
    @pytest.mark.parametrize("assignment", [".RECIPEPREFIX = >", ".RECIPEPREFIX += >"])
    def test_recipeprefix_recipes(self, assignment, fix_missing_recipe_tabs):
        """Lines that start with the recipe prefix are recipe lines (GNU
        2878-2880, 5158-5169). '+=' sets the prefix of an empty
        .RECIPEPREFIX."""
        config = {"fix_missing_recipe_tabs": fix_missing_recipe_tabs}
        lines = [assignment, "foo:", ">@echo a", "foo: bar"]
        assert _rule_errors(lines, **config) == []
        lines = [assignment, "foo:", ">@echo a", "foo:", ">@echo b"]
        assert _rule_errors(lines, **config) == [_error("foo", 2, 4)]


class TestConditionals:
    """Rules in different branches of a conditional are never compared."""

    def test_else_if_chain(self):
        """Every branch of a chain is a branch of its own (GNU 5399-5419)."""
        lines = ["ifeq ($(X),a)", "foo:", T + "@echo a"]
        lines += ["else ifeq ($(X),b)", "foo:", T + "@echo b"]
        lines += ["else", "foo:", T + "@echo c", "endif"]
        assert _rule_errors(lines) == []
        assert _duplicate_errors(lines) == []

    def test_nested_branches(self):
        lines = ["ifeq ($(A),1)", "ifeq ($(B),1)", "foo:", T + "@echo a"]
        lines += ["else", "foo:", T + "@echo b", "endif", "endif"]
        assert _rule_errors(lines) == []

    @pytest.mark.parametrize("opener", ["if DEBUG", "if !DEBUG"])
    def test_automake_conditionals(self, opener):
        """automake replaces 'if', 'else' and 'endif' before make runs."""
        lines = [opener, "foo:", T + "@echo a", "else", "foo:", T + "@echo b"]
        lines += ["endif"]
        assert _rule_errors(lines) == []
        assert _duplicate_errors(lines) == []

    def test_conditional_rule_then_unconditional_rule(self):
        lines = ["ifeq ($(X),1)", "foo:", T + "@echo a", "endif"]
        lines += ["foo:", T + "@echo b"]
        assert _rule_errors(lines) == [_error("foo", 2, 5)]

    def test_shell_else_in_recipe_is_not_a_branch(self):
        """A recipe line goes to the shell (GNU 2893-2905), so its 'else'
        does not start a branch: both rules are in the same branch."""
        lines = ["ifeq ($(A),1)", "foo:", T + "if true; then " + BS]
        lines += [T + "  echo a; " + BS, T + "else " + BS, T + "  echo b; " + BS]
        lines += [T + "fi", "foo:", T + "@echo c", "endif"]
        assert _rule_errors(lines) == [_error("foo", 2, 8)]

    def test_recipe_after_endif_of_rule_in_one_branch(self):
        """make reads one branch (GNU 5399-5421): with Y=1 it reads 'bar.x:'
        and not '.PHONY: t2', so the TAB line after 'endif' is a recipe line
        of 'bar.x'."""
        lines = ["ifeq ($(Y),1)", "bar.x:", "else", ".PHONY: t2", "endif"]
        lines += [T + "@echo a", "bar.x:", T + "@echo b"]
        assert _rule_errors(lines) == [_error("bar.x", 2, 7)]

    def test_else_branch_continues_the_rule_before_the_conditional(self):
        """make reads the 'else' branch only when it skipped the first one, so
        the rule context there is the one before 'ifdef' (GNU 5345-5358)."""
        lines = ["all:", "ifdef VERBOSE", "V = 1", "else", T + "@echo quiet"]
        lines += ["endif", "all:", T + "@echo b"]
        assert _rule_errors(lines) == [_error("all", 1, 7)]

    def test_unconditional_recipe_overridden_in_each_branch(self):
        """Whichever branch make reads overrides the recipe of line 1."""
        lines = ["foo:", T + "@echo a", "ifeq ($(X),1)", "foo:", T + "@echo b"]
        lines += ["else", "foo:", T + "@echo c", "endif"]
        assert _rule_errors(lines) == [_error("foo", 1, 4), _error("foo", 1, 7)]

    @pytest.mark.parametrize(
        "lines",
        [
            ["build: main.o", "ifdef DEBUG", "build: debug-deps", "endif"]
            + [T + "@echo cc -o build main.o"],
            ["test: build", "ifeq ($(COVERAGE),1)", "test: coverage-deps"]
            + [T + "@echo pytest --cov", "else", T + "@echo pytest", "endif"],
            ["install: all", "ifneq ($(PREFIX),/usr)", "install: check-prefix"]
            + ["endif", T + "@echo installing"],
            ["install : all", "ifneq ($(PREFIX),/usr)", "install : check-prefix"]
            + ["endif", T + "@echo installing"],
            ["foo: dep", "ifeq ($(B),1)", "foo: ; @echo i2", "else"]
            + [T + "@echo r5", "endif"],
        ],
    )
    def test_each_reading_has_one_recipe(self, lines):
        """The recipe line after 'endif' or in the 'else' branch belongs to
        the rule whose rule context the branch that make read left open: the
        rule of the branch when make reads it, else the rule before the
        conditional (GNU 5345-5358, 5399-5421). No reading has two recipes,
        so make warns about none (issue #106 in a conditional)."""
        assert _rule_errors(lines) == []
        assert _duplicate_errors(lines) == []

    def test_override_of_a_recipe_read_in_one_branch(self):
        """Line 6 overrides the recipe of line 5, which belongs to line 3
        with DEBUG set and to line 1 without; the latest rule that may have
        it is named (GNU 2550-2552)."""
        lines = ["build: main.o", "ifdef DEBUG", "build: debug-deps", "endif"]
        lines += [T + "@echo cc", "build:", T + "@echo again"]
        assert _rule_errors(lines) == [_error("build", 3, 6)]

    def test_many_conditionals_after_a_rule(self):
        """Each conditional can double the ways a rule context is open; their
        number stays bounded, and a recipe after them still counts."""
        lines = ["all: x"]
        for number in range(40):
            lines += [f"ifdef A{number}", f"ifdef B{number}", f"V{number} = 1"]
            lines += ["endif", "endif"]
        lines += [T + "@echo a", "all:", T + "@echo b"]
        start = time.perf_counter()
        errors = _rule_errors(lines)
        assert time.perf_counter() - start < 10
        assert errors == [_error("all", 1, len(lines) - 1)]

    @pytest.mark.parametrize("same_target", [False, True])
    def test_long_runs_of_conditionals_stay_fast(self, same_target):
        """A conditional without 'else' after a rule keeps the rule context
        open in the readings that take none of its branches (GNU 2881-2886,
        5315-5333). 2000 of them in a row once took minutes."""
        lines = ["CC ?= cc"]
        for number in range(2000):
            target = "prog" if same_target else f"prog{number}"
            lines += [f"ifneq ($(filter p{number},$(PROGRAMS)),)", f"{target}: a.o"]
            lines += [T + "$(CC) -o $@ $^", "endif"]
        start = time.perf_counter()
        _rule_errors(lines)
        assert time.perf_counter() - start < 30


class TestBoundedReadings:
    """The readings that the scan keeps for a rule are bounded; the bound may
    only lose a report, never add one."""

    def test_many_branches_between_a_rule_and_a_recipe_line(self):
        """The TAB line after the conditionals belongs to the second 'foo:'
        only where A1 and B1 are set, and then to no other rule with a
        recipe; make 3.81 and 4.4.1 never warn here (GNU 2550-2552)."""
        lines = ["foo:", "ifdef A1", "ifdef B1", "foo:", "endif", "else"]
        lines += ["ifdef C1", "V = 1", "endif", "endif"]
        for number in range(2, 7):
            lines += [f"ifdef A{number}", f"ifdef B{number}", "V = 1", "endif"]
            lines += ["else", f"ifdef C{number}", "V = 1", "endif", "endif"]
        lines.append(T + "@echo shared")
        assert _rule_errors(lines) == []


class TestTargetsWithReferences:
    """make expands the targets of a rule when it reads the rule (GNU
    1193-1203), so the same text may name different files."""

    def test_reassigned_variable_names_another_target(self):
        """make 3.81 and 4.4.1 run both recipes without a warning."""
        lines = ["DIR = build/debug", "$(DIR)/app: main.c", T + "@echo debug $@"]
        lines += ["DIR = build/release", "$(DIR)/app: main.c"]
        lines.append(T + "@echo release $@")
        assert _rule_errors(lines) == []

    def test_same_value_is_still_an_override(self):
        """Without an assignment between them, both rules name build/app, and
        make warns about the second recipe (GNU 2550-2552)."""
        lines = ["DIR = build", "$(DIR)/app: main.c", T + "@echo one"]
        lines += ["$(DIR)/app: main.c", T + "@echo two"]
        assert _rule_errors(lines) == [_error("$(DIR)/app", 2, 4)]


class TestFormatterConsistency:
    """A line counts as a recipe line exactly when the formatter makes it one."""

    @pytest.mark.parametrize(
        ("lines", "setting", "target"),
        [
            (
                ["ifeq ($(Y),1)", "bar.x:", "else", ".PHONY: t2", "endif"]
                + [T + "@echo a", "bar.x:", T + "@echo b"],
                ("Y=1",),
                "bar.x",
            ),
            (
                ["all:", "ifdef VERBOSE", "V = 1", "else", T + "@echo quiet"]
                + ["endif", "all:", T + "@echo b"],
                (),
                "all",
            ),
        ],
    )
    def test_overrides_through_branches(
        self, gnu_make, tmp_path, lines, setting, target
    ):
        """make reads one branch of a conditional (GNU 5399-5421); in the
        reading of the setting, it overrides the recipe of the target, which
        the rule reports."""
        warned = {
            name for name, _, _ in _make_warnings(gnu_make, tmp_path, lines, setting)
        }
        assert target in warned
        assert [error.split("'")[1] for error in _rule_errors(lines)] == [target]

    @pytest.mark.parametrize(
        "lines",
        [
            ["foo:", "    @echo a", "foo:", "    @echo b"],
            ["foo:", "echo a", "foo:", "echo b"],
            ["foo : a", T + "@echo a", "foo : b", T + "@echo b"],
            ["foo:", T, "foo:", T + "@echo b"],
        ],
    )
    def test_diagnostics_identical_before_and_after_formatting(self, lines):
        """TabsRule and RecipeValidationRule add the TABs, TargetSpacingRule
        removes the space before ':' (GNU 1488, 2878-2881), and the TAB-only
        line stays an empty recipe (2890-2891)."""
        formatter = _formatter()
        formatted, errors, _ = formatter.format_lines(lines)
        _, errors_after, _ = _formatter().format_lines(formatted)
        assert errors == [_error("foo", 1, 3)]
        assert errors_after == errors

    def test_unrepaired_lines_are_not_recipes(self):
        """With fix_missing_recipe_tabs off, 'echo a' keeps its column and
        make never reads it as a recipe line."""
        lines = ["foo:", "echo a", "foo:", "echo b"]
        assert _rule_errors(lines, fix_missing_recipe_tabs=False) == []
        assert _duplicate_errors(lines, fix_missing_recipe_tabs=False) == []

    @pytest.mark.parametrize("line", ["    $(call setup)", "  sinclude x.mk"])
    def test_space_led_lines_follow_tabs_rule(self, line):
        """The line is a recipe exactly when TabsRule.converts_to_recipe makes
        it one, and the errors stay the same after formatting."""
        lines = ["foo:", T + "@echo a", "foo:", line]
        converted = TabsRule().converts_to_recipe(line, 3, lines, T)
        expected = [_error("foo", 1, 3)] if converted else []
        assert _rule_errors(lines) == expected
        formatted, errors, _ = _formatter().format_lines(lines)
        assert [error for error in errors if "Duplicate" in error] == expected
        assert _duplicate_errors(formatted) == expected

    @pytest.mark.parametrize(
        "lines",
        [
            ["foo: bar", "foo: baz"],
            ["foo:", T + "@echo a", "foo:", T + "@echo b"],
            ["# bake-format off", "all:", "# bake-format on", "all: ; @x"],
        ],
    )
    def test_rule_never_changes_lines(self, lines):
        result = DuplicateTargetRule().format(list(lines), {})
        assert result.lines == lines
        assert result.changed is False
        assert result.warnings == []
        assert result.check_messages == []


class TestMessages:
    """The message and the Error severity stay as they were."""

    def test_genuine_override_keeps_message_and_severity(self):
        lines = ["foo:", T + "@echo a", "foo:", T + "@echo b"]
        _, errors, _ = _formatter().format_lines(lines)
        assert errors == [_error("foo", 1, 3)]
        _, errors, _ = _formatter(gnu_error_format=False).format_lines(lines)
        [error] = errors
        assert (
            "Duplicate target 'foo' defined at lines 1 and 3. Second definition "
            "will override the first." in error
        )
        assert "(line 3)" in error

    def test_dot_named_override_is_reported(self):
        """make warns for .DEFAULT too (GNU 8441-8447, 11331-11337)."""
        lines = [".DEFAULT:", T + "@echo a", ".DEFAULT:", T + "@echo b"]
        assert _rule_errors(lines) == [_error(".DEFAULT", 1, 3)]

    @pytest.mark.parametrize(
        ("lines", "expected"),
        [
            (
                ["foo: CFLAGS = -g", "foo:", T + "@echo a", "foo:", T + "@echo b"],
                [_error("foo", 2, 4)],
            ),
            (
                ["foo: $(patsubst %.c,%.o,$(SRCS))", T + "@echo a"]
                + ["foo:", T + "@echo b", "foo:", T + "@echo c"],
                [_error("foo", 3, 5)],
            ),
            (
                ["foo : a", T + "@echo a", "foo : b", T + "@echo b"],
                [_error("foo", 1, 3)],
            ),
        ],
    )
    def test_previously_masked_overrides_are_reported(self, lines, expected):
        """make warns about these overrides (GNU 2550-2552)."""
        assert _rule_errors(lines) == expected

    def test_hidden_recipe_lines_count(self):
        """Lines that '# bake-format off' hides are read where they are, and
        the line numbers are those of the file."""
        lines = ["all:", "# bake-format off", T + "@echo hidden", "# bake-format on"]
        lines += ["all:", T + "@echo b"]
        assert _duplicate_errors(lines) == [_error("all", 1, 5)]

    def test_hidden_rules_are_not_compared(self):
        """A hidden rule has no line to report."""
        lines = ["# bake-format off", "all:", T + "@echo a", "# bake-format on"]
        lines += ["all:", T + "@echo b"]
        assert _duplicate_errors(lines) == []

    @pytest.mark.parametrize("fix_missing_recipe_tabs", [True, False])
    def test_hidden_recipeprefix(self, fix_missing_recipe_tabs):
        """A .RECIPEPREFIX in a disabled region sets the prefix of the lines
        after it (GNU 5158-5169)."""
        lines = ["# bake-format off", ".RECIPEPREFIX = >", "# bake-format on"]
        lines += ["all:", ">@echo a", "all:", ">@echo b"]
        config = {"fix_missing_recipe_tabs": fix_missing_recipe_tabs}
        assert _duplicate_errors(lines, **config) == [_error("all", 4, 6)]


# The S4 reproducers of '.RECIPEPREFIX +=', which RecipeValidationRule read
# with a TAB prefix: '>' on the first run, '\t>' on the second, wherever the
# whitespace after the backslash of 'VPATH = src \ ' was kept.
S41F358 = (
    "R = $(1): ; @echo rule $(1)\nEMPTY =\n\t\t \nX = $(Y) \nVPATH = src   # c\n"
    ".RECIPEPREFIX += >\n$(info hi)\nVPATH = src \\ \nt5::\n>@echo r\n>\n\t \n\t\n"
)
S41F358_SHAPE = ".RECIPEPREFIX += >\nVPATH = src " + BS + " \nt5::\n>@echo r\n>\n"

# The configurations under which those reproducers were not idempotent. They
# keep the whitespace after the backslash, so it does not continue the line
# (GNU 762-769).
_KEEP_WHITESPACE_CONFIGS = {
    "keepws": {"remove_trailing_whitespace": False, "normalize_empty_lines": False},
    "keepws_align": {
        "remove_trailing_whitespace": False,
        "normalize_empty_lines": False,
        "align_variable_assignments": True,
    },
    "keeptrail_indent2": {
        "remove_trailing_whitespace": False,
        "indent_nested_conditionals": True,
        "tab_width": 2,
    },
    "keeptrail_group_top": {
        "remove_trailing_whitespace": False,
        "auto_insert_phony_declarations": True,
        "group_phony_declarations": True,
        "phony_at_top": False,
    },
}
_PREFIX_CONFIGS = {"default": {}, **_KEEP_WHITESPACE_CONFIGS}

# Makefiles that set the recipe prefix in a way that the line-by-line reading
# of the rules missed: on a line that '# bake-format off' hides, with '+=',
# with a value that make computes, and with define (GNU 1126-1181,
# 4588-4592, 4795-4821, 5158-5169). Each has one recipe line that starts with
# the prefix.
_PREFIX_FORMS = {
    "hidden": "# bake-format off\n.RECIPEPREFIX = >\n# bake-format on\nall:\n"
    ">@echo a\n",
    "append": ".RECIPEPREFIX += >\nall:\n>@echo a\n",
    "recursive_reference": "GT := >\n.RECIPEPREFIX = $(GT)\nall:\n$@echo a\n",
    "simple_dollar": ".RECIPEPREFIX := $$\nall:\n$@echo a\n",
    "define": "define .RECIPEPREFIX\n>\nendef\nall:\n>@echo a\n",
}


# make runs the command of '!=' when it reads the line (GNU 1126-1181), so
# the recipe prefix after it is not known before; with SHELL=true the value
# is empty, and the TAB is the prefix again.
_COMPUTED_PREFIX = (
    "%.x: ; @echo implicit $@\n.RECIPEPREFIX = >\n\n.RECIPEPREFIX := $$\n"
    "R = r1: ; @echo r1\n.RECIPEPREFIX != echo '>'\nfoo.x:\nall: t1 t2\n"
    + T
    + "# c\n$ \nt3:: ; @:\n"
)


def _recipe_line(text):
    """Return the last line of text, the recipe line of _PREFIX_FORMS."""
    return text.splitlines()[-1]


def _lines_and_hidden(text):
    """Split text as the formatter does for rules: the lines they see, and
    the lines that '# bake-format off' hides after each such line."""
    lines, hidden, off = [], {}, None
    for line in text.splitlines():
        if line == "# bake-format on":
            off = None
        elif off is not None:
            hidden[off].append(line)
            continue
        lines.append(line)
        if line == "# bake-format off":
            off = len(lines) - 1
            hidden[off] = []
    return lines, hidden


class TestRecipePrefixReading:
    """RecipeValidationRule and TabsRule read the recipe prefix line by line,
    as before, also where the makefile sets it in a way that this reading
    misses (GNU 5158-5169); their output there stays as it was, and a second
    run changes nothing. DuplicateTargetRule reads make's prefix for its own
    reports."""

    @pytest.mark.parametrize("form", sorted(_PREFIX_FORMS))
    def test_prefix_is_not_read_while_phony_lines_may_move(self, form):
        """With auto_insert_phony_declarations, PhonyRule may put a .PHONY
        line above a line that starts with the prefix, which then becomes
        its recipe line (GNU 2878-2884); a second run changes nothing."""
        config = _KEEP_WHITESPACE_CONFIGS["keeptrail_group_top"]
        text = _PREFIX_FORMS[form]
        first = _formatter(**config).format(text).content
        assert _formatter(**config).format(first).content == first

    @pytest.mark.parametrize("text", [S41F358, S41F358_SHAPE])
    def test_append_reproducers_when_whitespace_is_removed(self, text):
        """WhitespaceRule removes the whitespace after the backslash, so
        'VPATH = src \\' continues onto 't5::' (GNU 762-769); a second run
        changes nothing."""
        first = _formatter().format(text).content
        assert _formatter().format(first).content == first

    @pytest.mark.parametrize("config", sorted(_PREFIX_CONFIGS))
    @pytest.mark.parametrize(
        "text",
        [
            # ':=' expands '$$' to '$', the recipe prefix (GNU 4588-4592,
            # 5158-5169)
            ".RECIPEPREFIX = >\n.RECIPEPREFIX := $$$$\nall:\n> a\n> b\n",
            ".RECIPEPREFIX = >\n.RECIPEPREFIX =\n.RECIPEPREFIX := $$\nfoo.x:\n"
            "> @echo c\n> @echo c\n",
            # An empty value makes the TAB the prefix again (GNU 5158-5169)
            ".RECIPEPREFIX = >\n.RECIPEPREFIX =\nall:\n>@echo a\n>@echo b\n",
        ],
    )
    def test_lines_of_an_earlier_prefix_get_no_tab(self, text, config):
        """'> a' starts with a recipe prefix that a later assignment
        replaced, so make reads it as makefile syntax. A TAB would make it a
        recipe line with the command '> a', so RecipeValidationRule leaves it
        as it did when it read '>' as the prefix; reading make's prefix
        without this, it added a TAB to one more line on each run."""
        result = _formatter(**_PREFIX_CONFIGS[config]).format(text)
        assert [line for line in result.content.splitlines() if "\t" in line] == []
        again = _formatter(**_PREFIX_CONFIGS[config]).format(result.content)
        assert again.content == result.content
        _, _, messages = _formatter(**_PREFIX_CONFIGS[config]).format_lines(
            text.splitlines(), True, text
        )
        assert not any("Missing required tab separator" in m for m in messages)

    @pytest.mark.parametrize("config", sorted(_PREFIX_CONFIGS))
    @pytest.mark.parametrize(
        "text",
        [
            "ifdef Y\nbaz: dep\n.RECIPEPREFIX = >\nbar:\n>@echo d\nendif\n",
            "ifdef Y\nbaz: dep\n.RECIPEPREFIX = >\nbar:\n\t@echo d\nendif\n",
        ],
    )
    def test_plain_recipeprefix_assignment_is_stable(self, text, config):
        """Where the line-by-line reading of '.RECIPEPREFIX = >' agrees with
        make, the rules work as before; a second run changes nothing."""
        first = _formatter(**_PREFIX_CONFIGS[config]).format(text).content
        again = _formatter(**_PREFIX_CONFIGS[config]).format(first).content
        assert again == first

    @pytest.mark.parametrize("config", sorted(_PREFIX_CONFIGS))
    def test_computed_prefix_output_is_idempotent(self, config):
        """Where make computes the prefix, the rules keep their reading of
        before; a second run changes nothing."""
        first = _formatter(**_PREFIX_CONFIGS[config]).format(_COMPUTED_PREFIX)
        again = _formatter(**_PREFIX_CONFIGS[config]).format(first.content)
        assert again.content == first.content

    def test_space_prefix_recipes_are_compared(self):
        lines = ["define .RECIPEPREFIX", "  >", "endef", "all:", "  @echo a"]
        assert _rule_errors(lines + ["all: x"]) == []
        assert _rule_errors(lines + ["all:", "  @echo b"]) == [_error("all", 4, 6)]


# Makefiles in which other rules move or join lines around a recipe line that
# starts with a recipe prefix other than the TAB, the configurations that do
# so, and whether make 4.x accepts both the makefile and its formatted lines.
# The formatter reads the prefix line by line there, as before. Reading make's
# prefix, it was not idempotent on these, or gave makefiles that make
# rejects.
_MOVED_PREFIX_LINES = {
    # PhonyRule would insert '.PHONY: test' above '>@echo build', the recipe
    # of the rule hidden in the region, if the rules read make's prefix. With
    # auto_insert_phony_declarations the rules keep their reading of before,
    # whose output gmake rejects as before (an S9 hand-off), but is stable.
    "phony_above_a_hidden_rule": (
        "# Project makefile\n# bake-format off\n.RECIPEPREFIX = >\nbuild:\n"
        "# bake-format on\n>@echo build\ntest:\n>@echo test\n",
        ["auto_group_top", "auto_group_after", "reporter107", "keeptrail_group_top"],
        False,
    ),
    "phony_above_a_hidden_rule_with_append": (
        ".RECIPEPREFIX += >\n# bake-format off\nall:\n# bake-format on\n"
        ">@echo a\nclean:\n>@echo clean\n",
        ["auto_group_top", "auto_group_after", "reporter107", "keeptrail_group_top"],
        False,
    ),
    # PhonyRule's order of the targets it detects depends on the hash seed
    "two_phony_targets_with_append": (
        ".RECIPEPREFIX += >\nclean:\n>@echo clean\ntest:\n>@echo test\n",
        ["auto_group_top", "auto_group_after", "reporter107", "keeptrail_group_top"],
        False,
    ),
    # WhitespaceRule makes the FLAGS line continue onto 'foo.x:'
    "whitespace_joins_the_rule_line": (
        "GT := >\n%.x: ; @echo implicit $@\n.RECIPEPREFIX := $$\n"
        "FLAGS := -O2 -g " + BS + " \nfoo.x:\n$(R)\n" + T + "\n",
        ["default", "indent2", "indent4", "auto_group_top", "reporter107"],
        True,
    ),
    # PhonyRule moves '.PHONY: t1 t2', which owns '$(R)', to the top
    "phony_line_with_a_recipe_moves": (
        "GT := >\n%.x: ; @echo implicit $@\n.PHONY: t1\n" + T + "@:\n"
        "foo.x bar.x:\n" + T + " \n\n.RECIPEPREFIX = $(GT)\n.PHONY: t1 t2\n"
        "$(R)\nifndef X\nt1: ; @:\nall: t1 t2\nall: t1 t2\nendif\n\n",
        ["auto_group_top", "keeptrail_group_top", "reporter107"],
        True,
    ),
    "phony_line_with_a_dollar_line_moves": (
        ".RECIPEPREFIX = $(P)\n%.x: ; @echo implicit $@\nR = rr.x:\n"
        "define .RECIPEPREFIX :=\n$(P)\nendef\ndefine .RECIPEPREFIX :=\n$(P)\n"
        "endef\n# c\n# c\nifndef Z\n.PHONY: t1 t2\n$(R)\nbaz:\n.PHONY: t1 t2\n"
        "\nendif\nt2: ; @:\nt1: ; @:\n",
        ["reporter107"],
        False,
    ),
    "phony_line_with_a_gt_line_moves": (
        "%.x: ; @echo implicit $@\nR = rr.x:\nbaz:\n.RECIPEPREFIX += >\n"
        "# bake-format off\n.RECIPEPREFIX = >\n# bake-format on\n.PHONY: t1 t2\n"
        "ifdef Y\n>\n$ \nendif\nt1: ; @:\n",
        ["reporter107"],
        True,
    ),
    # PhonyRule would move the '.PHONY' line out of the 'else' branch
    "conditional_phony_line": (
        "define .RECIPEPREFIX :=\n$(P)\nendef\n%.x: ; @echo implicit $@\n"
        "R = rr.x:\nfoo.x:\nifndef Z\nelse\n.RECIPEPREFIX =\n$@echo c\n"
        ".RECIPEPREFIX += >\n.PHONY: t1 t2\n" + T + "@echo c\n \nendif\n"
        "t1: ; @:\n",
        ["indent2", "indent4", "reporter107"],
        True,
    ),
    # A last line of only whitespace with ensure_final_newline off
    "whitespace_last_line": (
        "%.x: ; @echo implicit $@\nW = a " + BS + "\nfoo.x:\n"
        ".PHONY: t1 t2 t3\n.RECIPEPREFIX += >\nt4::\n>@echo r\n"
        ".PHONY: t2\n" + T + "@echo c\nifndef X\nendif\n" + T + "# tc\n"
        "foo.x bar.x:\nifdef X\nendif\n" + T + "\n",
        ["conservative"],
        False,
    ),
    # A backslash and whitespace before a define in a conditional
    "dangling_backslash_before_define": (
        "%.x: ; @echo implicit $@\nV = src " + BS + " \nY = 1\n"
        ".PHONY: t1\nifeq ($(X),1)\n"
        + T
        + "Y = z "
        + BS
        + " \n"
        + T
        + "@echo c\nt5.x:\nt1: ; @:\n"
        + T
        + "Y = z "
        + BS
        + " \n$(info i)\n.PHONY: t1\ndefine E "
        + BS
        + " \n.RECIPEPREFIX = >\nendif\n",
        ["indent2", "indent4"],
        False,
    ),
    # A define of .RECIPEPREFIX whose body starts with spaces
    "space_prefix_define": (
        "%.x: ; @echo implicit $@\n" + T + "\nifndef X\n"
        ".RECIPEPREFIX := $(GT)\n$(R)\n>@echo r\ndefine D\nfoo.x:\nendef\n"
        + T
        + "\n.PHONY: t1\n.PHONY: t1 t2\n.RECIPEPREFIX =\nelse\n"
        "define .RECIPEPREFIX\n  >\nendef\nt1:\n$\n" + T + "# tc\n"
        ".RECIPEPREFIX = $(GT)\nt1: ; @:\n \nendif\n" + T + "\n",
        ["indent2", "indent4", "keeptrail_indent2", "reporter107"],
        False,
    ),
}

_MOVED_CONFIGS = {
    "default": {},
    "conservative": {
        "auto_insert_phony_declarations": False,
        "ensure_final_newline": False,
        "group_phony_declarations": False,
        "phony_at_top": False,
    },
    "indent2": {"indent_nested_conditionals": True, "tab_width": 2},
    "indent4": {"indent_nested_conditionals": True, "tab_width": 4},
    "keeptrail_indent2": {
        "remove_trailing_whitespace": False,
        "indent_nested_conditionals": True,
        "tab_width": 2,
    },
    "auto_group_top": {
        "auto_insert_phony_declarations": True,
        "group_phony_declarations": True,
        "phony_at_top": False,
    },
    "keeptrail_group_top": _KEEP_WHITESPACE_CONFIGS["keeptrail_group_top"],
    "reporter107": {
        "auto_insert_phony_declarations": True,
        "group_phony_declarations": True,
        "phony_at_top": False,
        "indent_nested_conditionals": True,
        "tab_width": 4,
    },
    "auto_group_after": {
        "auto_insert_phony_declarations": True,
        "group_phony_declarations": True,
        "phony_at_top": True,
    },
}


def _moved_cases(accepted_only=False):
    return [
        (name, config)
        for name, (_, configs, accepted) in sorted(_MOVED_PREFIX_LINES.items())
        if accepted or not accepted_only
        for config in configs
    ]


class TestPrefixLinesThatOtherRulesMove:
    """make reads a line that starts with the recipe prefix as a recipe line
    only in a rule context, and only while the line that sets the prefix is
    makefile syntax (GNU 2878-2884, 5158-5169). Where other rules may change
    that, formatting stays idempotent."""

    @pytest.mark.parametrize(("name", "config"), _moved_cases())
    def test_formatting_is_idempotent(self, name, config):
        text = _MOVED_PREFIX_LINES[name][0]
        first = _formatter(**_MOVED_CONFIGS[config]).format(text).content
        again = _formatter(**_MOVED_CONFIGS[config]).format(first).content
        assert again == first

    @pytest.mark.parametrize("config", ["auto_group_top", "reporter107"])
    def test_output_does_not_depend_on_the_hash_seed(self, config, tmp_path):
        """The same output for every PYTHONHASHSEED, as before this change."""
        path = tmp_path / "Makefile"
        text = _MOVED_PREFIX_LINES["two_phony_targets_with_append"][0]
        script = (
            "import sys\n"
            "from mbake.config import Config, FormatterConfig\n"
            "from mbake.core.formatter import MakefileFormatter\n"
            f"config = {_MOVED_CONFIGS[config]!r}\n"
            "formatter = MakefileFormatter(Config(formatter=FormatterConfig(**config)))\n"
            "sys.stdout.write(formatter.format(open(sys.argv[1]).read()).content)\n"
        )
        path.write_text(text)
        outputs = set()
        for seed in range(4):
            env = {**os.environ, "PYTHONHASHSEED": str(seed)}
            proc = subprocess.run(
                [sys.executable, "-c", script, str(path)],
                capture_output=True,
                text=True,
                timeout=60,
                env=env,
            )
            assert proc.returncode == 0, proc.stderr
            outputs.add(proc.stdout)
        assert len(outputs) == 1

    def test_conditional_phony_line_keeps_its_branch(self):
        """make reads '.PHONY: t1 t2' only in the 'else' branch (GNU
        5399-5421), and with indent_nested_conditionals it stays there."""
        text = _MOVED_PREFIX_LINES["conditional_phony_line"][0]
        config = _MOVED_CONFIGS["reporter107"]
        lines = _formatter(**config).format(text).content.splitlines()
        assert (
            lines.index("else") < lines.index(".PHONY: t1 t2") < (lines.index("endif"))
        )


class TestTabsRuleConversion:
    """TabsRule.converts_to_recipe is the decision of TabsRule.format."""

    @pytest.mark.parametrize(
        "text",
        [
            "foo:\n    @echo a\n  ifdef X\n    $(call setup)\n  endif\n"
            "  sinclude x.mk\n  X = 1\n    echo b\n  # c\n",
            ".RECIPEPREFIX += >\nfoo:\n>@echo a\n    echo b\n  .RECIPEPREFIX = <\n",
            "# bake-format off\n.RECIPEPREFIX = >\n# bake-format on\nfoo:\n"
            "    echo b\n>@echo c\n",
            "X = a " + BS + "\n    b\nfoo:\n    echo c\n",
        ],
    )
    def test_converts_exactly_the_lines_that_format_converts(self, text):
        """format() gives a TAB to exactly the lines with leading spaces that
        converts_to_recipe accepts, with the prefixes that format() reads."""
        lines, hidden = _lines_and_hidden(text)
        rule = TabsRule()
        prefixes = rule_context.line_by_line_prefixes(lines)
        result = rule.format(list(lines), {}, disabled_region_lines=hidden)
        for index, line in enumerate(lines):
            if not line.startswith(" "):
                continue
            converted = rule.converts_to_recipe(line, index, lines, prefixes[index])
            assert result.lines[index].startswith(T) == converted, line
            if converted:
                assert result.lines[index] == T + line.lstrip()


class TestParsingHelpers:
    """The shared helpers that DuplicateTargetRule uses."""

    @pytest.mark.parametrize(
        ("code", "expected"),
        [
            ("if DEBUG", True),
            ("  if !DEBUG ", True),
            ("ifdef DEBUG", False),
            ("if a b", False),
            ("iff X", False),
        ],
    )
    def test_is_automake_conditional(self, code, expected):
        assert rule_context.is_automake_conditional(code) is expected

    @pytest.mark.parametrize(
        ("backslashes", "expected"),
        [(0, False), (1, True), (2, False), (3, False), (4, False), (5, True)],
    )
    def test_has_semicolon_on_second_scan(self, backslashes, expected):
        """GNU 730-737: each scan removes half of the backslashes before ';'."""
        text = "a" + BS * backslashes + ";b"
        assert LineUtils.has_semicolon_on_second_scan(text) is expected
        assert (
            LineUtils.has_semicolon_on_second_scan("$(subst " + BS + ";,x,y)") is False
        )


class TestRecipePrefixHelpers:
    """recipe_prefixes reads the lines with scan_makefile, and
    line_by_line_prefixes gives the prefixes that the rules read."""

    def test_recipe_prefixes_without_recipeprefix(self):
        lines = ["all:", "\t@echo a", "X = 1", "  y"]
        assert rule_context.recipe_prefixes(lines) == [T] * 4

    @pytest.mark.parametrize(
        ("lines", "hidden"),
        [
            ([".RECIPEPREFIX += >", "all:", ">@echo a"], None),
            ([".RECIPEPREFIX = >", ".RECIPEPREFIX =", "all:", T + "@echo a"], None),
            (["define .RECIPEPREFIX", "  >", "endef", "all:", "  @echo a"], None),
            (["GT := >", ".RECIPEPREFIX = $(GT)", "all:", "$@echo a"], None),
            (["# bake-format off", "# bake-format on", "all:", ">@echo a"], {}),
            (
                ["# bake-format off", "# bake-format on", "all:", ">@echo a"],
                {0: [".RECIPEPREFIX = >"]},
            ),
        ],
    )
    def test_recipe_prefixes_are_those_of_scan_makefile(self, lines, hidden):
        expected = [
            state.recipe_prefix for state in rule_context.scan_makefile(lines, hidden)
        ]
        assert rule_context.recipe_prefixes(lines, hidden) == expected

    def test_recipe_prefixes_follow_append_and_hidden_lines(self):
        """'+=' gives an empty .RECIPEPREFIX its first character, and hidden
        lines count where they are (GNU 4657-4659, 5158-5169)."""
        assert rule_context.recipe_prefixes(
            [".RECIPEPREFIX += >", "all:", ">@echo a"]
        ) == [
            T,
            ">",
            ">",
        ]
        lines = ["# bake-format off", "# bake-format on", "all:", ">@echo a"]
        hidden = {0: [".RECIPEPREFIX = >"]}
        assert rule_context.recipe_prefixes(lines, hidden) == [T, ">", ">", ">"]

    def test_line_by_line_prefixes(self):
        """The reading of LineUtils.get_active_recipe_prefix, in one pass."""
        lines = [".RECIPEPREFIX = >", "all:", ".RECIPEPREFIX =", "  .RECIPEPREFIX := @"]
        lines += ["x", ".RECIPEPREFIX = " + T, "y", ".RECIPEPREFIX = $(GT)", "z"]
        lines += ["define .RECIPEPREFIX", ".RECIPEPREFIX := \0", "w"]
        lines += [".RECIPEPREFIX = \1", "v", ".RECIPEPREFIX += <", "u"]
        assert rule_context.line_by_line_prefixes(lines) == [
            LineUtils.get_active_recipe_prefix(lines, index)
            for index in range(len(lines))
        ]


# make runs with a minimal environment so that no inherited variable (such as
# MAKEFLAGS) changes what it reads.
_MAKE_ENV = {"PATH": os.defpath, "LC_ALL": "C"}
_GOAL = "__mbake_test_goal__"


@pytest.fixture(scope="module", params=["make", "gmake"])
def gnu_make(request):
    """Return (make, true, major version), or skip when that GNU make cannot
    run here.

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
    match = re.match(r"GNU Make (\d+)\.", version)
    if "GNU Make" not in version or match is None:
        pytest.skip("make is not GNU make")
    return make, true, int(match.group(1))


_DIRECTIVES = ("ifeq", "ifneq", "ifdef", "ifndef", "else", "endif")


def _holds(words, settings):
    """Evaluate a conditional directive of the forms these tests use:
    'ifdef V', 'ifndef V', 'ifeq ($(V),x)' and 'ifneq ($(V),x)'."""
    values = dict(setting.split("=", 1) for setting in settings)
    if words[0] in ("ifdef", "ifndef"):
        return bool(values.get(words[1])) == (words[0] == "ifdef")
    match = re.fullmatch(r"\(\$\((\w+)\),(.*)\)", "".join(words[1:]))
    assert match is not None, words
    return (values.get(match.group(1), "") == match.group(2)) == (words[0] == "ifeq")


def _read_lines(lines, settings):
    """Return, for each line, whether make reads it with the settings (GNU
    5399-5421). Recipe lines are never directives in these tests."""
    read = []
    # (whether make reads the current branch, whether it took a branch)
    stack = []
    for line in lines:
        read.append(all(reading for reading, _ in stack))
        words = [] if line.startswith("\t") else line.split("#")[0].split()
        if words and words[0] in _DIRECTIVES[:4]:
            reading = read[-1] and _holds(words, settings)
            stack.append((reading, reading))
        elif words and words[0] == "else" and stack:
            _, taken = stack.pop()
            outer = all(reading for reading, _ in stack)
            reading = outer and not taken
            if reading and len(words) > 1:
                reading = _holds(words[1:], settings)
            stack.append((reading, taken or reading))
        elif words and words[0] == "endif" and stack:
            stack.pop()
    return read


def _owner(lines, number, read):
    """Return the line number of the rule whose recipe starts at line number.

    make names the first line of each recipe: the rule line for an inline
    recipe, else the first recipe line. Only blank lines, comments and
    conditional directives come between a rule line and its first recipe
    line here, among the lines that make reads (read, see _read_lines).
    """
    index = number - 1
    if not lines[index].startswith(("\t", ">")):
        return number
    index -= 1
    while index > 0 and (
        not read[index]
        or not lines[index].strip()
        or lines[index].startswith("#")
        or lines[index].split()[0] in _DIRECTIVES
    ):
        index -= 1
    return index + 1


def _make_warnings(gnu_make, tmp_path, lines, settings):
    """Return (target, overriding line, overridden line) for each override
    that make warns about, with the lines of the recipes as make names them."""
    make, true, _ = gnu_make
    (tmp_path / "input.mk").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (tmp_path / "goal.mk").write_text(f"{_GOAL}: ;\n", encoding="utf-8")
    proc = subprocess.run(
        [make, "-r", "-R", "-n", "-f", "input.mk", "-f", "goal.mk"]
        + [f"SHELL={true}", *settings, _GOAL],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        env=_MAKE_ENV,
    )
    assert proc.returncode == 0, proc.stderr
    warnings = []
    overriding = None
    pattern = re.compile(
        r"input\.mk:(\d+): warning: (overriding|ignoring old) "
        r"(?:recipe|commands) for target [`'](.*)'"
    )
    for line in proc.stderr.splitlines():
        match = pattern.match(line)
        if match is None:
            continue
        if match.group(2) == "overriding":
            overriding = int(match.group(1))
        else:
            warnings.append((match.group(3), overriding, int(match.group(1))))
    return warnings


def _make_overrides(gnu_make, tmp_path, lines, settings):
    """Return the (overridden rule, overriding rule) line pairs make warns about."""
    read = _read_lines(lines, settings)
    return [
        (_owner(lines, old, read), _owner(lines, new, read))
        for _, new, old in _make_warnings(gnu_make, tmp_path, lines, settings)
    ]


def _rule_pairs(lines):
    """Return the (first, second) line pairs of the rule's errors."""
    pairs = []
    for error in _rule_errors(lines):
        match = re.search(r"defined at lines (\d+) and (\d+)\.", error)
        assert match is not None, error
        pairs.append((int(match.group(1)), int(match.group(2))))
    return pairs


_SAME_AS_MAKE = {
    "prerequisites": (["foo: bar", "foo: baz", "bar baz: ;"], [()]),
    "target_variable": (["foo: bar = 1", "foo: baz", "baz: ;"], [()]),
    "special_target": ([".PRECIOUS: a", ".PRECIOUS: b"], [()]),
    "reassignment": (["FOO:=a", "FOO:=b"], [()]),
    "recipe_then_prerequisite": (["foo:", T + "@echo a", "foo: bar", "bar: ;"], [()]),
    "override": (["foo:", T + "@echo a", "foo:", T + "@echo b"], [()]),
    "empty_recipe": (["foo:", T, "foo:", T + "@echo b"], [()]),
    "inline": (["foo: ; @echo a", "foo: ; @echo b"], [()]),
    "empty_inline": (["foo: ;", "foo:", T + "@echo b"], [()]),
    "across_prerequisite_rule": (
        ["foo:", T + "@echo a", "foo: bar", "foo:", T + "@echo b", "bar: ;"],
        [()],
    ),
    "default": ([".DEFAULT:", T + "@echo a", ".DEFAULT:", T + "@echo b"], [()]),
    "after_target_variable": (
        ["foo: CFLAGS = -g", "foo:", T + "@echo a", "foo:", T + "@echo b"],
        [()],
    ),
    "blank_and_comment": (
        ["foo:", "", "# c", T + "@echo a", "foo:", T + "@echo b"],
        [()],
    ),
    "comment_continuation": (
        ["foo:", T + "@echo a", "# c " + BS, "foo:", T + "@echo b"],
        [()],
    ),
    "define_body": (
        ["define TPL", "foo:", T + "@echo a", "endef", "foo:", T + "@echo b"],
        [()],
    ),
    "override_define_body": (
        ["all:", T + "@echo a", "override define MSG", "all:", "endef", "all: ; @x"],
        [()],
    ),
    "modified_define_does_not_nest": (
        ["define OUTER", "override define INNER", "endef"]
        + ["foo:", T + "@echo a", "foo:", T + "@echo b"],
        [()],
    ),
    "eval_line": (["all: x", "$(eval $(call TPL,x))", "all:", T + "@echo b"], [()]),
    "documentation": (["build:", T + "cc -o x x.c", "build: ## Build it"], [()]),
    "double_colon": (
        ["foo:: a", T + "@echo 1", "foo:: b", T + "@echo 2", "a b: ;"],
        [()],
    ),
    "pattern_rules": (["%.o:", T + "@echo a", "%.o:", T + "@echo b"], [()]),
    "space_before_colon": (
        ["foo : a", T + "@echo a", "foo : b", T + "@echo b", "a b: ;"],
        [()],
    ),
    "tab_comment": (["foo:", T + "# c", "foo:", T + "@echo b"], [()]),
    "else_chain": (
        ["ifeq ($(X),a)", "foo:", T + "@echo a", "else ifeq ($(X),b)", "foo:"]
        + [T + "@echo b", "else", "foo:", T + "@echo c", "endif"],
        [(), ("X=a",), ("X=b",)],
    ),
    "conditional_then_unconditional": (
        ["ifeq ($(X),1)", "foo:", T + "@echo a", "endif", "foo:", T + "@echo b"],
        [(), ("X=1",)],
    ),
    "overridden_in_each_branch": (
        ["foo:", T + "@echo a", "ifeq ($(X),1)", "foo:", T + "@echo b", "else"]
        + ["foo:", T + "@echo c", "endif"],
        [(), ("X=1",)],
    ),
    "recipe_in_branches": (
        ["foo:", "ifeq ($(X),1)", T + "@echo a", "else", T + "@echo b", "endif"]
        + ["foo: extra", "extra: ;"],
        [(), ("X=1",)],
    ),
    "shell_else": (
        ["ifeq ($(A),1)", "foo:", T + "if true; then " + BS, T + "  echo a; " + BS]
        + [T + "else " + BS, T + "  echo b; " + BS, T + "fi", "foo:", T + "@echo c"]
        + ["endif"],
        [(), ("A=1",)],
    ),
    "tab_led_else": (
        ["ifeq ($(X),1)", "foo:", T + "@echo a", T + "else", "endif", "foo:"]
        + [T + "@echo c"],
        [(), ("X=1",)],
    ),
    # Issue #106 in a conditional: a recipe line after 'endif' or in an
    # 'else' branch belongs to the rule that the branch make read leaves
    # open, so no reading has two recipes for the target (GNU 5345-5358).
    "prerequisites_in_branch": (
        ["build: main.o", "ifdef DEBUG", "build: debug-deps", "endif"]
        + [T + "@echo cc -o build main.o", "main.o debug-deps: ;"],
        [(), ("DEBUG=1",)],
    ),
    "recipe_in_each_branch": (
        ["test: build", "ifeq ($(COVERAGE),1)", "test: coverage-deps"]
        + [T + "@echo pytest --cov", "else", T + "@echo pytest", "endif"]
        + ["build coverage-deps: ;"],
        [(), ("COVERAGE=1",)],
    ),
    "prerequisites_in_ifneq_branch": (
        ["install: all", "ifneq ($(PREFIX),/usr)", "install: check-prefix"]
        + ["endif", T + "@echo installing", "all check-prefix: ;"],
        [(), ("PREFIX=/usr",)],
    ),
    "prerequisites_in_branch_space_before_colon": (
        ["install : all", "ifneq ($(PREFIX),/usr)", "install : check-prefix"]
        + ["endif", T + "@echo installing", "all check-prefix: ;"],
        [(), ("PREFIX=/usr",)],
    ),
    "inline_recipe_in_branch": (
        ["foo: dep", "ifeq ($(B),1)", "foo: ; @echo i2", "else", T + "@echo r5"]
        + ["endif", "dep: ;"],
        [(), ("B=1",)],
    ),
    "override_after_recipe_of_branch": (
        ["build: main.o", "ifdef DEBUG", "build: debug-deps", "endif", T + "@echo cc"]
        + ["build:", T + "@echo again", "main.o debug-deps: ;"],
        [(), ("DEBUG=1",)],
    ),
    # make scans the prerequisites for ';' again after it removed half of the
    # backslashes (GNU 730-737, 1499-1503).
    "escaped_semicolon_1": (["foo: a" + BS + ";b", "foo:", T + "@echo b"], [()]),
    "escaped_semicolon_3": (["foo: a" + BS * 3 + ";b", "foo:", T + "@echo b"], [()]),
    "escaped_semicolon_5": (["foo: a" + BS * 5 + ";b", "foo:", T + "@echo b"], [()]),
}

# .RECIPEPREFIX needs make 4.x.
_SAME_AS_MAKE_4 = {
    "recipeprefix": (
        [".RECIPEPREFIX = >", "foo:", ">@echo a", "foo:", ">@echo b"],
        [()],
    ),
    "recipeprefix_append": (
        [".RECIPEPREFIX += >", "foo:", ">@echo a", "foo:", ">@echo b"],
        [()],
    ),
    "recipeprefix_append_prerequisite": (
        [".RECIPEPREFIX += >", "foo:", ">@echo a", "foo: bar", "bar: ;"],
        [()],
    ),
}


class TestAgainstGnuMake:
    """The errors name the rules whose recipe make overrides.

    For each rule that overrides a recipe in some reading of make (with any
    of the variable settings), the rule reports an error, for one rule that
    make reads before it in such a reading (GNU 11331-11337). Every error is
    checked, also those that the rule reported before.
    """

    @pytest.mark.parametrize("name", sorted(_SAME_AS_MAKE) + sorted(_SAME_AS_MAKE_4))
    def test_errors_match_make_warnings(self, gnu_make, tmp_path, name):
        if name in _SAME_AS_MAKE_4:
            if gnu_make[2] < 4:
                pytest.skip("make 3.81 has no .RECIPEPREFIX")
            lines, settings = _SAME_AS_MAKE_4[name]
        else:
            lines, settings = _SAME_AS_MAKE[name]
        make_pairs = set()
        for setting in settings:
            make_pairs.update(_make_overrides(gnu_make, tmp_path, lines, setting))
        rule_pairs = _rule_pairs(lines)
        assert {second for _, second in rule_pairs} == {
            second for _, second in make_pairs
        }
        assert set(rule_pairs) <= make_pairs

    @pytest.mark.parametrize(
        "lines",
        [
            ["foo:", "    @echo a", "foo:", "    @echo b"],
            ["foo:", "echo a", "foo:", "echo b"],
            ["foo:", T + "@echo a", "foo:", "    @echo b"],
        ],
    )
    def test_formatted_recipes_match_make_warnings(self, gnu_make, tmp_path, lines):
        """make warns about the formatted lines where the rule reports the
        original ones: the formatter turns these lines into recipe lines."""
        config = {
            "auto_insert_phony_declarations": False,
            "ensure_final_newline": False,
        }
        formatted, _, _ = _formatter(**config).format_lines(lines)
        assert len(formatted) == len(lines)
        assert set(_rule_pairs(lines)) == set(
            _make_overrides(gnu_make, tmp_path, formatted, ())
        )

    def test_computed_prefix_output_stays_accepted(self, gnu_make, tmp_path):
        """make 4.x accepts the formatted makefile as it accepts the input,
        although the prefix after '!=' is not known before make runs."""
        make, true, major = gnu_make
        if major < 4:
            pytest.skip("make 3.81 has no .RECIPEPREFIX")
        formatted = _formatter().format(_COMPUTED_PREFIX).content
        (tmp_path / "goal.mk").write_text(f"{_GOAL}: ;\n", encoding="utf-8")
        for makefile in (_COMPUTED_PREFIX, formatted):
            (tmp_path / "input.mk").write_text(makefile, encoding="utf-8")
            proc = subprocess.run(
                [make, "-r", "-R", "-n", "-f", "input.mk", "-f", "goal.mk"]
                + [f"SHELL={true}", _GOAL],
                cwd=tmp_path,
                capture_output=True,
                text=True,
                timeout=60,
                env=_MAKE_ENV,
            )
            assert proc.returncode == 0, proc.stderr

    @pytest.mark.parametrize(("name", "config"), _moved_cases(accepted_only=True))
    def test_moved_prefix_lines_stay_accepted(self, gnu_make, tmp_path, name, config):
        """make 4.x accepts the formatted makefile as it accepts the input."""
        make, true, major = gnu_make
        if major < 4:
            pytest.skip("make 3.81 has no .RECIPEPREFIX")
        text = _MOVED_PREFIX_LINES[name][0]
        formatted = _formatter(**_MOVED_CONFIGS[config]).format(text).content
        (tmp_path / "goal.mk").write_text(f"{_GOAL}: ;\n", encoding="utf-8")
        for makefile in (text, formatted):
            (tmp_path / "input.mk").write_text(makefile, encoding="utf-8")
            proc = subprocess.run(
                [make, "-r", "-R", "-n", "-f", "input.mk", "-f", "goal.mk"]
                + [f"SHELL={true}", _GOAL],
                cwd=tmp_path,
                capture_output=True,
                text=True,
                timeout=60,
                env=_MAKE_ENV,
            )
            assert proc.returncode == 0, proc.stderr


class TestCli:
    """'format --stdin' exits 0 for the issue's examples and 2 for an override."""

    CONFIG = Config(
        formatter=FormatterConfig(
            auto_insert_phony_declarations=False,
            ensure_final_newline=False,
            group_phony_declarations=False,
            phony_at_top=False,
        )
    )

    @pytest.mark.parametrize(
        ("text", "exit_code"),
        [
            ("foo: bar\nfoo: baz", 0),
            ("foo: bar = 1\nfoo: baz", 0),
            ("foo:\n\t@echo a\nfoo:\n\t@echo b", 2),
            (
                "build: main.o\nifdef DEBUG\nbuild: debug-deps\nendif\n"
                "\t@echo cc -o build main.o",
                0,
            ),
        ],
    )
    @pytest.mark.parametrize("check", [False, True])
    def test_cli_stdin_issue_examples(self, text, exit_code, check):
        args = ["format", "--stdin"] + (["--check"] if check else [])
        with patch("mbake.cli.Config.load_or_default", return_value=self.CONFIG):
            result = CliRunner().invoke(app, args, input=text)
        assert result.exit_code == exit_code
        if exit_code == 0 and not check:
            assert result.stdout == text
