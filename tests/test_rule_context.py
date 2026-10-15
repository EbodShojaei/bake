"""Tests for scan_makefile, the line-by-line model of how GNU make reads a makefile.

Line numbers refer to the GNU make 4.4.1 manual. Behaviour that the manual
leaves open was checked with make 3.81 and GNU make 4.4.1 (.RECIPEPREFIX,
which make 3.81 does not support, with 4.4.1 only).
"""

import importlib.util
import os
import re
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from mbake.core.rules.recipe_validation import RecipeValidationRule, _LineFacts
from mbake.utils.line_utils import LineUtils
from mbake.utils.rule_context import (
    ASSIGNMENT,
    BLANK,
    COMMENT,
    CONDITIONAL,
    DEFINE,
    DEFINE_BODY,
    DIRECTIVE,
    ENDEF,
    FUNCTION_CALL,
    OTHER,
    RECIPE,
    RULE,
    TARGET_VARIABLE,
    cleanup_readings,
    define_body_lines,
    empty_recipe_lines,
    empty_recipes_to_keep,
    include_whitespace_lines,
    orphaned_recipe_lines,
    recipe_of_phony_only,
    scan_makefile,
    significant_whitespace_lines,
    target_variable_assignment,
    value_whitespace_lines,
    whitespace_recipe_lines,
)

TESTS_DIR = Path(__file__).parent
BS = "\\"  # one backslash, to keep continuation lines readable

# Lines that set .RECIPEPREFIX, and the recipe prefix that GNU make 4.4.1 uses
# after them (GNU 1126-1181, 4588-4592, 4795-4827, 5158-5169)
RECIPEPREFIX_FORMS = [
    (["GT := >", ".RECIPEPREFIX = $(GT)"], "$"),
    (["override .RECIPEPREFIX = $(GT)"], "$"),
    ([".RECIPEPREFIX := $$"], "$"),
    ([".RECIPEPREFIX :::= $$"], "$"),
    ([".RECIPEPREFIX := $$>"], "$"),
    ([".RECIPEPREFIX =", "GT := >", ".RECIPEPREFIX += $(GT)"], "$"),
    (["GT := >", ".RECIPEPREFIX :::=", ".RECIPEPREFIX += $(GT)"], "$"),
    (["GT := >", ".RECIPEPREFIX = $(GT)", ".RECIPEPREFIX += !"], "$"),
    (["define .RECIPEPREFIX", ">", "endef"], ">"),
    (["define .RECIPEPREFIX =", "$(GT)", "endef"], "$"),
    (["define .RECIPEPREFIX :=", ">", "endef"], ">"),
    (["override define .RECIPEPREFIX", ">", "endef"], ">"),
    (["define .RECIPEPREFIX", "  >", "endef"], " "),
    (["define .RECIPEPREFIX", "\\", ">", "endef"], " "),
    ([".RECIPEPREFIX = >", "define .RECIPEPREFIX", "endef"], "\t"),
    ([".RECIPEPREFIX = >", "define .RECIPEPREFIX", "", "endef"], "\t"),
    (["define .RECIPEPREFIX +=", "!", "endef"], "!"),
    ([".RECIPEPREFIX = >", "define .RECIPEPREFIX +=", "!", "endef"], ">"),
    (["define .RECIPEPREFIX ?=", ">", "endef"], "\t"),
    ([".RECIPEPREFIX = >", "define .RECIPEPREFIX", "!", ">endef", "endef"], "!"),
]

# make runs with a minimal environment so that no inherited variable (such as
# MAKEFLAGS) changes what it reads.
_MAKE_ENV = {"PATH": os.defpath, "LC_ALL": "C"}


@pytest.fixture(scope="module")
def gnu_make_4():
    """Return (path, (major, minor)) of a GNU make 4.x ('gmake' or 'make'), or
    skip.

    make 3.81 has no .RECIPEPREFIX.
    """
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
        match = re.match(r"GNU Make (\d+)\.(\d+)", version)
        if match and int(match.group(1)) >= 4:
            return make, (int(match.group(1)), int(match.group(2)))
    pytest.skip("no GNU make 4.x is installed")


def _kinds(lines, hidden=None):
    return [state.kind for state in scan_makefile(lines, hidden)]


def _contexts(lines, hidden=None):
    return [state.rule_context for state in scan_makefile(lines, hidden)]


class TestKinds:
    """Each line gets the kind of line make reads it as."""

    def test_kinds_of_makefile_syntax(self):
        """Assignments, target-specific variables, directives, calls that
        expand to nothing, rules and other text (GNU 1209-1229, 4938-4951,
        6388-6390, 10847-10913)."""
        lines = [
            "# comment",
            "",
            "X = 1",
            "prog: cflags = -g",
            "vpath %.c src",
            "-include x.mk",
            "$(info hi)",
            "$(foreach t,a,$(eval $(t): ; @true))",
            "all: prog",
            "$(VAR)",
            "ifdef X",
            "endif",
            "define D",
            "body",
            "endef",
        ]
        assert _kinds(lines) == [
            COMMENT,
            BLANK,
            ASSIGNMENT,
            TARGET_VARIABLE,
            DIRECTIVE,
            DIRECTIVE,
            FUNCTION_CALL,
            FUNCTION_CALL,
            RULE,
            OTHER,
            CONDITIONAL,
            CONDITIONAL,
            DEFINE,
            DEFINE_BODY,
            ENDEF,
        ]

    def test_assignment_comes_before_directive_words(self):
        """'export = 1' assigns to a variable named 'export' (GNU
        10883-10902)."""
        assert _kinds(["export = 1", "export X"]) == [ASSIGNMENT, DIRECTIVE]

    def test_colon_in_comment_or_inline_recipe_is_no_rule(self):
        """Only a ':' before the comment and before an inline recipe makes a
        rule (GNU 730-742, 1488, 1499-1503)."""
        assert _kinds(["foo # a: b", "foo ; a: b", "foo: ; a"]) == [OTHER, OTHER, RULE]

    def test_text_of_makefile_and_recipe_lines(self):
        """Makefile syntax is joined into one logical line (GNU 776-781); a
        recipe line keeps its backslash/newline (2910-2920)."""
        lines = ["X = a " + BS, "    b", "all:", "\techo a " + BS, "\tb"]
        states = scan_makefile(lines)
        assert states[0].text == states[1].text == "X = a b"
        assert states[3].text == states[4].text == "\techo a " + BS + "\n\tb"


class TestRuleContext:
    """Where a rule context may reach a line (GNU 2878-2905)."""

    def test_tab_line_after_rule_is_recipe_even_inside_conditional(self):
        """A TAB-led line in a rule context is a recipe line, even if it reads
        as an assignment or a conditional (GNU 2897-2905); a conditional keeps
        the rule context (5315-5333)."""
        lines = ["all:", "\t@echo", "ifeq (1,1)", "\tX = 1", "endif"]
        states = scan_makefile(lines)
        kinds = [s.kind for s in states]
        assert kinds == [RULE, RECIPE, CONDITIONAL, RECIPE, CONDITIONAL]
        assert [s.rule_context for s in states] == [False, True, True, True, True]
        assert states[3].depth == 1

    def test_blank_and_comment_lines_keep_rule_context(self):
        """GNU 2884-2886."""
        states = scan_makefile(["all:", "", "# c", "\tX = 1"])
        assert states[3].kind == RECIPE
        assert states[3].rule_line == 0

    @pytest.mark.parametrize(
        "syntax",
        [
            "X = 1",
            "export X = 1",
            "unexport X = 1",
            "private X = 1",
            "prog: cflags = -g",
            "vpath %.c src",
            "-include none.mk",
            "sinclude none.mk",
            "export X",
            "$(info hi)",
            "$(foreach v,a,$(eval Z = 1))",
        ],
    )
    def test_makefile_syntax_ends_rule_context(self, syntax):
        """Other makefile syntax ends a rule context (GNU 2881-2884), so the
        TAB-led assignment after it is makefile syntax (1217-1219). make 3.81
        and 4.4.1 both read it as an assignment."""
        states = scan_makefile(["all:", syntax, "\tV = 1"])
        assert states[2].kind == ASSIGNMENT
        assert not states[2].rule_context

    @pytest.mark.parametrize(
        "lines",
        [
            ["override W = 2"],
            ["define D", "x", "endef"],
            ["override define D", "x", "endef"],
        ],
    )
    def test_override_and_define_keep_rule_context(self, lines):
        """make 3.81 keeps the rule context at 'override' and 'define' lines
        (make 4.4.1 ends it), so the model keeps it too."""
        states = scan_makefile(["all:", *lines, "\tV = 1"])
        assert states[-1].kind == RECIPE

    def test_prefixed_line_outside_rule_does_not_open_context(self):
        """A TAB-led line outside a rule context never starts one: make stops
        with "recipe commences before first target" (GNU 11292-11297)."""
        states = scan_makefile(["\t$(info x)", "\tX = 1"])
        assert states[1].kind == ASSIGNMENT
        assert not states[1].rule_context

    def test_variable_reference_line_may_open_rule_context(self):
        """A reference can expand to a whole rule (GNU 1231-1236)."""
        assert _kinds(["$(myrule)", "\tV = 1"])[1] == RECIPE

    def test_assignment_in_branch_ends_rule_context_in_that_branch(self):
        """The lines after an assignment in the same branch are read only
        when the assignment is (GNU 5345-5358); after 'endif' the branch that
        make took decides, so the rule context may go on."""
        lines = ["all:", "ifeq (1,1)", "W = 2", "\tU = 1", "endif", "\tV = 1"]
        lines += ["Z = 3", "\tY = 4"]
        states = scan_makefile(lines)
        assert states[3].kind == ASSIGNMENT
        assert states[5].kind == RECIPE
        assert states[7].kind == ASSIGNMENT
        assert not states[7].rule_context

    @pytest.mark.parametrize(
        ("lines", "kind"),
        [
            (["X = 1", "ifdef NOPE", "all:", "else", "\tV = 1", "endif"], ASSIGNMENT),
            (["all:", "ifdef NOPE", "X = 1", "else", "\tV = 1", "endif"], RECIPE),
        ],
    )
    def test_else_branch_starts_from_the_lines_above_the_conditional(self, lines, kind):
        """make reads an 'else' branch only when it ignored the branch before
        (GNU 5345-5358), so the lines above the conditional decide. make 3.81
        and 4.4.1 read '\\tV = 1' as an assignment after 'X = 1' and as a
        recipe line after 'all:'."""
        assert _kinds(lines)[4] == kind

    def test_tab_led_conditional_in_rule_context_is_a_recipe_line(self):
        """It goes to the shell and leaves the conditional depth alone (GNU
        2902-2905)."""
        lines = ["all:", "\tifeq (1,1)", "\t@echo yes", "\tendif", "X = 1"]
        states = scan_makefile(lines)
        assert [s.kind for s in states[1:4]] == [RECIPE, RECIPE, RECIPE]
        assert states[4].depth == 0

    def test_tab_led_conditional_outside_rule_context_counts(self):
        """Outside a rule context a TAB-led line is makefile syntax (GNU
        1217-1219), so these conditionals nest."""
        lines = ["ifdef A", "\tifdef B", "\t\tX = 1", "\tendif", "endif", "Y = 1"]
        assert [s.depth for s in scan_makefile(lines)] == [0, 1, 2, 2, 1, 0]

    @pytest.mark.parametrize(
        "include",
        [
            "-include",
            "include # none",
            "-include $(D)",
            "-include $(A)$(B)",
            "-include $X",
            "-include $(D)# c",
        ],
    )
    def test_include_that_may_name_no_file_keeps_rule_context(self, include):
        """make 3.81 skips an include directive whose file names expand to
        nothing and keeps the rule context; make 4.4.1 ends it."""
        states = scan_makefile(["foo:", include, "\tV = 1"])
        assert states[2].kind == RECIPE
        assert states[2].rule_line == 0
        assert states[2].readings == {RECIPE, ASSIGNMENT}

    @pytest.mark.parametrize(
        "include", ["-include $(D) ", "sinclude $(A) $(B)", "include $(D) # c"]
    )
    def test_include_with_a_blank_after_a_reference_ends_rule_context(self, include):
        """make 3.81 expands the text after the directive word with the blanks
        at its end (cut at the comment, GNU 730-742), which then is not empty,
        so it ends the rule context as make 4.4.1 does (GNU 848-856). Both
        read '\\tV = 1' as an assignment."""
        states = scan_makefile(["foo:", include, "\tV = 1"])
        assert states[2].kind == ASSIGNMENT
        assert states[2].readings == {ASSIGNMENT}

    def test_include_of_a_file_ends_rule_context(self):
        states = scan_makefile(["foo:", "-include x.mk", "\tV = 1"])
        assert states[2].kind == ASSIGNMENT
        assert states[2].readings == {ASSIGNMENT}


class TestReadings:
    """readings follows make through every branch, with make 3.81 and 4.x.

    Each expectation was checked with make 3.81 and GNU make 4.4.1, by
    printing the variable that the line would set.
    """

    @staticmethod
    def _readings(lines, hidden=None):
        return [state.readings for state in scan_makefile(lines, hidden)]

    def test_tab_led_assignments_between_conditionals_outside_rules(self):
        """No rule comes before them, so make reads them as assignments,
        although rule_context over-approximates after 'endif' (GNU 1217-1219,
        5345-5358)."""
        lines = ["ifeq ($(OS),Windows_NT)", "\tEXE = .exe ", "endif"]
        lines += ["ifeq ($(DEBUG),)", "\tCFLAGS += -g ", "endif"]
        states = scan_makefile(lines)
        assert states[4].kind == RECIPE
        assert states[4].rule_line is None
        assert states[4].readings == {ASSIGNMENT}

    def test_nested_tab_led_conditionals_outside_rules(self):
        lines = ["ifeq ($(A),)", "\tifeq ($(B),)", "\t\tX = 1", "\tendif"]
        lines += ["\tY = a ", "endif"]
        readings = self._readings(lines)
        assert readings[1] == readings[3] == {CONDITIONAL}
        assert readings[4] == {ASSIGNMENT}

    def test_recipe_in_every_branch_is_certain(self):
        """A rule context that every branch keeps is certain (GNU 5315-5333)."""
        lines = ["foo:", "ifdef X", "\t@echo x", "endif", "\tV = a"]
        assert self._readings(lines)[4] == {RECIPE}

    def test_rule_in_one_branch_makes_the_rule_context_possible(self):
        lines = ["X = 1", "ifdef A", "foo:", "endif", "\tV = a"]
        assert self._readings(lines)[4] == {RECIPE, ASSIGNMENT}

    @pytest.mark.parametrize(
        "between", [["override O = 1"], ["define D", "endef"], ["$(MAYBE_RULE)"]]
    )
    def test_lines_that_may_end_a_rule_context(self, between):
        """make 4.4.1 ends a rule context at 'override' and 'define', make
        3.81 does not; a reference may expand to a rule or to nothing (GNU
        1231-1236, 2881-2884)."""
        states = scan_makefile(["all:", "\t@:", *between, "\tV = a "])
        assert states[-1].kind == RECIPE
        assert states[-1].readings == {RECIPE, ASSIGNMENT}

    def test_conditional_that_may_be_a_recipe_line(self):
        """Where a rule context is possible but not certain, '\\tifdef B' is a
        recipe line or a conditional, and both readings go on (GNU
        2902-2905)."""
        lines = ["ifdef A", "foo:", "endif", "\tifdef B", "\t\tV = a ", "\tendif"]
        lines += ["X = 1"]
        readings = self._readings(lines)
        assert readings[3] == {RECIPE, CONDITIONAL}
        assert readings[4] == {RECIPE, ASSIGNMENT}
        assert readings[6] == {ASSIGNMENT}

    def test_skipped_branch_skips_recipe_prefixed_directives(self):
        """In a rule context, make skips a recipe-prefixed line of a branch it
        does not take without reading it as a directive (GNU 5315-5333)."""
        lines = ["foo:", "ifdef NOPE", "\tendif", "endif", "\tV = a"]
        readings = self._readings(lines)
        assert readings[2] == {RECIPE}
        assert readings[4] == {RECIPE}

    def test_define_of_a_skipped_branch_ends_at_the_first_endef(self):
        """A define that make reads nests (GNU 4823-4827); one in a branch
        that make skips ends at the first 'endef'."""
        lines = ["ifdef NOPE", "define A", "define B", "endef", "endif", "X = a "]
        readings = self._readings(lines)
        assert readings[4] == {DEFINE_BODY, CONDITIONAL}
        assert readings[5] == {DEFINE_BODY, ASSIGNMENT}

    def test_define_that_may_be_a_recipe_line(self):
        """'\\tdefine X' after a possible rule context opens a body when make
        reads it as makefile syntax, so the body lines may be a value."""
        lines = ["ifdef A", "foo:", "endif", "\tdefine X", "y  ", "endef"]
        states = scan_makefile(lines)
        assert states[4].kind == OTHER
        assert not states[4].in_define
        assert states[4].readings == {DEFINE_BODY}
        assert states[4].may_be_define_body

    def test_recipeprefix_in_a_branch(self):
        """Without NOPE the prefix stays a TAB, so the TAB-only line is the
        empty recipe of foo.x (GNU 5158-5169; make 4.4.1)."""
        lines = ["ifdef NOPE", ".RECIPEPREFIX = >", "endif", "foo.x:", "\t"]
        states = scan_makefile(lines)
        assert states[4].recipe_prefix == ">"
        assert states[4].kind == BLANK
        assert states[4].readings == {RECIPE, BLANK}

    @pytest.mark.parametrize(
        "assignments",
        [
            [".RECIPEPREFIX != echo '>'"],
            [".RECIPEPREFIX := $(GT)"],
            ["define .RECIPEPREFIX :=", "$(GT)", "endef"],
            [".RECIPEPREFIX += $(GT)"],
        ],
    )
    def test_recipeprefix_that_make_computes(self, assignments):
        """make 4.4.1 sets the prefix from the command's output, or from the
        expansion of the reference for ':=' and for '+=' to the empty, simply
        expanded .RECIPEPREFIX it starts with (GNU 1126-1181), which the scan
        cannot know."""
        states = scan_makefile([*assignments, "all:", "\tV = a"])
        assert states[-1].recipe_prefix == "\t"
        assert states[-1].readings == {RECIPE, ASSIGNMENT}

    def test_recipeprefix_set_to_a_reference(self):
        """'=' stores the text as written, so GNU make 4.4.1 takes '$' for
        the prefix and runs '$@echo a' (GNU 1126-1166, 5158-5169); make 3.81
        has no .RECIPEPREFIX."""
        lines = ["GT := >", ".RECIPEPREFIX = $(GT)", "all:", "$@echo a", "\tV = a"]
        states = scan_makefile(lines)
        assert states[3].recipe_prefix == "$"
        assert states[3].kind == RECIPE
        assert states[3].readings == {RECIPE, OTHER}
        assert states[4].kind == ASSIGNMENT

    def test_recipeprefix_defined_with_define(self):
        """The body is the value (GNU 4795-4799); make 3.81 stops at
        '>@echo a'."""
        lines = ["define .RECIPEPREFIX", ">", "endef", "all:", ">@echo a", "\tV = a"]
        readings = self._readings(lines)
        assert readings[4] == {RECIPE}
        assert readings[5] == {ASSIGNMENT}

    def test_recipeprefix_defined_in_a_skipped_branch(self):
        """Without NOPE make 4.4.1 keeps the TAB prefix."""
        lines = ["ifdef NOPE", "define .RECIPEPREFIX", ">", "endef", "endif"]
        lines += ["all:", "\tV = a"]
        states = scan_makefile(lines)
        assert states[6].recipe_prefix == ">"
        assert states[6].readings == {RECIPE, ASSIGNMENT}

    def test_computed_recipeprefix_is_no_letter(self):
        """A computed prefix may be any character, but not one that names
        start with, so 'endef' still ends the body."""
        lines = [".RECIPEPREFIX != echo '>'", "define X", "a  ", "endef", "Y = 1 "]
        readings = self._readings(lines)
        assert readings[2] == {DEFINE_BODY}
        assert readings[3] == {ENDEF}
        assert readings[4] == {ASSIGNMENT}

    def test_line_that_stops_make_has_no_reading(self):
        """make stops at a recipe-prefixed line outside a rule context ("recipe
        commences before first target", GNU 11292-11297); the lines after it
        are read as if it were not there."""
        readings = self._readings(["\t$(info x)", "\tX = 1"])
        assert readings == [frozenset(), {ASSIGNMENT}]

    def test_make_381_reads_double_colon_assignment_as_rule(self):
        """make 3.81 does not know '::=' (GNU 4612-4625 is 4.x syntax)."""
        assert self._readings(["X ::= 1", "\tV = a"])[1] == {RECIPE, ASSIGNMENT}

    def test_hidden_lines_count_for_readings(self):
        lines = ["X = 1", "# bake-format off", "# bake-format on", "\tY = a "]
        assert self._readings(lines, {1: ["all:"]})[3] == {RECIPE}
        assert self._readings(lines, {1: []})[3] == {ASSIGNMENT}

    def test_recipe_owners_follow_every_branch(self):
        """With A the TAB-only line after 'endif' is a recipe line of b,
        without A of c; 'all' cannot reach it, since both branches start a
        rule (GNU 2881-2884, 5345-5358)."""
        lines = ["all:", "\t@:", "ifdef A", "b:", "else", "c:", "endif", "\t"]
        lines += ["d:", "\t"]
        states = scan_makefile(lines)
        assert states[1].recipe_owners == {0}
        assert states[7].recipe_owners == {3, 5}
        assert states[9].recipe_owners == {8}
        assert states[8].recipe_owners == frozenset()

    def test_recipe_owners_of_disabled_regions(self):
        """A rule that a region hides is named by its '# bake-format off'
        line; without the hidden lines either marker may stand for one."""
        lines = ["X = 1", "# bake-format off", "# bake-format on", "\tY = 2"]
        assert scan_makefile(lines, {1: ["all:"]})[3].recipe_owners == {1}
        assert scan_makefile(lines, {1: []})[3].recipe_owners == frozenset()
        assert scan_makefile(lines)[3].recipe_owners == {1, 2}


class TestDefineBodies:
    """A define body is the value of a variable (GNU 4785-4827)."""

    def test_nested_define_and_tab_led_endef(self):
        """Only a bare 'define' nests, and a TAB-led 'endef' ends nothing
        (GNU 4823-4827)."""
        lines = ["define A", "define B", "x", "endef", "\tendef", "endef", "all:"]
        assert _kinds(lines) == [
            DEFINE,
            DEFINE_BODY,
            DEFINE_BODY,
            DEFINE_BODY,
            DEFINE_BODY,
            ENDEF,
            RULE,
        ]

    def test_body_lines_are_in_define(self):
        states = scan_makefile(["define newline", "", "", "endef"])
        assert [s.in_define for s in states] == [False, True, True, False]

    @pytest.mark.parametrize(
        ("end", "ends"), [("endef # done", True), ("endef#not", False)]
    )
    def test_endef_needs_a_blank_or_end_of_line(self, end, ends):
        """GNU 4797-4799; make 3.81 and 4.4.1 agree."""
        kinds = _kinds(["define X", "x", end, "y"])
        assert kinds[2] == (ENDEF if ends else DEFINE_BODY)

    def test_prefixed_define_in_rule_context_is_a_recipe_line(self):
        """GNU 4825-4827."""
        assert _kinds(["all:", "\tdefine X", "x"]) == [RULE, RECIPE, OTHER]

    def test_prefixed_define_outside_rule_context_starts_a_body(self):
        """GNU 1217-1219, 4795-4799."""
        assert _kinds(["X = 1", "\tdefine D", "x", "endef"]) == [
            ASSIGNMENT,
            DEFINE,
            DEFINE_BODY,
            ENDEF,
        ]


class TestConditionalDepth:
    """depth counts the open conditionals (GNU 5386-5421)."""

    def test_depth_counts_ifdef_quoted_ifeq_and_else_chains(self):
        lines = ["ifdef A", 'ifeq "a" "b"', "else ifdef C", "X = 1", "endif"]
        lines += ["endif", "Y = 2"]
        states = scan_makefile(lines)
        assert states[3].depth == 2
        assert states[6].depth == 0

    def test_branches_tell_the_branches_apart(self):
        """'else' starts the next branch of the same conditional."""
        states = scan_makefile(["ifdef A", "X = 1", "else", "Y = 2", "endif"])
        (outer_x,) = states[1].branches
        (outer_y,) = states[3].branches
        assert outer_x[0] == outer_y[0]
        assert (outer_x[1], outer_y[1]) == (0, 1)

    def test_automake_if_counts_for_depth(self):
        """The automake conditional of #90 nests like a make conditional and
        starts no rule of its own, so the 'endif' that closes it leaves an
        enclosing conditional open."""
        lines = [".DELETE_ON_ERROR:", "", "ifdef A", "if STRICT"]
        lines += ["  WERROR = -Werror", "else", "  WERROR =", "endif", "X = 1"]
        lines += ["endif"]
        states = scan_makefile(lines)
        assert states[3].kind == CONDITIONAL
        assert [s.depth for s in states[3:]] == [1, 2, 2, 2, 2, 1, 1]
        assert states[4].rule_line == 0

    def test_shell_if_without_tab_is_no_automake_conditional(self):
        assert _kinds(["all:", "    if [ -f x ]; then echo; fi"])[1] == OTHER


class TestRecipePrefix:
    """.RECIPEPREFIX sets the recipe prefix (GNU 5158-5169)."""

    def test_recipeprefix_changes_recipe_detection(self):
        lines = [".RECIPEPREFIX = >", "all:", "> echo", "\tX = 1"]
        states = scan_makefile(lines)
        assert states[2].kind == RECIPE
        assert states[2].recipe_prefix == ">"
        assert states[3].kind == ASSIGNMENT

    @pytest.mark.parametrize(
        ("assignments", "prefix"),
        [
            ([".RECIPEPREFIX = >", ".RECIPEPREFIX ="], "\t"),
            ([".RECIPEPREFIX = >", ".RECIPEPREFIX = # reset"], "\t"),
            ([".RECIPEPREFIX = >", ".RECIPEPREFIX = $(TAB)"], "$"),
            ([".RECIPEPREFIX = $(TAB)"], "$"),
            ([".RECIPEPREFIX = > # angle"], ">"),
            ([".RECIPEPREFIX = \\#"], "#"),
            ([".RECIPEPREFIX ?= >"], "\t"),
            ([".RECIPEPREFIX += >"], ">"),
            ([".RECIPEPREFIX = >", ".RECIPEPREFIX += !"], ">"),
            (["override .RECIPEPREFIX := >"], ">"),
            ([".RECIPEPREFIX != echo"], "\t"),
            ([".RECIPEPREFIX = >", ".RECIPEPREFIX := $(TAB)"], ">"),
            (["define .RECIPEPREFIX"], "\t"),
            (["define"], "\t"),
        ],
    )
    def test_edge_values_never_raise(self, assignments, prefix):
        """An empty value, also one that is only a comment, means a TAB (GNU
        5160-5162, 730-742); '\\#' is a '#'. GNU make 4.4.1 ignores '?='
        because .RECIPEPREFIX is always defined, and '+=' only sets an empty
        value. '=' stores the text as written, so '$(TAB)' gives '$' (GNU
        1126-1166). The output of '!=' and the expansion of a reference for
        ':=' are not known here, so recipe_prefix keeps the previous prefix
        and readings treats it as unknown; make 4.4.1 does use them
        ('.RECIPEPREFIX != echo' gives an empty value, so a TAB). A define
        that the end of the file cuts off changes nothing."""
        states = scan_makefile([*assignments, "all:"])
        assert states[-1].recipe_prefix == prefix

    @pytest.mark.parametrize(("assignments", "prefix"), RECIPEPREFIX_FORMS)
    def test_prefix_is_the_first_character_of_the_stored_value(
        self, assignments, prefix
    ):
        """make takes the first character of the value it stores (GNU
        5158-5169): the text as written for '=' and a define without an
        operator, the expansion for ':=', '::=' and ':::=', and for '+=' to
        an empty value whichever of them the variable's flavor stores (GNU
        1126-1181, 4588-4592, 4816-4821). A define body keeps its leading
        whitespace (4795-4814), and the old prefix decides which lines end
        it (4823-4827). Each case was checked with GNU make 4.4.1."""
        states = scan_makefile([*assignments, "all:"])
        assert states[-1].recipe_prefix == prefix

    @pytest.mark.parametrize(("assignments", "prefix"), RECIPEPREFIX_FORMS)
    def test_gnu_make_4_reads_a_recipe_line_with_that_prefix(
        self, gnu_make_4, tmp_path, assignments, prefix
    ):
        """GNU make 4.x runs the line that starts with that prefix as the
        recipe of all. The ':::=' operator (GNU 4290-4348) came with GNU make
        4.4, so older makes, such as make 4.3, skip those forms."""
        make, version = gnu_make_4
        if version < (4, 4) and any(":::=" in line for line in assignments):
            pytest.skip("':::=' needs GNU make 4.4")
        text = "\n".join([*assignments, "all:", f"{prefix}@echo ok"]) + "\n"
        proc = subprocess.run(
            [make, "-r", "-R", "-n", "-f", "-", "SHELL=true", "all"],
            input=text,
            cwd=tmp_path,
            capture_output=True,
            text=True,
            timeout=60,
            env=_MAKE_ENV,
        )
        assert (proc.returncode, proc.stdout) == (0, "echo ok\n")


class TestDisabledRegions:
    """Lines that '# bake-format off' hides from a rule."""

    LINES = ["X = 1", "# bake-format off", "# bake-format on", "\tY = 2"]

    def test_hidden_lines_are_read_in_place(self):
        states = scan_makefile(self.LINES, {1: ["all:"]})
        assert states[3].kind == RECIPE
        assert states[3].rule_line == 1

    def test_marker_that_hides_nothing(self):
        states = scan_makefile(self.LINES, {1: []})
        assert states[3].kind == ASSIGNMENT
        assert not states[3].rule_context

    def test_without_hidden_lines_a_region_may_hold_a_rule(self):
        """Without the hidden lines the region is unknown content."""
        assert scan_makefile(self.LINES)[3].kind == RECIPE

    def test_region_present_in_the_lines_is_unknown_content(self):
        lines = ["X = 1", "# bake-format off", "Z = 1", "# bake-format on", "\tY = 2"]
        assert scan_makefile(lines)[4].rule_context
        assert not scan_makefile(lines, {})[4].rule_context

    def test_hidden_recipeprefix_is_honoured(self):
        """A '.RECIPEPREFIX' line in a disabled region sets the recipe prefix
        of the lines after it (GNU 5158-5169)."""
        lines = ["# bake-format off", "# bake-format on", "all:", ">@echo a"]
        states = scan_makefile(lines, {0: [".RECIPEPREFIX = >"]})
        assert states[2].recipe_prefix == ">"
        assert states[3].kind == RECIPE

    def test_hidden_define_opens_a_body(self):
        lines = ["# bake-format off", "# bake-format on", "x   ", "endef"]
        states = scan_makefile(lines, {0: ["define X"]})
        assert [s.kind for s in states[1:]] == [DEFINE_BODY, DEFINE_BODY, ENDEF]


class TestContinuations:
    """make reads logical lines (GNU 776-781, 1209-1219)."""

    def test_continuation_lines_follow_their_logical_line(self):
        lines = ["X = a " + BS, "\tb", "all: x " + BS, "\ty", "\techo"]
        states = scan_makefile(lines)
        assert states[1].continuation
        assert states[1].kind == ASSIGNMENT
        assert states[1].logical_start == 0
        assert states[3].continuation
        assert states[3].kind == RULE
        assert states[4].kind == RECIPE

    def test_even_backslashes_do_not_continue(self):
        """An escaped backslash does not continue the line (GNU 730-733)."""
        states = scan_makefile(["X = a" + BS * 2, "\tY = 1"])
        assert not states[1].continuation
        assert states[1].kind == ASSIGNMENT

    def test_backslash_and_space_does_not_continue(self):
        states = scan_makefile(["X = a " + BS + " ", "\tY = 1"])
        assert not states[1].continuation


class TestEmptyRecipeLines:
    """Whitespace-only recipe lines that make a recipe empty (GNU 2890-2891,
    4040-4055)."""

    @staticmethod
    def _needed(lines, hidden=None):
        return empty_recipe_lines(lines, scan_makefile(lines, hidden))

    def test_only_recipe_line_of_a_rule_is_needed(self):
        assert self._needed(["foo.x:", "\t"]) == {1}

    def test_first_of_several_is_needed(self):
        assert self._needed(["foo:", "\t", "\t   ", "bar:", "\t"]) == {1, 4}

    @pytest.mark.parametrize(
        "lines",
        [
            ["foo:", "\t@echo a", "\t"],
            ["foo:", "\t", "\t@echo a"],
            ["foo:", "\t# shell comment", "\t"],
            ["foo: ; @echo a", "\t"],
            ["foo: ;", "\t"],
            ["foo:", "ifdef A", "\t@echo a", "\t", "endif"],
        ],
    )
    def test_line_read_with_a_command_is_not_needed(self, lines):
        """A command of the same rule that make always reads with the line
        makes the recipe non-empty; an inline recipe is a command (GNU
        1499-1503)."""
        assert self._needed(lines) == set()

    @pytest.mark.parametrize(
        "lines",
        [
            ["foo:", "ifdef A", "\t@echo a", "endif", "\t"],
            ["foo:", "ifdef A", "\t@echo a", "else", "\t", "endif"],
            ["foo:", "\t@echo a", "ifdef A", "bar:", "endif", "\t"],
        ],
    )
    def test_line_split_from_the_commands_is_needed(self, lines):
        """Without A the line is the whole recipe of its rule (GNU
        5345-5358)."""
        assert self._needed(lines) == {len(lines) - 1 - lines[::-1].index("\t")}

    def test_line_outside_any_rule_is_not_needed(self):
        assert self._needed(["X = 1", "\t", "ifdef A", "endif", "\t"]) == set()

    @pytest.mark.parametrize(
        "lines",
        [["foo.x:", "\t "], ["foo.x:", "\t ", "\t"], ["foo.x:", "\t", "\t "]],
    )
    def test_no_break_space_is_a_command(self, lines):
        """make skips only its own whitespace (GNU 776-781), so a TAB and a
        no-break space make a command, and a TAB-only line with it is an
        empty command line."""
        assert self._needed(lines) == set()

    def test_rule_hidden_by_a_disabled_region(self):
        lines = ["X = 1", "# bake-format off", "# bake-format on", "\t"]
        assert self._needed(lines, {1: ["foo:"]}) == {3}
        assert self._needed(lines, {1: []}) == set()

    @pytest.mark.parametrize(
        "lines",
        [
            [".PHONY: clean", "\t"],
            [".PHONY : clean # c", "", "\t"],
            [".PHONY: clean", "ifdef A", "\t", "endif"],
        ],
    )
    def test_recipe_of_phony_is_not_needed(self, lines):
        """make never runs the recipe of .PHONY (GNU 1442-1446, 2234-2240)."""
        assert self._needed(lines) == set()

    def test_line_that_may_belong_to_another_rule_than_phony(self):
        """Without A the line is the empty recipe of foo.x (GNU 5345-5358)."""
        lines = ["foo.x:", "ifdef A", ".PHONY: x", "endif", "\t"]
        assert self._needed(lines) == {4}

    def test_phony_with_another_target_is_a_rule_of_that_target(self):
        assert self._needed([".PHONY foo:", "\t"]) == {1}


class TestHelpers:
    def test_whitespace_recipe_lines_of_one_rule(self):
        """The lines that follow the rule in its branch or in nested ones."""
        lines = [".PHONY: a", "\t", "\t@echo", "ifdef A", "\t  ", "endif", "\t"]
        states = scan_makefile(lines)
        assert whitespace_recipe_lines(lines, states, 0) == [1, 4, 6]

    def test_whitespace_recipe_line_after_endif_of_a_branch_rule(self):
        """A line after 'endif' belongs to the rule in the branch when make
        reads that branch, and to the rule before the conditional otherwise
        (GNU 2881-2884, 5345-5358). make 3.81 and 4.4.1 agree: with A the
        TAB-only line is a recipe line of .PHONY, without A the empty recipe
        of foo.x."""
        lines = ["foo.x:", "ifdef A", ".PHONY: a", "\t", "endif", "\t"]
        states = scan_makefile(lines)
        assert whitespace_recipe_lines(lines, states, 2) == [3, 5]
        assert whitespace_recipe_lines(lines, states, 0) == [5]
        assert states[5].recipe_owners == {0, 2}
        assert states[3].recipe_owners == {2}

    def test_whitespace_recipe_lines_stop_at_the_next_rule(self):
        lines = [".PHONY: a", "\t", "b:", "\t"]
        states = scan_makefile(lines)
        assert whitespace_recipe_lines(lines, states, 0) == [1]

    def test_line_of_only_a_prefix_that_a_reading_reads(self):
        """Without A the prefix is '>' and '>' is a recipe line of .PHONY
        (GNU 5158-5169); with A make stops at it ("missing separator"). The
        one model takes the TAB prefix of the branch. Such a line counts only
        when it is all whitespace, as whitespace cleanup keeps only such
        lines: '>' may be another rule's empty recipe in another reading."""
        lines = [".RECIPEPREFIX = >", "all:", ".PHONY: all", "ifdef A"]
        lines += [".RECIPEPREFIX =", "endif", ">"]
        states = scan_makefile(lines)
        assert states[6].recipe_prefix == "\t"
        assert states[6].readings == {RECIPE}
        assert states[6].recipe_owners == {2}
        assert whitespace_recipe_lines(lines, states, 2) == []
        assert orphaned_recipe_lines(cleanup_readings(lines), [2]) == set()

    def test_whitespace_line_that_a_reading_reads(self):
        """Without A the prefix is a TAB, so the TAB-only line is a recipe
        line of .PHONY; the one model takes the prefix '>' of the branch."""
        lines = ["all:", ".PHONY: all", "ifdef A", ".RECIPEPREFIX = >", "endif"]
        lines += ["\t"]
        states = scan_makefile(lines)
        assert states[5].recipe_prefix == ">"
        assert RECIPE in states[5].readings
        assert whitespace_recipe_lines(lines, states, 1) == [5]
        assert orphaned_recipe_lines(cleanup_readings(lines), [1]) == {5}

    def test_define_body_lines(self):
        lines = ["X = 1", "define T", "a=1", "endef", "Y = 2"]
        assert define_body_lines(lines) == {2}
        assert define_body_lines(["X = 1", "Y=2"]) == set()

    def test_define_body_lines_with_hidden_define(self):
        lines = ["# bake-format off", "# bake-format on", "a=1", "endef", "Y=1"]
        assert define_body_lines(lines, {0: ["define T"]}) == {1, 2}

    def test_value_and_include_whitespace_lines(self):
        """Value whitespace (GNU 4273-4288) and the whitespace of an include
        of references that make 3.81 reads (GNU 848-856)."""
        lines = ["X = a ", "Y = b # c ", "all:", "-include $(D) ", "Z =  "]
        lines += ["-include $(D).d "]
        states = scan_makefile(lines)
        assert value_whitespace_lines(lines, states) == {0}
        assert include_whitespace_lines(lines, states) == {3}
        assert significant_whitespace_lines(lines, states) == {0, 3}

    def test_value_whitespace_lines_as_syntax(self):
        """A TAB-led assignment in a rule context is a recipe line (GNU
        2897-2900); read as makefile syntax it sets a value."""
        lines = ["all:", "\tX = a ", "\tsinclude $(D) "]
        states = scan_makefile(lines)
        assert significant_whitespace_lines(lines, states) == set()
        assert significant_whitespace_lines(lines, states, as_syntax=True) == {1, 2}

    def test_cleanup_readings(self):
        """The reading after strip_dangling_backslashes comes last, where it
        changes the lines (GNU 762-769)."""
        lines = ["X = a " + BS + " ", "Y = b"]
        assert len(cleanup_readings(lines)) == 1
        assert len(cleanup_readings(["X = a"], strip_dangling=True)) == 1
        readings = cleanup_readings(lines, strip_dangling=True)
        assert [read_lines for read_lines, _ in readings] == [
            lines,
            ["X = a " + BS, "Y = b"],
        ]
        assert readings[1][1][1].continuation

    @pytest.mark.parametrize(
        "lines",
        [
            # After the cleanup, the comment goes on over 'X = 1'.
            ["%.x: ; @echo implicit $@", "foo.x:", "# note " + BS + " ", "X = 1"],
            # After the cleanup, '.RECIPEPREFIX = >' is part of VPATH.
            ["VPATH = src " + BS + " ", ".RECIPEPREFIX = >", "foo.x:"],
            # After the cleanup, the line is a recipe line of bar.x with A.
            ["foo.x:", "ifdef A", "bar.x:", "# c " + BS + " ", "X = 1", "endif"],
        ],
    )
    def test_empty_recipes_to_keep_need_the_same_reading(self, lines):
        """A line that only the reading after strip_dangling_backslashes, or
        that reading in other branches or with another make, reads as an
        empty recipe is not kept: make reads the lines as they are (GNU
        762-769, 4040-4055)."""
        lines = [*lines, "\t"]
        readings = cleanup_readings(lines, strip_dangling=True)
        assert len(readings) == 2
        assert len(lines) - 1 in empty_recipes_to_keep(readings[1:])
        assert empty_recipes_to_keep(readings) == {}

    def test_empty_recipes_below_the_cleanup_are_not_kept(self):
        """After the cleanup, 'X ?= 2' is part of the value of V (GNU
        762-769), so make may read the branch of the TAB-only line, while the
        text of both readings reads it alike (GNU 5345-5358)."""
        lines = ["V = src " + BS + " ", "X ?= 2", "all.x:", "ifndef X", "\t", "endif"]
        readings = cleanup_readings(lines, strip_dangling=True)
        assert len(readings) == 2
        assert empty_recipes_to_keep(readings[1:]) == {4: "\t"}
        assert empty_recipes_to_keep(readings) == {}

    def test_empty_recipes_to_keep(self):
        """The cleanup after the empty recipe changes nothing before it."""
        lines = ["foo.x:", "\t   ", "X = a " + BS + " ", "Y = b"]
        readings = cleanup_readings(lines, strip_dangling=True)
        assert len(readings) == 2
        assert empty_recipes_to_keep(readings) == {1: "\t"}

    @pytest.mark.parametrize(
        ("lines", "orphaned"),
        [
            # Only .PHONY may own the TAB-only line.
            (["foo.x:", ".PHONY: t1", "\t", "t1:"], {2}),
            (["foo.x:", ".PHONY: t1", "ifdef A", "\t", "endif"], {3}),
            # No rule context reaches the '.PHONY:' line.
            ([".PHONY: t1", "ifdef A", "foo.x:", "endif", "\t"], set()),
            # With A, make reads the line as the empty recipe of foo.x.
            ([".PHONY: x", ".PHONY: t1", "ifdef A", "foo.x:", "endif", "\t"], None),
            (["all: ; @:", ".PHONY: t1", "ifdef A", "foo.x:", "endif", "\t"], None),
        ],
    )
    def test_orphaned_recipe_lines(self, lines, orphaned):
        """GNU 2881-2891, 4040-4055, 5345-5358."""
        removed = [i for i, line in enumerate(lines) if line.startswith(".PHONY:")]
        assert orphaned_recipe_lines(cleanup_readings(lines), removed) == orphaned

    def test_orphaned_recipe_lines_in_every_reading(self):
        """The line after 'endif' may be the empty recipe of foo.x, but after
        the cleanup no rule context reaches the '.PHONY:' line (the value of
        FLAGS goes on over '$(R)'), so the run after this one would move the
        '.PHONY:' line: it is not kept in place now either."""
        lines = ["foo.x:", "ifeq (a,a)", "FLAGS := -O2 " + BS + " ", "$(R)"]
        lines += [".PHONY: t1", "endif", "\t"]
        readings = cleanup_readings(lines, strip_dangling=True)
        assert orphaned_recipe_lines(readings[:1], [4]) is None
        assert orphaned_recipe_lines(readings, [4]) == {6}

    def test_recipe_of_phony_only(self):
        """make never runs the recipe of .PHONY (GNU 2234-2240)."""
        lines = [".PHONY: x", "\t", "foo:", "\t", "ifdef A", "bar:", "endif"]
        lines += ["\t"]
        states = scan_makefile(lines)
        assert recipe_of_phony_only(states, 1)
        assert not recipe_of_phony_only(states, 3)
        assert not recipe_of_phony_only(states, 7)

    @pytest.mark.parametrize(
        ("line", "value"),
        [
            ("foo: X = a ", "a "),
            ("foo:: X += b", "b"),
            ("%.o: override X := c;d ", "c;d "),
            ("foo:", None),
        ],
    )
    def test_target_variable_assignment(self, line, value):
        """GNU 4938-4951, 4994-4999."""
        assignment = target_variable_assignment(line)
        assert (assignment.value if assignment else None) == value


def _cases_from(value: Any) -> Iterator[list]:
    """Yield the lists of makefile lines found in value."""
    if isinstance(value, list) and value and all(isinstance(x, str) for x in value):
        yield value
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _cases_from(item)


def _recipe_validation_cases() -> list:
    """The line lists of the fixtures and of test_target_specific_variables."""
    cases = []
    for path in sorted((TESTS_DIR / "fixtures").glob("*/input.mk")):
        lines = path.read_text(encoding="utf-8").splitlines()
        cases.append(pytest.param(lines, id=f"fixture-{path.parent.name}"))
    path = TESTS_DIR / "test_target_specific_variables.py"
    spec = importlib.util.spec_from_file_location("_recipe_repair_cases", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    found = []
    for _name, value in sorted(vars(module).items()):
        found.extend(_cases_from(value))
        if not isinstance(value, type):
            continue
        for attribute in sorted(vars(value)):
            for mark in getattr(getattr(value, attribute), "pytestmark", []):
                if mark.name == "parametrize":
                    found.extend(_cases_from(list(mark.args[1])))
    for number, lines in enumerate(found):
        cases.append(pytest.param(lines, id=f"recipe-repair-{number}"))
    return cases


@pytest.mark.parametrize("lines", _recipe_validation_cases())
def test_rule_context_covers_recipe_validation_model(lines):
    """scan_makefile's rule_context over-approximates: it is True wherever
    RecipeValidationRule's model says that a rule context may reach a logical
    line (GNU 2878-2886).

    Exception: lines are only compared while the recipe prefix is still the
    one at the top of the file. RecipeValidationRule takes the prefix from
    LineUtils.get_active_recipe_prefix, which keeps the previous prefix for
    an empty '.RECIPEPREFIX =' (make 4.4.1 goes back to a TAB, GNU
    5158-5163) and ignores '.RECIPEPREFIX += >' after an empty value (make
    4.4.1 then uses '>'). scan_makefile follows make there, so after such a
    line the two models can disagree about define bodies and rule contexts.
    """
    rule = RecipeValidationRule()
    facts = _LineFacts(lines)
    for hidden in (None, {}):
        states = scan_makefile(lines, hidden)
        for start, state in enumerate(states):
            prefix = LineUtils.get_active_recipe_prefix(lines, start)
            if not state.recipe_prefix == prefix == states[0].recipe_prefix:
                break
            if facts.starts[start] != start:
                continue
            if rule._is_inside_define_block(facts, start, prefix):
                continue
            if rule._may_be_in_rule_context(facts, start, prefix):
                assert state.rule_context, (start, lines[start])
