"""Tests for recipe repair next to target-specific variables and make syntax.

With fix_missing_recipe_tabs (the default), RecipeValidationRule adds the
missing TAB to a line that follows a rule or a recipe. That only repairs lines
that make rejects: make reads every line that does not start with the recipe
prefix as makefile syntax, and such a line ends the rule context (GNU make
manual 3.8, lines 1209-1229; 5.1, lines 2878-2886). Target-specific variables,
directives and calls to functions that expand to nothing are makefile syntax,
so they keep their column, and a target-specific variable never starts a rule
context (6.11, lines 4938-4951).

Line numbers refer to the GNU make 4.4.1 manual. TestAgainstGnuMake checks
with the GNU make on PATH that formatting keeps what make does.
"""

import os
import shutil
import subprocess

import pytest

from mbake.config import Config, FormatterConfig
from mbake.core.formatter import MakefileFormatter
from mbake.utils.line_utils import LineUtils

BS = "\\"  # one backslash, to keep continuation lines readable
MISSING_TAB = "Missing required tab separator in recipe line"
EMPTY_RESULT_FUNCTIONS = ("eval", "info", "warning", "error")


def _formatter(**config):
    return MakefileFormatter(Config(formatter=FormatterConfig(**config)))


def _format(lines, **config):
    """Return (lines, errors, warnings) for lines formatted with config."""
    return _formatter(**config).format_lines(lines)


def _formatted_lines(lines, **config):
    return _format(lines, **config)[0]


def _phony_targets(lines):
    """Return the targets of all .PHONY lines."""
    targets = set()
    for line in lines:
        if line.startswith(".PHONY:"):
            targets.update(line[len(".PHONY:") :].split())
    return targets


class TestDirectiveWord:
    """LineUtils.directive_word names the directive a makefile line starts."""

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("vpath %.c src", "vpath"),
            ("vpath", "vpath"),
            ("  vpath %.c src", "vpath"),
            ("vpath foo: X = 1", "vpath"),
            ("include a.mk", "include"),
            ("-include a.mk", "-include"),
            ("sinclude a.mk", "sinclude"),
            ("load ext.so", "load"),
            ("-load ext.so", "-load"),
            ("export", "export"),
            ("export FOO", "export"),
            ("unexport FOO", "unexport"),
            ("undefine X", "undefine"),
            ("override undefine X", "undefine"),
            ("private undefine X", "undefine"),
            ("define X", "define"),
            ("define X =", "define"),
            ("override define X", "define"),
            ("export define X", "define"),
            ("private override define X", "define"),
            ("ifdef X", "ifdef"),
            ("else", "else"),
            ("endif", "endif"),
            ("endef", "endef"),
        ],
    )
    def test_directives(self, text, expected):
        """The directives of GNU 10847-10913, 9028-9034; 'define' and
        'undefine' may follow modifiers (4776-4781, 4878-4882)."""
        assert LineUtils.directive_word(text) == expected

    @pytest.mark.parametrize(
        "text",
        [
            "export = 1",
            "export FOO = 1",
            "override define = 1",
            "override vpath %.c src",
            "override FOO",
            "vpath: x",
            "define: x",
            "vpathx a b",
            "echo hi",
            "$(info x)",
            "",
        ],
    )
    def test_not_directives(self, text):
        """Assignments come first, even to a variable named like a directive
        (GNU 10883-10902); a modifier only goes with an assignment, 'define'
        or 'undefine', so make rejects 'override vpath'; 'vpath:' is a
        target."""
        assert LineUtils.directive_word(text) is None


class TestIsFunctionCallOnly:
    """LineUtils.is_function_call_only finds lines of calls to given functions."""

    @pytest.mark.parametrize(
        "text",
        [
            "$(info x)",
            "$(info )",
            "$(eval\t$(call T,x))",
            "${info x}",
            "$(info a) $(warning b)",
            "$(info a)$(eval b)",
            "  $(error stop)  # the end",
        ],
    )
    def test_calls(self, text):
        """A call is '$(' or '${', the function name and a blank (GNU
        5588-5605); a comment does not count (730-742)."""
        assert LineUtils.is_function_call_only(text, EMPTY_RESULT_FUNCTIONS)

    @pytest.mark.parametrize(
        "text",
        [
            "$(info)",
            "$(eval)",
            "$(call T,x)",
            "$(MAKE)",
            "$(info x) $(VAR)",
            "$(info x) echo",
            "$(info x) " + BS,
            "$(info x",
            "$(eval $(x)",
            "$(foreach o,$(L),$(eval x))",
            "$(infox y)",
            "$( info x)",
            "$$(info x)",
            "# $(info x)",
            "",
        ],
    )
    def test_other_text(self, text):
        """Without a blank after the name, '$(info)' refers to the variable
        'info' (make 3.81 and 4.4 read 'info := hello' then '$(info)' as
        'hello'); other functions, variables, other text and unterminated
        calls do not count."""
        assert not LineUtils.is_function_call_only(text, EMPTY_RESULT_FUNCTIONS)


class TestTargetSpecificVariables:
    """A target-specific variable line is not a rule header."""

    @pytest.mark.parametrize(
        "variable_line",
        [
            "prog: cflags = -g",
            "prog: X != echo hi",
            "prog: export x = 1",
            "prog: override CFLAGS = -O2",
            "prog:: cflags = -g",
            "%.o: cflags = -g",
        ],
    )
    def test_line_after_target_specific_variable_gets_no_tab(self, variable_line):
        """A target-specific variable of any name, operator or modifier, or a
        pattern-specific one, does not start a rule context (GNU 4938-4951,
        4994-4999, 2881-2884). The next line is therefore no recipe line:
        make rejects 'echo hi' there ("missing separator"), and with a TAB it
        rejects it as a recipe without a target (11292-11297)."""
        lines = [variable_line, "echo hi"]
        assert _formatted_lines(lines) == [*lines, ""]

    @pytest.mark.parametrize(
        "variable_line",
        [
            "prog: cflags = -g",
            "prog: X != echo hi",
            "prog: override private x += 1",
            "prog: export x = 1",
        ],
    )
    def test_info_after_target_specific_variable_keeps_column(self, variable_line):
        """'$(info ...)' after a target-specific variable is makefile syntax;
        with a TAB, make 3.81 stops with "commands commence before first
        target" (GNU 4938-4951, 6597-6601, 11292-11297). Only the lines are
        checked, so the result does not depend on duplicate-target rules."""
        lines = [variable_line, "$(info configured)", "", "prog: prog.o"]
        lines.append("\t@echo $(cflags)")
        assert _formatted_lines(lines) == [*lines, ""]

    def test_continued_target_specific_variable_is_not_a_rule(self):
        """The variable line is read as one logical line (GNU 776-781), so a
        line after its continuation is not a recipe line either."""
        lines = ["prog: cflags = -g " + BS, "  -O2", "echo hi"]
        assert _formatted_lines(lines)[2] == "echo hi"

    def test_assignment_on_continuation_line_is_not_a_rule(self):
        """'prog: \\' and '  cflags = -g' form the logical line 'prog:
        cflags = -g' (GNU 776-781), a target-specific variable, although the
        first physical line looks like a rule."""
        lines = ["prog: " + BS, "  cflags = -g", "echo hi"]
        assert _formatted_lines(lines)[2] == "echo hi"


class TestMakefileSyntaxAfterRules:
    """Makefile syntax after a rule or recipe keeps its column."""

    @pytest.mark.parametrize(
        "lines",
        [
            ["all:", "\t@echo a", "$(info done)"],
            ["all:", "\t@echo a", "$(warning careful)"],
            ["all:", "\t@echo a", "$(error stop)"],
            ["all: x", "$(eval $(call TPL,x))"],
            ["all:", "\t@echo a", "$(info a) $(warning b)"],
            ["all:", "\t@echo a", "${info c}$(eval $(call T,x))"],
            [
                "define DEF",
                "X := 1",
                "endef",
                "all:",
                "\t@echo X=[$(X)]",
                "$(eval $(DEF))",
                "other: ; @echo other X=[$(X)]",
            ],
        ],
    )
    def test_calls_that_expand_to_nothing_keep_column(self, lines):
        """'$(eval ...)', '$(info ...)', '$(warning ...)' and '$(error ...)'
        expand to nothing, so make reads such lines as makefile syntax
        anywhere outside a recipe (GNU 6388-6390, 6565-6601). A TAB would move
        them into the recipe: make 3.81 then prints 'other X=[]' instead of
        'other X=[1]' for the '$(eval $(DEF))' case."""
        assert _formatted_lines(lines) == [*lines, ""]

    @pytest.mark.parametrize(
        "lines",
        [
            ["all: x", "$(eval $(call TPL,x)) # instantiate x"],
            ["all:", "\t@echo a", "$(info done)  # trace"],
            ["all:", "\t@echo a", "vpath %.c src # sources"],
            ["all:", "\t@echo a", "override define MSG # greeting", "hi", "endef"],
        ],
    )
    def test_trailing_comment_does_not_matter(self, lines):
        """The line is checked without its comment (GNU 730-742)."""
        assert _formatted_lines(lines) == [*lines, ""]

    def test_continued_eval_keeps_column(self):
        """'$(eval' continued on the next line is one logical line (GNU
        776-781), which only calls 'eval'."""
        lines = ["all: x", "$(eval " + BS, "$(call TPL,x))"]
        assert _formatted_lines(lines) == [*lines, ""]

    def test_continued_eval_with_indented_tail_keeps_column(self):
        """The first line of the logical line keeps its column. The indented
        continuation line may change its leading whitespace, which make
        condenses to one space (GNU 776-781)."""
        lines = ["all: x", "$(eval " + BS, "  $(call TPL,x))"]
        formatted = _formatted_lines(lines)
        assert formatted[:2] == lines[:2]
        assert formatted[2].strip() == "$(call TPL,x))"

    @pytest.mark.parametrize(
        "directive",
        [
            "vpath %.c src",
            "vpath",
            "sinclude extra.mk",
            "undefine X",
            "override undefine X",
            "private undefine X",
            "load ext.so",
            "-load ext.so",
        ],
    )
    def test_directives_after_recipe_keep_column(self, directive):
        """These directives are makefile syntax (GNU 1812-1830, 927-928,
        4855-4882, 9028-9034, 10847-10913). With a TAB, make runs them as
        shell commands and, for example, loses the vpath search path."""
        lines = ["all:", "\t@echo hi", directive, "other:", "\t@echo other"]
        assert _formatted_lines(lines) == [*lines, ""]

    def test_directive_after_rule_without_recipe_keeps_column(self):
        """GNU 927-928: 'sinclude' is another name for '-include'."""
        lines = ["all:", "sinclude extra.mk"]
        assert _formatted_lines(lines) == [*lines, ""]

    def test_continued_rule_after_recipe_gets_no_tab(self):
        """'foo \\' continues on the next line, so the logical line
        'foo bar: baz' is a rule (GNU 776-781, 2881-2884). With a TAB it
        becomes recipe text and make 3.81 says "No rule to make target
        `foo'"."""
        lines = ["all:", "\t@echo a", "foo " + BS, "bar: baz", "\t@echo $@"]
        lines += ["baz:", "\t@echo baz"]
        formatted = _formatted_lines(lines)
        assert formatted[2] == "foo " + BS
        assert formatted[3] == "bar: baz"


# A template whose call defines a rule that prints a line when it runs.
TPL = ["define TPL", "$(1): ; $$(info [built $(1)])", "endef"]

# Makefile syntax continued on a tab-indented line after a recipe, followed by
# a line that make accepts there. Each works with make 3.81 and 4.x.
CONTINUED_SYNTAX_CASES = [
    TPL
    + ["all:", "\t@echo all", "$(eval " + BS, "\t$(call TPL,x))"]
    + ["$(foreach t,a,$(eval $(call TPL,$(t))))", "both: x a"],
    ["all:", "\t@echo all", "vpath %.c " + BS, "\tsrc", "$(EMPTY)"]
    + ["show: x.c ; $(info [$<])"],
    ["R = $(1): ; $$(info [rule $(1)])", "all:", "\t@echo all"]
    + ["$(info hello " + BS, "\tworld)", "$(call R,r1)"],
    ["all:", "\t@echo all", "FOO = a " + BS, "\tb", "$(EMPTY)"]
    + ["show: ; $(info [$(FOO)])"],
]

# The same, with a space-indented continuation line, which TabsRule indents
# with a TAB.
SPACE_CONTINUED_SYNTAX_CASES = [
    TPL
    + ["all:", "\t@echo all", "$(eval " + BS, "    $(call TPL,x))"]
    + ["$(foreach t,a,$(eval $(call TPL,$(t))))", "both: x a"],
    TPL + ["all: x", "$(eval " + BS, "  $(call TPL,x))", "$(EMPTY)"],
]


class TestContinuedLines:
    """A line that continues another one belongs to that logical line."""

    @pytest.mark.parametrize("lines", CONTINUED_SYNTAX_CASES)
    def test_line_after_continued_makefile_syntax_keeps_column(self, lines):
        """A tab-indented line that continues '$(eval', 'vpath', '$(info' or
        an assignment is part of that makefile line, not a recipe line (GNU
        776-781, 1209-1218), and that line ends the rule context (2881-2884).
        With a TAB, the next line becomes a recipe line without a rule: make
        stops with "recipe commences before first target" (11292-11297)."""
        assert _formatted_lines(lines) == [*lines, ""]

    @pytest.mark.parametrize("lines", CONTINUED_SYNTAX_CASES)
    def test_no_error_after_continued_makefile_syntax(self, lines):
        """With fix_missing_recipe_tabs=False these lines produce no error."""
        formatted, errors, _ = _format(lines, fix_missing_recipe_tabs=False)
        assert formatted == [*lines, ""]
        assert not any(MISSING_TAB in error for error in errors)

    @pytest.mark.parametrize("lines", SPACE_CONTINUED_SYNTAX_CASES)
    def test_space_indented_continuation_is_stable(self, lines):
        """TabsRule indents the continuation line with a TAB on the first
        pass; the second pass must still read it as part of the makefile line
        and leave the next line alone (GNU 776-781, 2881-2884)."""
        text = "\n".join(lines) + "\n"
        once = _formatter().format(text).content
        assert _formatter().format(once).content == once
        assert once.splitlines()[-1] == lines[-1]

    def test_rule_with_continued_header_still_gets_recipe(self):
        """'prog: \\' continued with a tab-indented prerequisite is a rule
        (GNU 776-781, 2881-2884), so 'echo built' lacks its TAB."""
        lines = ["prog: " + BS, "\tmain.c", "echo built"]
        assert _formatted_lines(lines) == [
            "prog: " + BS,
            "\tmain.c",
            "\techo built",
            "",
        ]

    def test_continued_command_after_rule_still_repaired(self):
        """'echo a \\' is itself a recipe line that lacks its TAB, so the line
        after its continuation is repaired too, in the same pass."""
        lines = ["all:", "echo a " + BS, "\tb", "echo c"]
        expected = ["all:", "\techo a " + BS, "\tb", "\techo c", ""]
        assert _formatted_lines(lines) == expected

    def test_recipe_continuation_is_not_a_variable_line(self):
        """'config: path=/tmp' continues the recipe line above it, so it is
        recipe text (GNU 2910-2915), not a target-specific variable, and
        'echo done' still lacks its TAB."""
        lines = ["test:", "\t./run --opt " + BS, "config: path=/tmp", "echo done"]
        assert _formatted_lines(lines)[3] == "\techo done"
        _, errors, _ = _format(lines, fix_missing_recipe_tabs=False)
        assert f"4: Error: {MISSING_TAB}" in errors

    @pytest.mark.parametrize("text", ["sinclude none.mk", "vpath x"])
    def test_recipe_continuation_keeps_its_repair(self, text):
        """A column-0 line that continues a recipe line is recipe text, not a
        directive. It gets a TAB as before, which make removes from a
        continuation line, so the command does not change (GNU 2910-2915,
        2922-2925)."""
        lines = ["all:", "\t@echo a " + BS, text]
        assert _formatted_lines(lines) == ["all:", "\t@echo a " + BS, "\t" + text, ""]

    def test_continued_assignment_after_recipe_keeps_column(self):
        """'FOO \\' and '= bar' form the assignment 'FOO = bar' (GNU 776-781),
        which ends the rule context; with a TAB it is recipe text and FOO is
        never set."""
        lines = ["all:", "\t@echo a", "FOO " + BS, "= bar"]
        assert _formatted_lines(lines) == [*lines, ""]

    def test_colon_in_comment_does_not_make_a_rule(self):
        """'foo bar # a: b' has its only ':' in the comment (GNU 730-742), so
        it is not a rule and 'foo \\' still lacks its TAB."""
        lines = ["all:", "\t@echo a", "foo " + BS, "bar # a: b"]
        expected = ["all:", "\t@echo a", "\tfoo " + BS, "bar # a: b", ""]
        assert _formatted_lines(lines) == expected


class TestDirectiveLinesWithColons:
    """A directive with a ':' in it, or in its comment, is not a rule."""

    @pytest.mark.parametrize(
        "lines",
        [
            ["vpath %.c src:lib", "$(foreach o,a b,$(info $(o)))"],
            ["all:", "\t@echo a", "vpath %.c src:lib", "$(EMPTY)"],
            ["all:", "\t@echo a", "export foo: bar", "$(EMPTY)"],
        ],
    )
    def test_line_after_directive_with_colon_keeps_column(self, lines):
        """'vpath %.c src:lib' lists two directories (GNU 1826-1829) and
        'export foo: bar' is an export directive (10892-10897). Neither starts
        a rule context, and both end one, so the next line is no recipe line
        (2881-2884, 11292-11297)."""
        assert _formatted_lines(lines)[len(lines) - 1] == lines[-1]

    @pytest.mark.parametrize(
        "lines",
        [
            ["define setup", "$(info setup ran)", "endef", "ifdef DEBUG"]
            + ["CFLAGS += -g", "endif # debug: OPT = -O0", "$(call setup)"]
            + ["all: ; @echo ok"],
            ["define T", "$(1): ; @echo built $(1)", "endef", "ifdef A"]
            + ["endif # note: MODE = fast"]
            + ["$(foreach t,x y,$(eval $(call T,$(t))))", "all: x y"],
            ["include config.mk # sets: PREFIX = /usr/local", "$(call check)"],
        ],
    )
    def test_comment_after_directive_does_not_make_a_rule(self, lines):
        """The comment is not part of the directive (GNU 730-742, 1209-1214),
        so the next line keeps its column and is never reported."""
        assert _formatted_lines(lines) == [*lines, ""]
        formatted, errors, _ = _format(lines, fix_missing_recipe_tabs=False)
        assert formatted == [*lines, ""]
        assert not any(MISSING_TAB in error for error in errors)

    def test_conditional_keeps_rule_context(self):
        """A conditional inside a recipe selects recipe lines (GNU 5315-5333),
        so a line after 'endif' can still lack its TAB."""
        lines = ["all:", "ifndef DEBUG", "\t@echo nodebug"]
        lines += ["endif # DEBUG: extra output", "echo done"]
        assert _formatted_lines(lines)[4] == "\techo done"

    @pytest.mark.parametrize(
        "directive", ["vpath foo: X = 1", "unexport foo: X = 1", "-include foo: X = 1"]
    )
    def test_directive_with_variable_text_is_not_a_rule(self, directive):
        """A directive line is not a target-specific variable either (GNU
        10847-10913), so it does not start a rule context."""
        lines = [directive, "echo hi"]
        assert _formatted_lines(lines) == [*lines, ""]


class TestDefineDirectives:
    """Define directives with modifiers, and their bodies, are left alone."""

    @pytest.mark.parametrize("modifier", ["override", "private"])
    def test_modifier_define_after_recipe_keeps_column(self, modifier):
        """'override define' and 'private define' start a define body (GNU
        4776-4781, 4795-4799). With a TAB, the define line becomes a recipe
        line and make stops with "missing separator" at the body."""
        lines = ["all:", "\t@echo a", f"{modifier} define MSG", "hello", "endef"]
        lines += ["show:", "\t@echo $(MSG)"]
        assert _formatted_lines(lines) == [*lines, ""]

    @pytest.mark.parametrize("modifier", ["override", "export", "private"])
    def test_body_of_modifier_define_is_unchanged(self, modifier):
        """A define body is the variable's value; a TAB added to 'echo two'
        changes it (GNU 4795-4799, 4776-4781)."""
        lines = [f"{modifier} define BODY", "\t@echo one", "echo two", "endef"]
        lines += ["all:", "\t@echo $(BODY)"]
        assert _formatted_lines(lines) == [*lines, ""]

    def test_modifier_define_inside_body_does_not_nest(self):
        """Inside a body only a bare 'define' nests, so the first 'endef'
        ends OUTER here, and 'echo b' after the recipe is still repaired (GNU
        4823-4827)."""
        lines = ["define OUTER", "override define INNER", "x", "endef", "all:"]
        lines += ["\t@echo a", "echo b"]
        expected = lines[:6] + ["\techo b", ""]
        assert _formatted_lines(lines) == expected

    def test_bare_define_inside_body_nests(self):
        """A nested 'define' needs its own 'endef' (GNU 4823-4827), so
        'echo b' is still part of OUTER's body."""
        lines = ["define OUTER", "define INNER", "x", "endef", "all:"]
        lines += ["\t@echo a", "echo b", "endef"]
        assert _formatted_lines(lines) == [*lines, ""]

    def test_tab_led_endef_does_not_end_body(self):
        """A line that starts with the recipe prefix is never 'endef' (GNU
        4825-4827), so 'echo x' is still body text."""
        lines = ["define BODY", "\tendef", "echo x", "endef"]
        lines += ["all:", "\t@echo $(BODY)"]
        assert _formatted_lines(lines) == [*lines, ""]

    @pytest.mark.parametrize(
        "body_end",
        [
            ["endef # TPL"],
            ["\tdefine NOTE", "endef"],
        ],
    )
    def test_lines_kept_before_stay_unrepaired(self, body_end):
        """Lines after 'endef # TPL', or after a body with a tab-indented
        'define', were kept as written before and still are. Here make
        accepts the '$(foreach ...)' line, which expands to nothing (GNU
        6381-6390); with a TAB it would become recipe text."""
        lines = ["define TPL", "$(1): ; @echo built $(1)", *body_end]
        lines += ["all:", "\t@echo all", "$(foreach t,x,$(eval $(call TPL,$(t))))"]
        assert _formatted_lines(lines) == [*lines, ""]
        formatted, errors, _ = _format(lines, fix_missing_recipe_tabs=False)
        assert formatted == [*lines, ""]
        assert not any(MISSING_TAB in error for error in errors)

    def test_modifier_define_body_ends_at_endef_with_comment(self):
        """'endef' followed by a blank ends the body; make removes the comment
        after it (GNU 4797-4799; make 3.81 and 4.4 agree). 'echo b' after
        the recipe is outside the body and lacks its TAB."""
        lines = ["override define X", "x", "endef # end of X", "all:", "\t@echo a"]
        lines.append("echo b")
        assert _formatted_lines(lines) == [*lines[:5], "\techo b", ""]
        _, errors, _ = _format(lines, fix_missing_recipe_tabs=False)
        assert f"6: Error: {MISSING_TAB}" in errors

    def test_endef_followed_by_hash_does_not_end_body(self):
        """make only takes 'endef' followed by a blank or the end of the line
        (make 3.81 and 4.4 agree), so the body goes on to the last 'endef'
        and keeps 'echo b' as written (GNU 4795-4799)."""
        lines = ["define BODY", "x", "endef#not-the-end", "all:", "\t@echo a"]
        lines += ["echo b", "endef", "show: ; $(info [$(BODY)])"]
        assert _formatted_lines(lines) == [*lines, ""]

    @pytest.mark.parametrize("prefix", ["\t", ""])
    def test_define_in_recipe_continuation_opens_no_body(self, prefix):
        """A line that continues a recipe line is recipe text, even when it
        reads 'override define' (GNU 2910-2915, 4825-4827), so 'echo oops'
        after the recipe still lacks its TAB."""
        lines = ["help:", "\t@echo usage: " + BS, prefix + "override define X"]
        lines += ["\t@echo more", "echo oops"]
        assert _formatted_lines(lines)[4] == "\techo oops"
        _, errors, _ = _format(lines, fix_missing_recipe_tabs=False)
        assert f"5: Error: {MISSING_TAB}" in errors


class TestTabLedDefineLines:
    """A 'define' line that starts with a TAB, as TabsRule may write it."""

    @pytest.mark.parametrize(
        "before", [["prog: cflags = -g"], ["export foo: bar"], ["vpath %.c src"]]
    )
    def test_space_led_modifier_define_is_stable(self, before):
        """'  override define MSG' after a line that is no rule starts a body
        (GNU 2881-2884, 4776-4781). TabsRule indents it with a TAB, which
        still starts a body there, because no rule context reaches it
        (1217-1219), so the second pass keeps 'hello' as written too."""
        lines = [*before, "  override define MSG", "hello", "endef"]
        lines.append("show: ; $(info [$(MSG)])")
        once = _formatter().format("\n".join(lines) + "\n").content
        assert once.splitlines()[len(before) + 1] == "hello"
        assert _formatter().format(once).content == once

    @pytest.mark.parametrize(
        "lines",
        [
            ["\toverride define MSG", "hello", "endef"],
            ["X = 1", "\toverride define MSG", "hello", "endef"],
            ["ifndef NOPE", "\toverride define MSG", "hello", "endef", "endif"],
            ["X = 1", "\toverride define MSG", "\tendef", "hello", "endef"],
        ],
    )
    def test_tab_led_modifier_define_outside_rule_keeps_body(self, lines):
        """Outside a rule context make reads a line that starts with a TAB as
        makefile syntax (GNU 1217-1219, 2881-2884), so '\\toverride define
        MSG' starts a body (4776-4781), which a TAB-led 'endef' does not end
        (4825-4827)."""
        lines = [*lines, "show: ; $(info [$(MSG)])"]
        assert _formatted_lines(lines) == [*lines, ""]

    def test_space_led_modifier_define_after_recipe_is_stable(self):
        """'  override define MSG' after a recipe line starts a body (GNU
        2881-2884, 4776-4781), so 'hello' keeps its column, and a second pass
        changes nothing, also after TabsRule has indented the 'define' line
        with a TAB."""
        lines = ["all:", "\t@echo all", "  override define MSG", "hello", "endef"]
        once = _formatter().format("\n".join(lines) + "\n").content
        assert once.splitlines()[3] == "hello"
        assert _formatter().format(once).content == once

    def test_tab_led_define_after_recipe_ends_at_tab_led_endef(self):
        """Every line here after the rule is a recipe line (GNU 2881-2884),
        so 'echo b' after the TAB-led 'endef' still lacks its TAB."""
        lines = ["all:", "\t@echo a", "\toverride define X", "\tendef", "echo b"]
        assert _formatted_lines(lines) == [*lines[:4], "\techo b", ""]


class TestDefineLogicalLines:
    """make reads define directives and body lines as logical lines."""

    @pytest.mark.parametrize("first", ["foo " + BS, "\tfoo " + BS])
    def test_define_on_continuation_line_does_not_nest(self, first):
        """The body line 'foo define Y' is one logical line (GNU 776-781) that
        does not start with 'define', so it does not nest (4823-4827). The
        first 'endef' ends X, and 'echo b' after the recipe lacks its TAB."""
        lines = ["override define X", first, "define Y", "endef", "all:"]
        lines += ["\t@echo a", "echo b"]
        assert _formatted_lines(lines) == [*lines[:6], "\techo b", ""]
        _, errors, _ = _format(lines, fix_missing_recipe_tabs=False)
        assert f"7: Error: {MISSING_TAB}" in errors

    def test_endef_continued_on_next_line_ends_body(self):
        """'endef\\' and '# end' form the line 'endef # end' (GNU 776-781),
        which ends the body (4797-4799), so 'echo b' after the recipe lacks
        its TAB."""
        lines = ["override define X", "x", "endef" + BS, "# end", "all:"]
        lines += ["\t@echo a", "echo b"]
        assert _formatted_lines(lines) == [*lines[:6], "\techo b", ""]
        _, errors, _ = _format(lines, fix_missing_recipe_tabs=False)
        assert f"7: Error: {MISSING_TAB}" in errors

    def test_endef_on_continuation_line_does_not_end_body(self):
        """'a \\' and 'endef' form the body line 'a endef' (GNU 776-781), so
        the body goes on to the last 'endef' and 'echo b' is kept."""
        lines = ["define X", "a " + BS, "endef", "all:", "\t@echo a", "echo b"]
        lines += ["endef", "show: ; $(info [$(X)])"]
        assert _formatted_lines(lines) == [*lines, ""]

    def test_continued_assignment_to_define_opens_no_body(self):
        """'override define \\' and '= 1' form 'override define = 1' (GNU
        776-781), which GNU make 4.x reads as an assignment to the variable
        'define' (4091-4092, 10883-10886), so no body starts and 'echo b'
        after the recipe lacks its TAB."""
        lines = ["override define " + BS, "= 1", "all:", "\t@echo a", "echo b"]
        assert _formatted_lines(lines) == [*lines[:4], "\techo b", ""]
        _, errors, _ = _format(lines, fix_missing_recipe_tabs=False)
        assert f"5: Error: {MISSING_TAB}" in errors


class TestEndefOutsideBody:
    """Outside a define body, 'endef' is an ordinary word for GNU make 4.x."""

    def test_rule_named_endef_gets_its_recipe_repaired(self):
        """'endef : foo' is a rule for make 4.x (GNU 4797-4799), so 'echo hi'
        lacks its TAB, on the first pass already."""
        text = "endef : foo\necho hi\nfoo: ; @echo foo\n"
        once = _formatter().format(text).content
        assert once.splitlines()[1] == "\techo hi"
        assert _formatter().format(once).content == once


class TestTabLedSyntaxOutsideRuleContext:
    """A line that starts with a TAB is a recipe line only in a rule context."""

    @pytest.mark.parametrize(
        "lines",
        [
            ["vpath %.c src", "\tsinclude none.mk", "$(EMPTY)"],
            ["prog: cflags = -g", "\tsinclude none.mk", "$(EMPTY)"],
            ["ifndef NO_SETUP", "\tEXE = .exe", "$(call setup)", "endif"],
            ["ifdef NOPE", "\tEXE = .exe", "else", "\tEXE = .bin", "$(call setup)"]
            + ["endif"],
            ["ifdef NOPE", "all:", "else", "\tX = 1", "$(call setup)", "endif"],
            ["ifdef NOPE", "all:", "ifdef X", "\tA = 1", "endif", "else"]
            + ["\tEXE = .bin", "$(call setup)", "endif"],
            ["define A", "x", "endef", "\tsinclude none.mk", "$(EMPTY)"],
        ],
    )
    def test_line_after_tab_led_makefile_syntax_keeps_column(self, lines):
        """Outside a rule context make reads the TAB-led line as makefile
        syntax (GNU 1217-1219, 2881-2884); a define ends a rule context like
        any variable definition. An 'else' branch starts where its 'ifdef'
        did, since make ignores the branch before it, nested conditionals
        included (5345-5358, 5399-5421). A TAB would turn the next line into a
        recipe line without a rule, which make rejects ("recipe commences
        before first target", 11292-11297)."""
        assert _formatted_lines(lines) == [*lines, ""]
        formatted, errors, _ = _format(lines, fix_missing_recipe_tabs=False)
        assert formatted == [*lines, ""]
        assert not any(MISSING_TAB in error for error in errors)

    @pytest.mark.parametrize(
        "lines",
        [
            ["all:", "ifdef NOPE", "\t@echo a", "else", "\t@echo b", "echo c"]
            + ["endif"],
            ["all:", "\t@echo a", "", "\t@echo b", "echo c"],
        ],
    )
    def test_line_after_recipe_line_in_rule_context_still_repaired(self, lines):
        """Conditionals and blank lines keep a rule context (GNU 2881-2886,
        5325-5333), so 'echo c' is a recipe line that lacks its TAB."""
        expected = [*lines, ""]
        expected[lines.index("echo c")] = "\techo c"
        assert _formatted_lines(lines) == expected

    @pytest.mark.parametrize(
        "lines",
        [
            ["# bake-format off", "all:", "# bake-format on", "\t@echo a", "echo c"],
            ["# bake-format off", "all:", "\t@echo a", "# bake-format on"]
            + ["\t@echo b", "echo c"],
        ],
    )
    def test_rule_in_disabled_region_keeps_repair(self, lines):
        """The rule above the recipe line may be in a '# bake-format off'
        region, which the rule does not see, so 'echo c' is still a recipe
        line that lacks its TAB (GNU 2881-2884)."""
        formatted = _formatter().format("\n".join(lines) + "\n").content
        expected = [*lines]
        expected[lines.index("echo c")] = "\techo c"
        assert formatted == "\n".join(expected) + "\n"


class TestRepairStillApplies:
    """Lines that make rejects outside a recipe still get their TAB."""

    def test_column0_command_after_recipe_still_repaired(self):
        """GNU 11283-11290: recipe lines must start with a TAB."""
        lines = ["all:", "\t@echo a", "echo b"]
        assert _formatted_lines(lines) == ["all:", "\t@echo a", "\techo b", ""]

    @pytest.mark.parametrize(
        ("lines", "expected"),
        [
            (["all:", "    $(MAKE)"], ["all:", "\t$(MAKE)", ""]),
            (["all:", "$(CC) -c x.c"], ["all:", "\t$(CC) -c x.c", ""]),
            (["all:", "\t@echo a", "$(MAKE)"], ["all:", "\t@echo a", "\t$(MAKE)", ""]),
        ],
    )
    def test_commands_after_rule_still_repaired(self, lines, expected):
        """A reference such as '$(MAKE)' or '$(CC)' expands to a command, which
        make rejects outside a recipe ("missing separator", GNU 11275-11290),
        so these lines are recipe lines that lack their TAB."""
        assert _formatted_lines(lines) == expected

    def test_missing_tab_reported_without_fix(self):
        """With fix_missing_recipe_tabs=False the line is reported, not
        changed."""
        lines, errors, _ = _format(["foo:", "echo a"], fix_missing_recipe_tabs=False)
        assert lines == ["foo:", "echo a", ""]
        assert f"2: Error: {MISSING_TAB}" in errors


class TestNoFalseErrors:
    """Makefile syntax after a recipe is never reported as a missing TAB."""

    @pytest.mark.parametrize(
        "syntax_lines",
        [
            ["vpath %.c src"],
            ["$(info done)"],
            ["$(eval " + BS, "$(call TPL,x))"],
            ["override define MSG", "hello", "endef"],
            ["foo " + BS, "bar: baz"],
        ],
    )
    def test_no_error_without_fix(self, syntax_lines):
        """With fix_missing_recipe_tabs=False these lines produce no error,
        which would make 'mbake format --stdin' exit with status 2."""
        lines = ["all:", "\t@echo all", *syntax_lines, "other:", "\t@echo other"]
        formatted, errors, _ = _format(lines, fix_missing_recipe_tabs=False)
        assert formatted == [*lines, ""]
        assert not any(MISSING_TAB in error for error in errors)

    def test_no_check_mode_message(self):
        """--check reports nothing for 'vpath' after a recipe."""
        lines = ["all:", "\t@echo all", "vpath %.c src", "other:", "\t@echo other"]
        _, errors, warnings = _formatter().format_lines(lines, check_only=True)
        assert not any(MISSING_TAB in message for message in errors + warnings)


class TestPhonyDetection:
    """Target-specific variable lines are not rules for .PHONY detection."""

    @pytest.mark.parametrize(
        ("lines", "expected"),
        [
            (["clean: rmflags = -f", "all: prog", "\t@echo done"], {"all"}),
            (["test: suite = unit", "", "prog: prog.o", "\tcc -o prog prog.o"], set()),
            (["install: prefix != echo /usr", "all:", "\t@echo all"], {"all"}),
            (["docs: override fmt = html", "all:", "\t@echo all"], {"all"}),
        ],
    )
    def test_target_with_only_variables_is_not_phony(self, lines, expected):
        """A target that only has target-specific variables has no rule here
        (GNU 4938-4951), so no .PHONY entry is added for it."""
        formatted = _formatted_lines(
            lines, auto_insert_phony_declarations=True, group_phony_declarations=True
        )
        assert _phony_targets(formatted) == expected

    def test_check_mode_suggestion_skips_variable_targets(self):
        """--check suggests .PHONY only for the real rule."""
        lines = ["clean: rmflags = -f", "all: prog", "\t@echo done"]
        _, _, warnings = _formatter().format_lines(lines, check_only=True)
        suggestions = [w for w in warnings if "Consider adding .PHONY" in w]
        assert len(suggestions) == 1
        targets = suggestions[0].split("targets:", 1)[1].replace(",", " ").split()
        assert set(targets) == {"all"}

    def test_ungrouped_phony_goes_above_the_rule(self):
        """An individual .PHONY line goes above the rule of its target, not
        above that target's variable line."""
        lines = ["install: prefix = /usr/local", "", "all: prog", "\t@echo all", ""]
        lines += ["install: all", "\tcp prog $(prefix)/bin"]
        formatted = _formatted_lines(
            lines, auto_insert_phony_declarations=True, group_phony_declarations=False
        )
        rule = formatted.index("install: all")
        assert formatted[rule - 1] == ".PHONY: install"
        variable = formatted.index("install: prefix = /usr/local")
        assert variable == 0 or not formatted[variable - 1].startswith(".PHONY")

    def test_directive_comment_does_not_move_phony_line(self):
        """'endif # clean: OPT = -O0' is a directive with a comment (GNU
        730-742), so '.PHONY: clean' goes above the rule 'clean:', outside the
        conditional."""
        lines = ["ifdef DEBUG", "CFLAGS += -g", "endif # clean: OPT = -O0", ""]
        lines += ["all:", "\t@echo all", "", "clean:", "\t@echo clean"]
        formatted = _formatted_lines(
            lines, auto_insert_phony_declarations=True, group_phony_declarations=False
        )
        assert formatted[formatted.index("clean:") - 1] == ".PHONY: clean"
        assert formatted.index(".PHONY: clean") > formatted.index(lines[2])

    @pytest.mark.parametrize("directive", ["vpath foo: X = 1", "unexport clean: X = 1"])
    def test_directive_with_variable_text_is_not_phony(self, directive):
        """A directive line names no targets (GNU 10847-10913)."""
        lines = [directive, "all:", "\t@echo all"]
        formatted = _formatted_lines(
            lines, auto_insert_phony_declarations=True, group_phony_declarations=True
        )
        assert _phony_targets(formatted) == {"all"}

    def test_check_mode_skips_endef_comment(self):
        """'endef # usage: SETUP = 1' ends a define body; it names no
        targets (GNU 4797-4799, 730-742)."""
        lines = ["define setup", "$(info setup ran)", "endef # usage: SETUP = 1"]
        lines += ["$(call setup)", "all: ; @echo ok"]
        _, _, warnings = _formatter().format_lines(lines, check_only=True)
        suggestions = [w for w in warnings if "Consider adding .PHONY" in w]
        assert len(suggestions) == 1
        targets = suggestions[0].split("targets:", 1)[1].replace(",", " ").split()
        assert set(targets) == {"all"}


# Each input makes make stop with "missing separator" at the listed lines,
# which lack their TAB after a define body has ended: (lines, goal, the
# 1-based lines that lack their TAB)
DEFINE_END_CASES = [
    (
        ["define OUTER", "\toverride define INNER", "x", "endef", "all:"]
        + ["\t@echo a", "echo b"],
        "all",
        [7],
    ),
    (
        ["define BODY", "x", "\tendef", "endef # end of BODY", "all:"]
        + ["\t@echo a", "echo b"],
        "all",
        [7],
    ),
    (
        ["all:", "\t@echo a", "\toverride define X", "echo b", "define Y", "y"]
        + ["endef", "clean:", "\t@echo c", "rm -f x"],
        "all",
        [4, 10],
    ),
    (
        ["override define MSG", "hello", "# bake-format off", "endef"]
        + ["# bake-format on", "all:", "\t@echo a", "echo b"],
        "all",
        [8],
    ),
]


class TestDefineBodiesEndWhereMakeEndsThem:
    """Lines after a define body are repaired as before (GNU 4797-4799).

    The cases: a TAB-led 'override define' inside a body does not nest
    (4823-4827); a TAB-led 'endef' does not end a body, and 'endef' with a
    comment does; a TAB-led 'override define' after a recipe line is itself a
    recipe line (2881-2884), so no body starts there; an 'endef' in a
    '# bake-format off' region ends the body too.
    """

    @pytest.mark.parametrize(("lines", "goal", "missing"), DEFINE_END_CASES)
    def test_lines_after_body_are_repaired(self, lines, goal, missing):
        expected = [*lines, ""]
        for number in missing:
            expected[number - 1] = "\t" + lines[number - 1]
        text = "\n".join(lines) + "\n"
        once = _formatter().format(text).content
        assert once == "\n".join(expected)
        assert _formatter().format(once).content == once

    @pytest.mark.parametrize(("lines", "goal", "missing"), DEFINE_END_CASES)
    def test_missing_tabs_are_reported(self, lines, goal, missing):
        _, errors, _ = _format(lines, fix_missing_recipe_tabs=False)
        reported = [error for error in errors if MISSING_TAB in error]
        assert reported == [f"{number}: Error: {MISSING_TAB}" for number in missing]
        _, errors, warnings = _formatter().format_lines(lines, check_only=True)
        for number in missing:
            assert f"{number}: Error: {MISSING_TAB}" in errors + warnings


class TestRuleContextAcrossLines:
    """Where a rule context reaches a line does not depend on the pass."""

    def test_rule_named_endef_with_recipe_line(self):
        """'endef : foo' is a rule for make 4.x (GNU 4797-4799), so 'echo hi'
        after its recipe line lacks its TAB, on the first pass already."""
        text = "endef : foo\n\t@echo x\necho hi\nfoo: ; @echo foo\n"
        once = _formatter().format(text).content
        assert once.splitlines()[2] == "\techo hi"
        assert _formatter().format(once).content == once

    def test_continued_rule_that_starts_with_spaces(self):
        """make reads '    curl -X POST \\' and 'https://example.com/hook' as
        one logical line (GNU 776-781) with a ':', which is a rule whether
        or not it gets a TAB, so 'echo done' lacks its TAB on the first
        pass already (2881-2886)."""
        lines = ["deploy:", "\t@echo start", "", "    curl -X POST " + BS]
        lines += ["https://example.com/hook", "echo done"]
        once = _formatter().format("\n".join(lines) + "\n").content
        assert once.splitlines()[5] == "\techo done"
        assert _formatter().format(once).content == once

    def test_automake_else_inside_make_conditional(self):
        """The 'else' belongs to the automake 'if', not to 'ifdef A', so the
        rule above it may still be in effect and 'echo c' keeps its repair."""
        lines = ["X = 1", "ifdef A", "all:", "if COND", "\t@echo a", "else"]
        lines += ["\t@echo b", "echo c", "endif", "endif"]
        assert _formatted_lines(lines)[7] == "\techo c"
        _, errors, _ = _format(lines, fix_missing_recipe_tabs=False)
        assert f"8: Error: {MISSING_TAB}" in errors

    def test_rule_in_disabled_region_above_a_comment(self):
        """The rule in the '# bake-format off' region above makes 'echo bar' a
        recipe line that lacks its TAB (GNU 2881-2886)."""
        lines = ["X = 0", "# bake-format off", "foo:", "\t@echo a"]
        lines += ["# bake-format on", "echo bar"]
        formatted = _formatter().format("\n".join(lines) + "\n").content
        assert formatted.splitlines()[5] == "\techo bar"

    @pytest.mark.parametrize(
        "lines",
        [
            ["X = 1", "\tsinclude none.mk", "  sinclude none2.mk", "$(EMPTY)"],
            ["ifndef NOPE", "\tsinclude none.mk", "    sinclude none2.mk"]
            + ["$(EMPTY)", "endif"],
        ],
    )
    def test_tab_led_syntax_keeps_no_rule_context(self, lines):
        """Outside a rule context the TAB-led 'sinclude' lines are makefile
        syntax (GNU 1217-1219), also after TabsRule has indented the second
        one with a TAB, so '$(EMPTY)' keeps its column on every pass."""
        once = _formatter().format("\n".join(lines) + "\n").content
        assert "$(EMPTY)" in once.splitlines()
        assert _formatter().format(once).content == once


class TestCallsThatExpandToBlanks:
    """'$(foreach ...)' and '$(if ...)' of calls that expand to nothing."""

    @pytest.mark.parametrize(
        "call",
        [
            "$(foreach prog,$(PROGRAMS),$(eval $(call PROGRAM_template,$(prog))))",
            "$(foreach t,a b, $(info $(t)) $(eval X += $(t)) )",
            "$(if $(DEBUG),$(info debug),$(warning no debug))",
            "$(if $(DEBUG),$(eval CFLAGS += -g))",
            "${foreach t,a b,${eval ${t}: ; @true}}",
        ],
    )
    @pytest.mark.parametrize("before", [["all: server"], ["all:", "\t@echo all"]])
    def test_line_keeps_column(self, call, before):
        """The manual's '$(foreach ...$(eval ...))' idiom (GNU 6424-6428)
        expands to blanks only (6146-6159, 6388-6390), so make reads it as
        makefile syntax anywhere; with a TAB it would become recipe text."""
        lines = [*before, call]
        assert _formatted_lines(lines) == [*lines, ""]
        _, errors, _ = _format(lines, fix_missing_recipe_tabs=False)
        assert not any(MISSING_TAB in error for error in errors)

    @pytest.mark.parametrize(
        "call",
        [
            "$(foreach t,x,$(t))",
            "$(if $(DEBUG),$(CC) -g)",
            "$(foreach t,x)",
            "$(foreach t,x,$(eval y)) $(MAKE)",
            "$(if $(X),$(eval a),$(call b))",
        ],
    )
    def test_calls_with_other_results_are_repaired(self, call):
        """These can expand to a command, which make rejects outside a recipe
        ("missing separator", GNU 11275-11290), so they lack their TAB."""
        lines = ["all:", "\t@echo all", call]
        assert _formatted_lines(lines) == ["all:", "\t@echo all", "\t" + call, ""]


# make runs with a minimal environment so that no inherited variable (such as
# MAKEFLAGS) changes what it reads.
_MAKE_ENV = {"PATH": os.defpath, "LC_ALL": "C"}


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


def _run_make(gnu_make, cwd, text, goal):
    """Run make on text with the goal and return (returncode, stdout).

    '-s' keeps make's own "is up to date" messages out of stdout.
    """
    make, true = gnu_make
    proc = subprocess.run(
        [make, "-s", "-r", "-R", "-f", "-", f"SHELL={true}", goal],
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

    Every input works with make 3.81 and 4.x. Recipes print with $(info ...)
    and run with SHELL=true.
    """

    @pytest.mark.parametrize(
        ("lines", "goal", "expected"),
        [
            (
                [
                    "prog: cflags = -g",
                    "$(info configured)",
                    "",
                    "prog: ; $(info [$(cflags)])",
                ],
                "prog",
                "configured\n[-g]\n",
            ),
            (
                [
                    "define TPL",
                    "$(1): ; $$(info [built $(1)])",
                    "endef",
                    "all: x",
                    "$(eval $(call TPL,x)) # instantiate x",
                ],
                "all",
                "[built x]\n",
            ),
            (
                ["all:", "\t@echo a", "$(info [parsed])  # trace"]
                + ["other: ; $(info [other])"],
                "other",
                "[parsed]\n[other]\n",
            ),
            (
                ["all:", "\t@echo all", "vpath %.c src", "show: x.c ; $(info [$<])"],
                "show",
                "[src/x.c]\n",
            ),
            (
                ["all:", "\t@echo a", "override define MSG", "hello", "endef"]
                + ["show: ; $(info [$(MSG)])"],
                "show",
                "[hello]\n",
            ),
            (
                ["all:", "\t@echo a", "foo " + BS, "bar: baz", "\t$(info [$@])"]
                + ["baz: ; $(info [baz])"],
                "foo",
                "[baz]\n[foo]\n",
            ),
            (
                ["define BODY", "\tendef", "echo x", "endef"]
                + ["show: ; $(info [$(BODY)])"],
                "show",
                "[\tendef\necho x]\n",
            ),
            (CONTINUED_SYNTAX_CASES[0], "both", "[built x]\n[built a]\n"),
            (CONTINUED_SYNTAX_CASES[1], "show", "[src/x.c]\n"),
            (CONTINUED_SYNTAX_CASES[2], "r1", "hello world\n[rule r1]\n"),
            (CONTINUED_SYNTAX_CASES[3], "show", "[a b]\n"),
            (
                ["vpath %.c src:lib", "$(foreach o,a b,$(info $(o)))"]
                + ["show: x.c ; $(info [$<])"],
                "show",
                "a\nb\n[src/x.c]\n",
            ),
            (
                ["define setup", "$(info setup ran)", "endef", "ifdef DEBUG"]
                + ["CFLAGS += -g", "endif # debug: OPT = -O0", "$(call setup)"]
                + ["all: ; $(info ok)"],
                "all",
                "setup ran\nok\n",
            ),
            (
                ["define BODY", "x", "endef#not-the-end", "all:", "\t@echo a"]
                + ["echo b", "endef", "show: ; $(info [$(BODY)])"],
                "show",
                "[x\nendef#not-the-end\nall:\n\t@echo a\necho b]\n",
            ),
            (
                TPL[:2]
                + ["endef # TPL", "all:", "\t@echo all"]
                + ["$(foreach t,x,$(eval $(call TPL,$(t))))"],
                "x",
                "[built x]\n",
            ),
            (
                ["\toverride define MSG", "hello", "endef"]
                + ["show: ; $(info [$(MSG)])"],
                "show",
                "[hello]\n",
            ),
            (
                ["X = 1", "\toverride define MSG", "\tendef", "hello", "endef"]
                + ["show: ; $(info [$(MSG)])"],
                "show",
                "[\tendef\nhello]\n",
            ),
            (
                ["define X", "a " + BS, "endef", "all:", "\t@echo a", "echo b"]
                + ["endef", "show: ; $(info [$(X)])"],
                "show",
                "[a endef\nall:\n\t@echo a\necho b]\n",
            ),
            (
                ["vpath %.c src", "\tsinclude none.mk", "$(EMPTY)"]
                + ["show: x.c ; $(info [$<])"],
                "show",
                "[src/x.c]\n",
            ),
            (
                ["ifdef NOPE", "\tEXE = .exe", "else", "\tEXE = .bin"]
                + ["$(call setup)", "endif", "all: ; $(info [$(EXE)])"],
                "all",
                "[.bin]\n",
            ),
            (
                ["ifdef NOPE", "all:", "ifdef X", "\tA = 1", "endif", "else"]
                + ["\tEXE = .bin", "$(call setup)", "endif"]
                + ["show: ; $(info [$(EXE)])"],
                "show",
                "[.bin]\n",
            ),
            (
                ["define A", "x", "endef", "\tsinclude none.mk", "$(EMPTY)"]
                + ["show: ; $(info [$(A)])"],
                "show",
                "[x]\n",
            ),
            (
                [*TPL, "all: x", "$(foreach t,x,$(eval $(call TPL,$(t))))"],
                "all",
                "[built x]\n",
            ),
            (
                [*TPL, "all: x", "\t$(info [all])"]
                + ["$(foreach t,x,$(eval $(call TPL,$(t))))"],
                "all",
                "[built x]\n[all]\n",
            ),
            (
                [*TPL, "all: x", "$(if $(TPL),$(eval $(call TPL,x)),)"],
                "all",
                "[built x]\n",
            ),
        ],
    )
    def test_formatting_keeps_make_behaviour(
        self, gnu_make, tmp_path, lines, goal, expected
    ):
        """GNU 1209-1229, 2878-2886: make reads each of these lines as
        makefile syntax, before and after formatting."""
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "x.c").write_text("")
        text = "\n".join(lines) + "\n"
        assert _run_make(gnu_make, tmp_path, text, goal) == (0, expected)
        formatted = _formatter().format(text).content
        assert _run_make(gnu_make, tmp_path, formatted, goal) == (0, expected)

    @pytest.mark.parametrize(
        ("lines", "goal", "expected"),
        [
            (SPACE_CONTINUED_SYNTAX_CASES[0], "both", "[built x]\n[built a]\n"),
            (SPACE_CONTINUED_SYNTAX_CASES[1], "all", "[built x]\n"),
            (
                ["prog: cflags = -g", "  override define MSG", "hello", "endef"]
                + ["show: ; $(info [$(MSG)])"],
                "show",
                "[hello]\n",
            ),
            (
                ["all:", "\t@echo a", "vpath %.c src", "  override define MSG"]
                + ["hi", "endef", "show: ; $(info [$(MSG)])"],
                "show",
                "[hi]\n",
            ),
            (
                ["X = 1", "\tsinclude none.mk", "  sinclude none2.mk", "$(EMPTY)"]
                + ["all: ; $(info [$(X)])"],
                "all",
                "[1]\n",
            ),
            (
                ["ifndef NOPE", "\tsinclude none.mk", "    sinclude none2.mk"]
                + ["$(EMPTY)", "endif", "all: ; $(info [ok])"],
                "all",
                "[ok]\n",
            ),
        ],
    )
    def test_second_pass_keeps_make_behaviour(
        self, gnu_make, tmp_path, lines, goal, expected
    ):
        """Formatting the formatted file again keeps what make does (GNU
        776-781, 2881-2884)."""
        text = "\n".join(lines) + "\n"
        assert _run_make(gnu_make, tmp_path, text, goal) == (0, expected)
        twice = _formatter().format(_formatter().format(text).content).content
        assert _run_make(gnu_make, tmp_path, twice, goal) == (0, expected)

    @pytest.mark.parametrize(("lines", "goal", "missing"), DEFINE_END_CASES)
    def test_repaired_file_runs(self, gnu_make, tmp_path, lines, goal, missing):
        """make stops at the lines that lack their TAB (GNU 11283-11290) and
        runs the formatted file."""
        text = "\n".join(lines) + "\n"
        assert _run_make(gnu_make, tmp_path, text, goal)[0] != 0
        formatted = _formatter().format(text).content
        assert _run_make(gnu_make, tmp_path, formatted, goal)[0] == 0
