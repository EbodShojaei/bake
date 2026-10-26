"""Tests for indent_nested_conditionals keeping what GNU make reads.

With indent_nested_conditionals, ConditionalRule indents the lines inside
conditionals with spaces and TabsRule then gives a TAB to a line with leading
spaces that looks like a recipe line that lacks its TAB. make reads a line that
does not start with the recipe prefix as makefile syntax, whatever its leading
spaces, and a line that starts with it as a recipe line in a rule context (GNU
make manual 3.8, lines 1209-1236; 5.1, lines 2878-2905):
- TabsRule no longer gives a TAB to makefile syntax, to a line of only variable
  references, or to a line that no rule context but that of .PHONY reaches;
- ConditionalRule leaves define bodies as written (6.8, lines 4795-4799),
  keeps a line that starts with the recipe prefix where make may read it as a
  recipe line, in any rule context, that of .PHONY included, with a warning
  when it looks like makefile syntax, and keeps the continuation lines of a
  recipe line as written (5.1.1, lines 2918-2925);
- with remove_trailing_whitespace off, a backslash followed by whitespace
  never becomes a line continuation (3.1.1, lines 762-769).

The make-backed tests take their expected value from GNU make itself: make must
read the formatted makefile as it reads the original one. The tests in
TestUnchangedBehaviour pin what already worked; all others failed before.
"""

import os
import re
import shutil
import subprocess

import pytest

from mbake.config import Config, FormatterConfig
from mbake.core.formatter import MakefileFormatter
from mbake.core.rules.tabs import TabsRule
from mbake.utils.rule_context import RECIPE, scan_makefile

T = "\t"
BS = "\\"  # one backslash, to keep continuation lines readable

INDENT2 = {"indent_nested_conditionals": True, "tab_width": 2}
INDENT4 = {"indent_nested_conditionals": True, "tab_width": 4}
REPORTER107 = {
    "auto_insert_phony_declarations": True,
    "group_phony_declarations": True,
    "phony_at_top": False,
    "indent_nested_conditionals": True,
    "tab_width": 4,
}
CONFIGS = {"indent2": INDENT2, "indent4": INDENT4, "reporter107": REPORTER107}

# make runs with a minimal environment so that no inherited variable (such as
# MAKEFLAGS) changes what it reads.
_MAKE_ENV = {"PATH": os.defpath, "LC_ALL": "C"}

# A second makefile that make reads after the one under test: it prints the
# variables that the makefiles below may set, so that make shows how it read
# them, and has the goal for the database. Nothing is appended to the
# makefile under test itself.
PROBE = (
    "$(info [X=$(X)][Y=$(Y)][Z=$(Z)][my-var=$(my-var)][X.Y=$(X.Y)]"
    "[CFLAGS=$(CFLAGS)][obj-y=$(obj-y)][GIT_CHANGE_DEP=$(GIT_CHANGE_DEP)])\n"
    "$(info [D=$(value D)])\n"
    "__probe__: ;\n"
)

# The reproducers found in review (indent_nested_conditionals, tab width 4).
# make 3.81 ("commands commence before first target") and 4.4.1 ("recipe
# commences before first target", GNU 11292-11297) rejected the old output of
# the first one: the bare '$(R)' line, indented with spaces inside the
# conditional, got a TAB where 'include $(NONE) ' ends the rule context.
REFERENCE_AFTER_INCLUDE = (
    "%.x: ; @echo implicit $@\n.PHONY: t2\nifeq (a,a)\ninclude $(NONE) \n$(R)\n"
    ".PHONY: t1\n# bake-format off\nfoo.x:\n# bake-format on\n\t@echo c\nendif\n"
)
# The same TAB made '$(R)' a second recipe of .PHONY: "overriding commands for
# target '.PHONY'".
REFERENCE_AFTER_PHONY = (
    "%.x: ; @echo implicit $@\n.PHONY: t1 t2 t3\nifeq (a,a)\n$(R)\n"
    "# bake-format off\n.PHONY: t1\n# bake-format on\n\t \n.PHONY: t1\nt4::\nendif\n"
)
# Inside a TAB-led 'ifdef Y', which make reads as a conditional because no rule
# context reaches it, the 'override define D' line got a TAB and became a
# recipe line of '.PHONY: t1 t2', and the body was indented: a second run then
# read the body as recipe lines.
DEFINE_IN_TAB_LED_CONDITIONAL = (
    "%.x: ; @echo implicit $@\nR = r1: ; @echo r1\nt2: t1\n-include $(A)$(B) \n"
    ".PHONY: t1\n\t \n\t@echo a \\\n\t\n\t  \t\nt3: ; @echo t3\nX = a \n"
    "\tifdef Y\noverride V += src:inc \t\n.PHONY: t1 t2\n\t  \n"
    "override define D\n  - item\n\t\nendef\nendif"
)


def _formatter(**config):
    return MakefileFormatter(Config(formatter=FormatterConfig(**config)))


def _format(text, config):
    return _formatter(**config).format(text)


def _in_rule_context(line, extra=""):
    """A makefile with line inside a conditional, in the rule context of t1."""
    return (
        f"R_RULE = r1: ; @echo r1\n{extra}all: ; @echo all\nt1:\n\t@echo t1\n"
        f"ifeq (a,a)\n{line}\nendif\nt2: ; @echo t2\n"
    )


@pytest.fixture(scope="module", params=["make", "gmake"])
def gnu_make(request):
    """Return (make, true, major version), or skip when that GNU make cannot
    run here. 'gmake' is often a second GNU make, such as 4.x next to macOS's
    3.81."""
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


def _run(gnu_make, cwd, options, arguments):
    """Run make on input.mk and probe.mk in cwd."""
    make, true, _ = gnu_make
    return subprocess.run(
        [make, "-r", "-R", *options, "-f", "input.mk", "-f", "probe.mk"]
        + [f"SHELL={true}", *arguments],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=60,
        env=_MAKE_ENV,
    )


def _recipes(database, goals):
    """Return the recipe lines of each goal in the database of 'make -p'."""
    found: dict = {}
    current = None
    for line in database.splitlines():
        if not line:
            current = None
        elif current is not None:
            if line.startswith(T):
                found[current].append(line.strip())
        elif ":" in line and not line.startswith(("#", T)):
            head = line.split(":", 1)[0]
            if head in goals:
                current = head
                found.setdefault(current, [])
    return found


def _make_reads(gnu_make, cwd, text, goals, *settings):
    """Return what make does with text and the probe makefile after it.

    That is the exit status and output of 'make -n' for the goals, the
    recipes of the goals in make's database, and the messages without the
    file names and line numbers that they start with, which other line counts
    would change.
    """
    (cwd / "input.mk").write_text(text, encoding="utf-8")
    (cwd / "probe.mk").write_text(PROBE, encoding="utf-8")
    dry = _run(gnu_make, cwd, ["-n"], [*settings, *goals])
    messages = [re.sub(r"^[^:\s]+:\d+: ", "", m) for m in dry.stderr.splitlines()]
    database = _run(gnu_make, cwd, ["-p", "-q"], [*settings, "__probe__"]).stdout
    return dry.returncode, dry.stdout, _recipes(database, goals), messages


def _assert_make_reads_the_same(
    gnu_make, tmp_path, text, config, goals, *settings, messages=True
):
    """make reads the formatted text as it reads text (and prints the same
    messages, unless messages is False)."""
    before = _make_reads(gnu_make, tmp_path, text, goals, *settings)
    assert before[0] == 0, before
    output = _format(text, config).content
    after = _make_reads(gnu_make, tmp_path, output, goals, *settings)
    if messages:
        assert after == before
    else:
        assert after[:3] == before[:3]


class TestReviewReproducers:
    """The cases found in review, with the 'indent4' configuration."""

    def test_reference_line_after_include_keeps_its_spaces(self):
        lines = _format(REFERENCE_AFTER_INCLUDE, INDENT4).content.splitlines()
        assert lines[4] == "    $(R)"

    def test_reference_line_after_include_reads_the_same(self, gnu_make, tmp_path):
        _assert_make_reads_the_same(
            gnu_make, tmp_path, REFERENCE_AFTER_INCLUDE, INDENT4, ["t1", "t2", "foo.x"]
        )

    def test_reference_line_gives_phony_no_second_recipe(self, gnu_make, tmp_path):
        _assert_make_reads_the_same(
            gnu_make, tmp_path, REFERENCE_AFTER_PHONY, INDENT4, ["t1", "t2", "t3"]
        )

    def test_define_line_in_tab_led_conditional_is_idempotent(self):
        once = _format(DEFINE_IN_TAB_LED_CONDITIONAL, INDENT4).content
        assert _format(once, INDENT4).content == once
        lines = once.splitlines()
        start = lines.index("    override define D")
        assert lines[start + 1 : start + 3] == ["  - item", T]

    def test_define_in_tab_led_conditional_reads_the_same(self, gnu_make, tmp_path):
        """With Y set, make reads the define, whose value keeps its body (GNU
        4795-4799), and no recipe line of '.PHONY: t1 t2' (2878-2884).

        The messages are not compared: in every configuration WhitespaceRule
        removes the whitespace-only recipe lines that only .PHONY owns, whose
        recipe make runs only when .PHONY is named as a goal (1443-1446,
        2234-2240), and with them make's warning about the second recipe of
        .PHONY.
        """
        _assert_make_reads_the_same(
            gnu_make,
            tmp_path,
            DEFINE_IN_TAB_LED_CONDITIONAL,
            INDENT4,
            ["t1", "t2", "t3"],
            "Y=1",
            messages=False,
        )


# Lines inside a conditional in the rule context of t1 that make reads as
# makefile syntax (GNU 1209-1236, 2878-2884). The old output turned each into a
# recipe line or changed it: {name: (line, the goals for 'make -n')}.
SYNTAX_IN_RULE_CONTEXT = {
    "empty_reference": ("$(R)", ["all", "t1", "t2"]),
    "reference_to_a_rule": ("$(R_RULE)", ["all", "t1", "t2", "r1"]),
    "call": ("$(call F,x)", ["all", "t1", "t2"]),
    "info_in_braces": ("${info hi}", ["all", "t1", "t2"]),
    "private_assignment": ("private X = 1", ["all", "t1", "t2"]),
    "dash_in_name": ("my-var = 1", ["all", "t1", "t2"]),
    "dot_in_name": ("X.Y = 1", ["all", "t1", "t2"]),
    "kernel_style_append": ("obj-y += arch.o", ["all", "t1", "t2"]),
    "sinclude": ("sinclude nofile.mk", ["all", "t1", "t2"]),
    "override_define": ("override define D\n  body line\nendef", ["all", "t1"]),
}

# Lines that start with a TAB in the rule context of t1, which make passes to
# the shell (GNU 2897-2905, 5511-5513): the old output re-indented them with
# spaces, which made them makefile syntax.
RECIPE_LINES_IN_RULE_CONTEXT = {
    "conditional": (T + "ifdef Y\n" + T + "@echo y\n" + T + "endif", ["t1"]),
    "append_without_spaces": (T + "CFLAGS+=-g", ["t1"]),
    "conditional_assignment": (T + "X?=1", ["t1"]),
    "shell_assignment": (T + "X=1 echo hi", ["t1"]),
    "append": (T + "CFLAGS += -g", ["t1"]),
    "override": (T + "override X = 1", ["t1"]),
    "include": (T + "-include nofile.mk", ["t1"]),
    "define": (T + "define D\n" + T + "endef", ["t1"]),
    "info": (T + "$(info hi)", ["t1"]),
    "vpath": (T + "vpath %.c src", ["t1"]),
}

# The same with syntax that make 3.81 does not know: {name: (line, goals)}
MAKE4_LINES_IN_RULE_CONTEXT = {
    "define_with_operator": ("define D =\n   spaced body\nendef", ["all", "t1"]),
    "export_define": ("export define D\nbody\nendef", ["all", "t1"]),
    "undefine": ("undefine X", ["all", "t1"]),
    "shell_assignment_operator": (T + "X!=echo hi", ["t1"]),
}

ALL_LINES = {
    **SYNTAX_IN_RULE_CONTEXT,
    **RECIPE_LINES_IN_RULE_CONTEXT,
    **MAKE4_LINES_IN_RULE_CONTEXT,
}


class TestLinesInsideConditionals:
    """make reads each formatted makefile as it reads the original one."""

    @pytest.mark.parametrize("config", sorted(CONFIGS))
    @pytest.mark.parametrize(
        "name", sorted({**SYNTAX_IN_RULE_CONTEXT, **RECIPE_LINES_IN_RULE_CONTEXT})
    )
    def test_make_reads_the_same(self, gnu_make, tmp_path, name, config):
        line, goals = ALL_LINES[name]
        text = _in_rule_context(line)
        _assert_make_reads_the_same(gnu_make, tmp_path, text, CONFIGS[config], goals)

    @pytest.mark.parametrize("config", sorted(CONFIGS))
    @pytest.mark.parametrize("name", sorted(MAKE4_LINES_IN_RULE_CONTEXT))
    def test_make_4_reads_the_same(self, gnu_make, tmp_path, name, config):
        if gnu_make[2] < 4:
            pytest.skip("make 3.81 does not know this syntax")
        line, goals = ALL_LINES[name]
        text = _in_rule_context(line)
        _assert_make_reads_the_same(gnu_make, tmp_path, text, CONFIGS[config], goals)

    @pytest.mark.parametrize("name", sorted(RECIPE_LINES_IN_RULE_CONTEXT))
    def test_recipe_lines_stay_as_written(self, name):
        line = RECIPE_LINES_IN_RULE_CONTEXT[name][0]
        output = _format(_in_rule_context(line), INDENT4).content
        assert line in output.split("\nifeq (a,a)\n", 1)[1]

    @pytest.mark.parametrize("config", sorted(CONFIGS))
    def test_define_line_second_run_changes_nothing(self, config):
        """The define line keeps its spaces, so the next run still reads its
        body as a body (GNU 4795-4799)."""
        line = SYNTAX_IN_RULE_CONTEXT["override_define"][0]
        text = _in_rule_context(line, extra=".PHONY: all t1 t2\n")
        once = _format(text, CONFIGS[config]).content
        assert _format(once, CONFIGS[config]).content == once


class TestTabsRuleConversion:
    """TabsRule gives a TAB only to a line that make cannot read as syntax."""

    @pytest.mark.parametrize(
        "line",
        [
            "  $(call setup)",
            "  sinclude x.mk",
            "  $(R)",
            "  ${info x}",
            "  undefine X",
            "  override define D",
            "  private X = 1",
            "  obj-y += a.o",
        ],
    )
    def test_makefile_syntax_after_a_rule_is_not_a_recipe(self, line):
        lines = ["foo:", T + "@echo a", line]
        rule = TabsRule()
        reading = rule.make_reading(lines, {}, True)
        assert reading is not None
        assert not rule.converts_to_recipe(line, 2, lines, T, reading=reading)
        assert rule.format(list(lines), INDENT4).lines[2] == line

    @pytest.mark.parametrize("line", ["  echo hi", "  $(MAKE) -C sub", "  @$(CC) x"])
    def test_recipe_line_without_its_tab_still_gets_one(self, line):
        lines = ["foo:", T + "@echo a", line]
        rule = TabsRule()
        reading = rule.make_reading(lines, {}, True)
        assert reading is not None
        assert rule.converts_to_recipe(line, 2, lines, T, reading=reading)
        assert rule.format(list(lines), INDENT4).lines[2] == T + line.lstrip()

    def test_line_without_a_rule_context_keeps_its_spaces(self):
        """make stops at a TAB line outside a rule context (GNU 11292-11297)."""
        lines = ["X = 1", "ifdef Y", "    echo hi", "endif"]
        assert TabsRule().format(list(lines), INDENT4).lines == lines

    def test_rule_context_of_phony_only_gets_no_tab(self):
        """A line with leading spaces whose only rule context is that of
        .PHONY keeps its spaces: make runs that recipe only when .PHONY is
        named as a goal (GNU 1443-1446, 2234-2240), and as written the line
        reads the same in every case."""
        lines = ["X = 1", ".PHONY: t1", "ifdef Y", "    echo hi", "endif"]
        assert TabsRule().format(list(lines), INDENT4).lines == lines

    @pytest.mark.parametrize(
        ("lines", "agrees"),
        [
            (["all:", T + "@echo a"], True),
            ([".RECIPEPREFIX = >", "all:", ">@echo a"], True),
            ([".RECIPEPREFIX += >", "all:", ">@echo a"], False),
            (["define .RECIPEPREFIX :=", "$(P)", "endef", "all:"], False),
        ],
    )
    def test_reads_prefix_as_make(self, lines, agrees):
        """Where make's recipe prefix is not the one that the rules read line
        by line, the old choices are kept (GNU 5158-5169)."""
        states = TabsRule.read_lines(lines, {}, True)
        assert TabsRule.reads_prefix_as_make(lines, states) is agrees


class TestRecipeLinesThatLookLikeSyntax:
    """A TAB-led line in a rule context that looks like makefile syntax is
    left as written and reported (GNU 2897-2905, 5511-5513, 851-854)."""

    @pytest.mark.parametrize(
        ("line", "what"),
        [
            ("CFLAGS+=-g", "assignment to 'CFLAGS'"),
            ("X?=1", "assignment to 'X'"),
            ("X!=cmd", "assignment to 'X'"),
            ("X = 1", "assignment to 'X'"),
            ("override X=1", "assignment to 'X'"),
            ("ifdef Y", "'ifdef'"),
            ("-include x.mk", "'-include'"),
        ],
    )
    def test_warning(self, line, what):
        text = f"all:\n\t@echo a\nifeq (a,a)\n\t{line}\nendif\n"
        result = _format(text, INDENT4)
        assert result.content.splitlines()[3] == T + line
        assert any(
            w.startswith(f"4: Warning: Tab-indented {what} in a rule context")
            for w in result.warnings
        ), result.warnings

    def test_shell_assignment_is_kept_without_warning(self):
        text = "all:\n\t@echo a\nifeq (a,a)\n\tX=1 ./configure\nendif\n"
        result = _format(text, INDENT4)
        assert result.content == text
        assert not any("Tab-indented" in w for w in result.warnings)

    def test_traditional_message_format(self):
        text = "all:\n\t@echo a\nifeq (a,a)\n\tX?=1\nendif\n"
        formatter = MakefileFormatter(
            Config(formatter=FormatterConfig(**INDENT4), gnu_error_format=False)
        )
        warnings = formatter.format(text).warnings
        assert (
            "Warning: Tab-indented assignment to 'X' in a rule context may be read "
            "as a recipe line, not as a variable assignment (left unchanged) (line 4)"
        ) in warnings


class TestRealWorldShapes:
    """Shapes from tests/verilator, where make reads TAB-led lines after a
    rule as recipe lines."""

    GIT_DEP = (
        "dbg: ; @echo dbg\nall: ; @echo all\n\n"
        "ifneq ($(NO_OPT),1)  # comment\n"
        "\tifneq ($(UNDER_GIT),)  # comment\n"
        "\tGIT_CHANGE_DEP = .git/logs/HEAD\n"
        "\tendif\n"
        "endif\n"
    )

    def test_tab_led_lines_after_a_rule_stay_as_written(self):
        result = _format(self.GIT_DEP, INDENT4)
        assert result.content == self.GIT_DEP
        assert len([w for w in result.warnings if "Tab-indented" in w]) == 3

    def test_make_reads_the_same(self, gnu_make, tmp_path):
        """make 3.81 and 4.x read the three lines as recipe lines of 'all',
        so GIT_CHANGE_DEP stays empty (GNU 2897-2905)."""
        _assert_make_reads_the_same(
            gnu_make, tmp_path, self.GIT_DEP, INDENT4, ["dbg", "all"], "UNDER_GIT=1"
        )

    def test_recipe_continuation_line_stays_as_written(self):
        """'\\telse \\\\' continues a recipe line (GNU 2910-2925); it is no
        conditional directive."""
        text = "%.a:\n\t@if true; then \\\n\t\techo a; \\\n"
        text += "\telse \\\n\t\techo b; \\\n\tfi\n"
        lines = _format(text, INDENT4).content.splitlines()
        assert lines[3] == "\telse \\"


class TestReadingPastErrors:
    """A recipe line that lacks its TAB stops make ("missing separator"), and
    TabsRule gives it its TAB. The lines below it are read as make reads them
    then: a TAB-led conditional there is a recipe line of the rule above (GNU
    2897-2905), kept and reported as where the recipe line has its TAB."""

    TEXT = (
        "all: ; @echo all\nX = 1\nifdef DEBUG\ndebug:\n    @echo debug\n"
        "\tifeq ($(V),1)\n\t@echo verbose\n\tendif\nendif\n"
    )
    WITH_TAB = TEXT.replace("    @echo debug", "\t@echo debug")

    @pytest.mark.parametrize("config", sorted(CONFIGS))
    def test_same_as_with_the_tab(self, config):
        result = _format(self.TEXT, CONFIGS[config])
        assert result.content == _format(self.WITH_TAB, CONFIGS[config]).content
        assert "\n\tifeq ($(V),1)\n\t@echo verbose\n\tendif\n" in result.content
        assert any("Tab-indented 'ifeq' in a rule" in w for w in result.warnings)
        assert _format(result.content, CONFIGS[config]).content == result.content

    def test_make_reads_the_same(self, gnu_make, tmp_path):
        _assert_make_reads_the_same(gnu_make, tmp_path, self.TEXT, INDENT4, ["all"])

    def test_make_reads_the_recipe_with_its_tab(self, gnu_make, tmp_path):
        """With DEBUG set, make stops at the line without its TAB, and reads
        the output as the makefile in which the line has it."""
        output = _format(self.TEXT, INDENT4).content
        settings = ("DEBUG=1", "V=1")
        expected = _make_reads(gnu_make, tmp_path, self.WITH_TAB, ["debug"], *settings)
        assert expected[0] == 0
        assert expected[2]["debug"][1] == "ifeq ($(V),1)"
        assert _make_reads(gnu_make, tmp_path, output, ["debug"], *settings) == expected


class TestRecipeLinesOfPhony:
    """A TAB-led line that make reads as a recipe line of .PHONY stays as
    written, like any recipe line (GNU 2878-2884). PhonyRule does not always
    move the .PHONY line: it keeps a declaration at the top of the file, a
    '.PHONY :' line, single declarations when it ungroups, and declarations
    whose rules it cannot see. Where the .PHONY line stays, new indentation
    would end its rule context, so that the TAB-led lines after it stop make
    ("recipe commences before first target", 11292-11297), or turn a command
    into an assignment that make reads (1209-1236)."""

    TEXT = "X = 1\nifeq (a,a)\n.PHONY: t1\n\t$(R)\nendif\nt1: ; @echo t1\n"

    def test_recipe_line_of_phony_keeps_its_tab(self):
        once = _format(self.TEXT, INDENT4).content
        assert "\n\t$(R)\n" in once
        assert _format(once, INDENT4).content == once

    def test_make_reads_the_same(self, gnu_make, tmp_path):
        _assert_make_reads_the_same(gnu_make, tmp_path, self.TEXT, INDENT4, ["t1"])


AUTO_UNGROUP_INDENT4 = {
    "auto_insert_phony_declarations": True,
    "group_phony_declarations": False,
    **INDENT4,
}

# The second review's reproducers: a .PHONY line that PhonyRule leaves where it
# is owns TAB-led lines inside a conditional. {name: (text, config, goals,
# settings for make)}
PHONY_RECIPE_LINES = {
    "declaration_at_the_top": (
        ".PHONY: all clean\nifeq ($(OS),Windows_NT)\n\t$(MAKE) -C win\nendif\n"
        "all: ; @echo all\nclean: ; @echo clean\n",
        REPORTER107,
        ["all", "clean"],
        ["OS=Windows_NT"],
    ),
    "space_before_the_colon": (
        ".PHONY : all\nifeq (a,a)\n\t$(CC) -c x.c\nendif\nall: ; @echo all\n",
        REPORTER107,
        ["all"],
        [],
    ),
    "assignment_text_after_a_spaced_declaration": (
        ".PHONY : t2 t1\nifndef A\n\tCFLAGS += -g\nendif\nt1: ; @echo t1\n"
        "t2: ; @:\n",
        REPORTER107,
        ["t1", "t2"],
        [],
    ),
    "assignment_text_in_a_branch": (
        ".PHONY:all t2\n.PHONY:t1\nifdef A\n\tX = 2\nendif\nall: ; @echo all\n"
        "t1: ; @:\nt2: ; @:\n",
        REPORTER107,
        ["all", "t1", "t2"],
        ["A=1"],
    ),
    "single_declaration_when_ungrouping": (
        ".PHONY: all\nifeq (a,a)\n\t$(R)\n\t@echo hi\nendif\nall: ; @echo all\n",
        AUTO_UNGROUP_INDENT4,
        ["all"],
        [],
    ),
}


class TestPhonyRecipeLinesThatStay:
    """Every line make reads as a recipe line of .PHONY keeps its TAB, and
    make reads the output as it reads the input."""

    @pytest.mark.parametrize("name", sorted(PHONY_RECIPE_LINES))
    def test_tab_led_lines_are_kept(self, name):
        text, config, _, _ = PHONY_RECIPE_LINES[name]
        output = _format(text, config).content
        for line in text.splitlines():
            if line.startswith(T):
                assert line in output.splitlines()
        assert _format(output, config).content == output

    @pytest.mark.parametrize("name", sorted(PHONY_RECIPE_LINES))
    def test_make_reads_the_same(self, gnu_make, tmp_path, name):
        text, config, goals, settings = PHONY_RECIPE_LINES[name]
        _assert_make_reads_the_same(gnu_make, tmp_path, text, config, goals)
        if settings:
            _assert_make_reads_the_same(
                gnu_make, tmp_path, text, config, goals, *settings
            )


class TestRecipeContinuationLines:
    """A continuation line of a recipe line is passed to the shell with its
    leading whitespace (GNU 2918-2925), so it is never indented."""

    TEXT = 'all:\nifdef A\n\t@echo "a ' + BS + '\nendif"\nendif\n'

    def test_continuation_line_is_kept(self):
        once = _format(self.TEXT, INDENT2).content
        assert once.splitlines()[3] == 'endif"'
        assert _format(once, INDENT2).content == once

    def test_make_reads_the_same(self, gnu_make, tmp_path):
        _assert_make_reads_the_same(
            gnu_make, tmp_path, self.TEXT, INDENT2, ["all"], "A=1"
        )


class TestLinesThatTabsRuleTurnsIntoRecipeLines:
    """ConditionalRule runs before TabsRule and reads the lines as TabsRule
    leaves them, so that a second run makes the same choices: after a
    rule without targets, a line with leading spaces that TabsRule gives a
    TAB keeps the 'override define E' after it a recipe line, so the
    'endif' lines below are directives, not a define body."""

    TEXT = (
        "\tifdef A\n  ifndef A\nendif\n\telse\n  ifndef A\n\tdefine D\n  endef\n"
        "$(EMPTY): t1\nifndef Z\n    $(MAKE) -C sub\n\toverride define E\nendif\n"
        "  endif\n  endif\n"
    )

    @pytest.mark.parametrize("config", [INDENT2, INDENT4], ids=["indent2", "indent4"])
    def test_second_run_changes_nothing(self, config):
        once = _format(self.TEXT, config).content
        assert _format(once, config).content == once

    def test_make_reads_the_same(self, gnu_make, tmp_path):
        _assert_make_reads_the_same(
            gnu_make, tmp_path, self.TEXT, INDENT2, ["__probe__"], "Z=1"
        )


class TestReadings:
    """The readings of rule_context.scan_makefile that ConditionalRule uses."""

    def test_skipped_as_recipe(self):
        """Without Y, make skips the 'else' as a recipe line of t2; with Y, it
        reads it as a directive, as 'X = 1' ends the rule context."""
        lines = TestSkippedBranches.TEXT.splitlines()
        state = scan_makefile(lines)[lines.index(T + "else")]
        assert state.skipped_as_recipe
        assert RECIPE not in state.readings

    def test_nothing_skipped_without_a_rule_context(self):
        lines = TestUnchangedBehaviour.TAB_INDENTED.splitlines()
        assert not any(state.skipped_as_recipe for state in scan_makefile(lines))

    def test_past_errors(self):
        lines = TestReadingPastErrors.TEXT.splitlines()
        index = lines.index(T + "ifeq ($(V),1)")
        assert RECIPE not in scan_makefile(lines)[index].readings
        assert RECIPE in scan_makefile(lines, past_errors=True)[index].readings


class TestDuplicateTargets:
    """DuplicateTargetRule counts a line with leading spaces as a recipe line
    exactly where TabsRule makes it one: makefile syntax after a second rule
    for a target gives that rule no recipe, so make overrides nothing (GNU
    2545-2558)."""

    @pytest.mark.parametrize(
        "line", ["    $(R)", "    sinclude x.mk", "    $(call setup)"]
    )
    def test_no_duplicate_target_error(self, line):
        result = _format(f"foo:\n\t@echo a\nfoo:\n{line}\n", INDENT4)
        assert result.content.splitlines()[3] == line
        assert result.errors == []

    def test_make_overrides_nothing(self, gnu_make, tmp_path):
        text = "foo:\n\t@echo a\nfoo:\n    $(R)\n"
        assert _format(text, INDENT4).errors == []
        _assert_make_reads_the_same(gnu_make, tmp_path, text, INDENT4, ["foo"])


class TestDefineBodies:
    """ConditionalRule leaves define bodies as written (GNU 4795-4799)."""

    @pytest.mark.parametrize("config", sorted(CONFIGS))
    def test_nested_conditional_indentation_fixture_bodies(self, config):
        path = os.path.join(
            os.path.dirname(__file__),
            "fixtures",
            "nested_conditional_indentation",
            "input.mk",
        )
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        lines = _format(text, CONFIGS[config]).content.splitlines()
        # 'something' and 'something_else' are the bodies of FOO_template
        assert "something" in lines
        assert "something_else" in lines

    @pytest.mark.parametrize("config", sorted(CONFIGS))
    def test_body_in_a_conditional_reads_the_same(self, gnu_make, tmp_path, config):
        text = (
            "ifeq (a,a)\nifeq (b,b)\ndefine D\n  two\n\tTAB\nx\nendef\nendif\nendif\n"
        )
        text += "all: ; @echo all\n"
        _assert_make_reads_the_same(gnu_make, tmp_path, text, CONFIGS[config], ["all"])


class TestKeptWhitespaceAfterBackslash:
    """With remove_trailing_whitespace off, a backslash followed by whitespace
    keeps the whitespace, so it does not continue the line (GNU 762-769)."""

    TEXT = "all: ; @echo [$(Y)]\nifdef X\nY = a " + BS + " \nendif\n"
    CONFIG = {"remove_trailing_whitespace": False, **INDENT2}

    def test_whitespace_is_kept(self):
        lines = _format(self.TEXT, self.CONFIG).content.splitlines()
        assert lines[2] == "  Y = a " + BS + " "

    def test_make_reads_the_same(self, gnu_make, tmp_path):
        _assert_make_reads_the_same(
            gnu_make, tmp_path, self.TEXT, self.CONFIG, ["all"], "X=1"
        )

    DIRECTIVE = (
        "ifdef A\nifdef B # note "
        + BS
        + " \nX = 1\nendif\nendif\nall: ; @echo [$(X)]\n"
    )

    def test_directive_line_keeps_its_whitespace(self):
        lines = _format(self.DIRECTIVE, self.CONFIG).content.splitlines()
        assert lines[1] == "  ifdef B # note " + BS + " "

    def test_directive_line_make_reads_the_same(self, gnu_make, tmp_path):
        _assert_make_reads_the_same(
            gnu_make, tmp_path, self.DIRECTIVE, self.CONFIG, ["all"], "A=1", "B=1"
        )


class TestSkippedBranches:
    """In a branch that make skips, it skips a TAB-led line without looking at
    it while a rule context is open, so a TAB-led 'else' there is no
    directive (GNU 2902-2905, 5315-5333): without Y, make never reads the
    'else' below, and t2 does not run '@echo other'."""

    # The .PHONY line keeps PhonyRule's order of the targets the same.
    TEXT = (
        ".PHONY: t2 t1\nt2: t1\n\t@echo t2\nifdef Y\nX = 1\n\telse\n"
        "\t@echo other\nendif\nt1: ; @echo t1\n"
    )

    @pytest.mark.parametrize("config", sorted(CONFIGS))
    def test_tab_led_else_stays_as_written(self, config):
        once = _format(self.TEXT, CONFIGS[config]).content
        assert "\n\telse\n" in once
        assert _format(once, CONFIGS[config]).content == once

    def test_make_reads_the_same(self, gnu_make, tmp_path):
        _assert_make_reads_the_same(gnu_make, tmp_path, self.TEXT, INDENT4, ["t2"])


class TestUnchangedBehaviour:
    """What make already read the same way works as before."""

    # TAB-indented conditionals that no rule context reaches: make reads each
    # as a directive (GNU 1217-1219), and none is reported.
    TAB_INDENTED = (
        "CC = gcc\nifdef A\n\tifdef B\n\t\tX = 1\n\tendif\nelse\n"
        "\tifdef C\n\t\tY = 1\n\tendif\nendif\n"
    )

    def test_tab_indented_conditionals_move(self):
        result = _format(self.TAB_INDENTED, INDENT2)
        assert result.content == (
            "CC = gcc\nifdef A\n  ifdef B\n    X = 1\n  endif\nelse\n"
            "  ifdef C\n    Y = 1\n  endif\nendif\n"
        )
        assert not any("Tab-indented" in w for w in result.warnings)

    @pytest.mark.parametrize(
        "settings", [(), ("A=1",), ("A=1", "B=1"), ("C=1",)], ids=str
    )
    def test_tab_indented_conditionals_read_the_same(
        self, gnu_make, tmp_path, settings
    ):
        text = self.TAB_INDENTED + "all: ; @echo [$(X)][$(Y)]\n"
        _assert_make_reads_the_same(
            gnu_make, tmp_path, text, INDENT2, ["all"], *settings
        )

    @pytest.mark.parametrize("config", sorted(CONFIGS))
    def test_second_run_changes_nothing_after_tab_led_else(self, config):
        """No rule context reaches either 'else', so make reads both as
        directives (GNU 1217-1219) and both move in the first run."""
        text = "X = 1\nifndef Z\n\telse\nifdef Y\nX = 2\n\telse\nY = 3\nendif\nendif\n"
        once = _format(text, CONFIGS[config]).content
        assert T not in once
        assert _format(once, CONFIGS[config]).content == once

    def test_tab_led_function_call_after_tab_led_else_is_reindented(self):
        text = "X = 1\nifdef Y\nX = 2\n\telse\n\t$(info hi)\nendif\n"
        once = _format(text, INDENT2).content
        assert once == "X = 1\nifdef Y\n  X = 2\nelse\n  $(info hi)\nendif\n"
        assert _format(once, INDENT2).content == once

    def test_tab_led_else_with_y_reads_the_same(self, gnu_make, tmp_path):
        """With Y, make reads the 'else' as a directive (TestSkippedBranches)."""
        _assert_make_reads_the_same(
            gnu_make, tmp_path, TestSkippedBranches.TEXT, INDENT4, ["t2"], "Y=1"
        )

    def test_tab_led_line_that_make_rejects_stays_as_written(self):
        """make stops at a TAB-led line outside a rule context (GNU
        11292-11297) and at the same text without the TAB ("missing
        separator"); the line is left as it is."""
        text = "X = 1\nifeq ($(DEBUG),yes)\nd=v: deps\n\tdebug_recipe\nendif\n"
        assert _format(text, INDENT4).content.splitlines()[3] == "\tdebug_recipe"

    def test_tab_led_function_call_outside_a_rule_context_is_reindented(self):
        """tests/verilator/Makefile-2.in line 44: without the TAB, make reads
        the line as makefile syntax, as before (GNU 1217-1219)."""
        text = "U = 1\nifeq (,$(wildcard x.o))\n\t$(shell true >x.o)\nendif\n"
        lines = _format(text, INDENT4).content.splitlines()
        assert lines[2] == "    $(shell true >x.o)"

    @pytest.mark.parametrize(
        "text",
        [
            "%.x: ; @echo i\nifeq (a,a)\n  X = 2\n$(info i)\n.PHONY: t3\n"
            "\tX ?= 1\n-include nofile.mk\nendif\nt3: t2\n",
            "t2:\n\tifdef Y\n.PHONY: t3\n  ifeq (b,b)\n    $(R)\n"
            "  sinclude nofile.mk\nendif\n",
        ],
        ids=["tab-led-assignment", "makefile-syntax"],
    )
    def test_second_run_changes_nothing_when_phony_lines_move(self, text):
        """A .PHONY line that owns a command line stays where it is, so the
        TAB-led lines below it keep their rule context on every run; the
        other .PHONY lines may move."""
        once = _format(text, REPORTER107).content
        assert _format(once, REPORTER107).content == once

    @pytest.mark.parametrize("config", sorted(CONFIGS))
    @pytest.mark.parametrize("name", sorted(set(ALL_LINES) - {"override_define"}))
    def test_second_run_changes_nothing(self, name, config):
        # The .PHONY line keeps PhonyRule's order of the targets the same.
        text = _in_rule_context(ALL_LINES[name][0], extra=".PHONY: all t1 t2\n")
        once = _format(text, CONFIGS[config]).content
        assert _format(once, CONFIGS[config]).content == once

    @pytest.mark.parametrize("config", ["indent2", "indent4"])
    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            ("    @echo spaced", T + "@echo spaced"),
            ("    $(MAKE) -C sub", T + "$(MAKE) -C sub"),
            ("echo hi", T + "echo hi"),
        ],
    )
    def test_recipe_line_without_its_tab_gets_one(self, config, line, expected):
        text = f"all:\n\t@echo a\nifdef X\n{line}\nendif\n"
        assert _format(text, CONFIGS[config]).content.splitlines()[3] == expected

    @pytest.mark.parametrize("config", sorted(CONFIGS))
    @pytest.mark.parametrize(
        "line", ["export X", "export X = 1", "X ?= 1", "override X = 1", "$(info i)"]
    )
    def test_makefile_syntax_is_indented_with_spaces(self, config, line):
        text = _in_rule_context(line)
        width = CONFIGS[config]["tab_width"]
        lines = _format(text, CONFIGS[config]).content.splitlines()
        assert " " * width + line in lines

    @pytest.mark.parametrize("config", sorted(CONFIGS))
    @pytest.mark.parametrize(
        "line", ["export X", "export X = 1", "X ?= 1", "override X = 1", "$(info i)"]
    )
    def test_make_reads_the_same(self, gnu_make, tmp_path, config, line):
        _assert_make_reads_the_same(
            gnu_make, tmp_path, _in_rule_context(line), CONFIGS[config], ["t1", "t2"]
        )

    def test_tab_led_directive_outside_a_rule_context_moves(self):
        """make reads it as a conditional (GNU 1217-1219), as before."""
        text = "X = a\n\tifdef Y\nZ = 1\n\tendif\nall: ; @echo all\n"
        assert _format(text, INDENT2).content == (
            "X = a\nifdef Y\n  Z = 1\nendif\nall: ; @echo all\n"
        )

    def test_tab_led_assignment_outside_a_rule_context_is_reindented(self):
        """make reads it as an assignment (GNU 1217-1219), so it is indented
        with spaces as before, and not reported."""
        text = "ifneq ($(words $(CURDIR)),1)\n\t$(error spaces)\nendif\n"
        text += "ifeq ($(ROOT),)\n\tVERILATOR = verilator\nendif\n"
        result = _format(text, INDENT4)
        assert result.content.splitlines()[4] == "    VERILATOR = verilator"
        assert not any("Tab-indented" in w for w in result.warnings)

    @pytest.mark.parametrize("line", ["export X=1", "echo hi"])
    def test_shell_commands_are_not_reported(self, line):
        text = f"all:\n\t@echo a\nifeq (a,a)\n\t{line}\nendif\n"
        result = _format(text, INDENT4)
        assert result.content == text
        assert not any("Tab-indented" in w for w in result.warnings)

    def test_recipe_line_without_its_tab_is_still_a_duplicate(self):
        result = _format("foo:\n\t@echo a\nfoo:\n    echo b\n", INDENT4)
        assert result.content.splitlines()[3] == T + "echo b"
        assert any("Duplicate target 'foo'" in error for error in result.errors)

    def test_default_configuration_converts_as_before(self):
        lines = ["foo:", T + "@echo a", "  $(call setup)", "  sinclude x.mk"]
        assert TabsRule().format(list(lines), {}).lines == [
            "foo:",
            T + "@echo a",
            T + "$(call setup)",
            T + "sinclude x.mk",
        ]

    def test_template_body_in_a_conditional_reads_the_same(self, gnu_make, tmp_path):
        text = "ifeq (a,a)\ndefine T\n$(1):\n\t@echo $(1)\nifeq ($(1),x)\nX = 1\n"
        text += "endif\nendef\nendif\n$(eval $(call T,x))\nall: x ; @echo [$(X)]\n"
        _assert_make_reads_the_same(gnu_make, tmp_path, text, INDENT4, ["all"])
