"""Tests for line continuations that keep what GNU make and the shell read.

Line numbers refer to the GNU make 4.4.1 manual.

- make continues a line only where an odd number of backslashes ends it, so a
  backslash followed by whitespace does not continue it (3.1, lines 730-733;
  3.1.1, lines 762-769). The formatter removes that whitespace, which makes
  the line continue, only where make rejects the next line on its own; it
  keeps every other such line as written, with a warning.
- make passes each backslash/newline of a recipe line to the shell with the
  whitespace around it, and removes only the recipe prefix after it (5.1.1,
  lines 2917-2925). A recipe block whose blanks matter stays as written: a
  backslash that joins two words, a backslash/newline in quotes or after
  '<<', and every recipe of a makefile with .ONESHELL (5.3.1, lines
  3094-3097) or with a SHELL that is no POSIX shell (5.3.2, lines
  3170-3174). Other recipes are re-indented as before, also where a
  continuation line lacks the recipe prefix and its spaces only separate
  words, as long as the shell gets the same words. A continuation line at
  column 1 gets no TAB where the TAB is no recipe prefix ('.RECIPEPREFIX',
  lines 5158-5169) or where it starts inside quotes or a here-document.
- make reads a line that does not start with the recipe prefix, with the
  lines it continues over, as makefile syntax (3.8, lines 1209-1219), so a
  line with leading spaces that starts a continued rule keeps them.
- Outside recipes, make turns a backslash/newline and the whitespace around
  it into one space (3.1.1, lines 776-781), so those continuations are
  normalized as before, except with .POSIX (lines 783-786), before a run of
  three or more backslashes, and in define bodies (6.8, lines 4795-4814).

The make-backed tests run each GNU make on PATH ('make' and 'gmake') on the
original and on the formatted makefile and require the same values, the same
'make -n' commands and the same output of the commands, which only echo text.
"""

import os
import re
import shlex
import shutil
import subprocess

import pytest
from typer.testing import CliRunner

from mbake.cli import app
from mbake.config import Config, FormatterConfig
from mbake.core.formatter import MakefileFormatter
from mbake.utils import line_utils, rule_context

T = "\t"
BS = "\\"  # one backslash, to keep continuation lines readable
WARNING = "Backslash followed by trailing whitespace does not continue the line"

DEFAULT: dict = {}
KEEP = {"remove_trailing_whitespace": False}
NO_NORMALIZE = {"normalize_line_continuations": False}
INDENT2 = {"indent_nested_conditionals": True, "tab_width": 2}
INDENT4 = {"indent_nested_conditionals": True, "tab_width": 4}
CONFIGS = {"default": DEFAULT, "keep": KEEP, "no-normalize": NO_NORMALIZE}
INDENT_CONFIGS = {"indent2": INDENT2, "indent4": INDENT4}
ALL_CONFIGS = {**CONFIGS, **INDENT_CONFIGS}

# Lines whose backslash whitespace follows, before a line that stands alone,
# with the goal whose recipe prints the values (the 1.5.0 hazard inputs). The
# whitespace keeps the backslash from continuing the line; formatting used to
# remove it, so that the line went on over the next one.
DANGLING = {
    "dangling_backslash": (
        "X = a " + BS + " \nY = b\nall:\n\t@echo [$(X)] [$(Y)]\n",
        "all",
    ),
    "dangling_backslash_continued": (
        "X = a " + BS + "\n  b " + BS + " \nY = c\nall:\n"
        "\t@printf '%s\\n' \"[$(X)] [$(Y)]\"\n",
        "all",
    ),
    "vpath_dangling": (
        "VPATH = src " + BS + " \nY = 1\nall:\n\t@echo [$(VPATH)] [$(Y)]\n",
        "all",
    ),
    "align_dangling": (
        "A = x" + BS + " \nBB = y\nall:\n\t@echo [$(A)] [$(BB)]\n",
        "all",
    ),
    "comment_dangling_backslash": (
        "# a comment " + BS + " \nX = 1\nshow:\n\t@echo [$(X)]\n",
        "show",
    ),
    "region_marker_dangling_backslash": (
        "# bake-format off " + BS + " \nX = 1\n# bake-format on\nshow:\n"
        "\t@echo [$(X)]\n",
        "show",
    ),
}

# The line of each makefile of DANGLING that is kept and reported
DANGLING_LINE = {
    "dangling_backslash": 1,
    "dangling_backslash_continued": 2,
    "vpath_dangling": 1,
    "align_dangling": 1,
    "comment_dangling_backslash": 1,
    "region_marker_dangling_backslash": 1,
}

# Lines whose backslash whitespace follows in places that other rules format,
# each before a line that stands alone, with the goal to check and the
# configuration
DANGLING_ELSEWHERE = {
    # PatternSpacingRule: the comment does not go on over the recipe line
    "static_pattern_rule": (
        "all: a.x\na.x b.x: %.x: %.y # objects " + BS + " \n\t@echo [$@] [$^]\n"
        "%.y: ; @:\n",
        "all",
        DEFAULT,
    ),
    # TargetSpacingRule: the comment does not go on over 'Y = 1'
    "vpath_comment": (
        "VPATH = src # dirs " + BS + " \nY = 1\nall: ; @echo [$(Y)]\n",
        "all",
        DEFAULT,
    ),
    # AssignmentAlignmentRule: 'CCC = 3' is no part of the value of BB
    "alignment_block": (
        "A = 1\nBB = x " + BS + " \nCCC = 3\nall: ; @echo [$(A)] [$(BB)] [$(CCC)]\n",
        "all",
        {"align_variable_assignments": True},
    ),
    # ConditionalRule: the comment of 'ifdef B' does not go on over 'X = 1'
    "conditional_directive": (
        "ifdef A\nifdef B # note " + BS + " \nX = 1\nendif\nendif\n"
        "all: ; @echo [$(X)]\n",
        "all",
        INDENT2,
    ),
    # WhitespaceRule: the second command stays a command of its own
    "recipe_line": ("all:\n\t@echo a " + BS + " \n\t@echo b\n", "all", DEFAULT),
    # WhitespaceRule: the TAB-only line stays the empty recipe of foo.x, so no
    # implicit rule makes foo.x (GNU 2890-2891, 4040-4055)
    "comment_before_empty_recipe": (
        "%.x: ; @echo implicit $@\nfoo.x:\n# c " + BS + " \n\t\n",
        "foo.x",
        DEFAULT,
    ),
    # ShellFormattingRule: the shell block ends at the line, which make does
    # not continue (GNU 2910-2915)
    "shell_block": (
        "all:\n\tif [ -f x ]; then " + BS + " \n\t  echo hi; " + BS + "\n\tfi\n",
        "all",
        DEFAULT,
    ),
}

# A backslash and a space before text that is no makefile syntax: make stops at
# the second line ("missing separator", GNU 11275-11281), so the whitespace goes
# and the line continues, as the formatter always did.
REPAIR = "X = a " + BS + " \n   -lfoo\n"

# Recipe blocks whose blanks matter to the shell (the 1.5.0 hazard inputs)
WORD_JOIN = "all:\n\t@echo a " + BS + "\n\tb" + BS + "\n\tc\n"
QUOTED = "all:\n\t@echo a " + BS + '\n\t  "b ' + BS + '\n\t    c"\n'
QUOTED_INDENTED = "all:\n\t@echo a " + BS + '\n\t"b ' + BS + '\n\t    c"\n'
HEREDOC = "all:\n\t@cat <<EOF " + BS + "\n\t  indented " + BS + "\n\tEOF\n"
# The example of the manual (GNU 2927-2944)
MANUAL_NOSPACE = (
    "all :\n\t@echo no\\\nspace\n\t@echo no\\\n\tspace\n\t@echo one \\\n\tspace\n"
    "\t@echo one\\\n\t space\n"
)
SENSITIVE = {"word_join": WORD_JOIN, "quoted": QUOTED, "heredoc": HEREDOC}

# The recipe after the ';' of a rule line, the example of the manual (GNU
# 2946-2963): the single quotes keep the backslash/newline, the double quotes
# keep the spaces after it
INLINE_RECIPE = (
    "all : ; @echo 'hello \\\n        world' ; echo \"hello \\\n    world\"\n"
)

# The ';' of a rule line on its second line: the rest of that line and the
# lines after it are recipe text (GNU 1499-1503, 2917-2925)
SEMICOLON_LATER = 'all: a \\\n   b ; echo "x \\\n      y \\\n  z"\na b: ; @:\n'
SEMICOLON_LATER_FORMATTED = 'all: a \\\n\tb ; echo "x \\\n      y \\\n  z"\na b: ; @:\n'

# A recipe of the default shell that is re-indented as before
IF_ELSE = (
    "all:\n\tif [ -f x ]; then \\\n\t  echo yes; \\\n\telse \\\n\t  echo no; \\\n\tfi\n"
)
IF_ELSE_FORMATTED = (
    "all:\n\tif [ -f x ]; then \\\n\t\techo yes; \\\n\telse \\\n\t\techo no; \\\n"
    "\tfi\n"
)
FOR_LOOP = "all:\n\t@for x in a b; do \\\n\t  echo $$x; \\\n\tdone\n"
FOR_LOOP_FORMATTED = "all:\n\t@for x in a b; do \\\n\t\techo $$x; \\\n\tdone\n"


def _formatter(**config):
    return MakefileFormatter(Config(formatter=FormatterConfig(**config)))


def _format(text, config, **settings):
    return MakefileFormatter(
        Config(formatter=FormatterConfig(**config), **settings)
    ).format(text)


def _runner() -> CliRunner:
    """Return a CliRunner that keeps stdout and stderr apart."""
    try:
        return CliRunner(mix_stderr=False)  # click < 8.2
    except TypeError:
        return CliRunner()  # click >= 8.2 always captures stderr separately


def _assert_stable(text, config):
    """Formatting the formatted text again changes nothing."""
    once = _formatter(**config).format(text).content
    assert _formatter(**config).format(once).content == once


# make runs with a minimal environment so that no inherited variable (such as
# MAKEFLAGS) changes what it reads.
_MAKE_ENV = {"PATH": os.defpath, "LC_ALL": "C"}

# A second makefile that make reads after the one under test: it prints the
# variables that the makefiles of these tests set, as make stores them. Nothing
# is appended to the makefile under test itself.
PROBE = (
    "$(info [X=$(value X)][Y=$(value Y)][A=$(value A)][BB=$(value BB)]"
    "[CCC=$(value CCC)][VPATH=$(value VPATH)][BODY=$(value BODY)])\n"
    "__probe__: ;\n"
)


def _make_release(make):
    """Return (major, minor) of a GNU make, or None if it is not one."""
    try:
        version = subprocess.run(
            [make, "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            env=_MAKE_ENV,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"GNU Make (\d+)\.(\d+)", version)
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2))


def _make_version(make):
    """Return the major version of a GNU make, or None if it is not one."""
    try:
        version = subprocess.run(
            [make, "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            env=_MAKE_ENV,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    if "GNU Make" not in version:
        return None
    return int(version.split("GNU Make ", 1)[1].split(".", 1)[0])


@pytest.fixture(scope="module", params=["make", "gmake"])
def gnu_make(request):
    """Return (make, true, sh, major version), or skip when that GNU make,
    true or sh cannot run here. 'gmake' is often a second GNU make, such as
    4.x next to macOS's 3.81."""
    if os.name == "nt":
        pytest.skip("GNU make checks do not run on Windows")
    make = shutil.which(request.param)
    true = shutil.which("true")
    sh = shutil.which("sh")
    if make is None or true is None or sh is None:
        pytest.skip(f"{request.param}, true or sh is not installed")
    plain_make = shutil.which("make")
    if (
        request.param != "make"
        and plain_make is not None
        and os.path.realpath(plain_make) == os.path.realpath(make)
    ):
        pytest.skip("gmake is the same program as make")
    major = _make_version(make)
    if major is None:
        pytest.skip(f"{request.param} is not GNU make")
    return make, true, sh, major


@pytest.fixture
def gnu_make_4(gnu_make):
    """gnu_make for a GNU make 4.x: make 3.81 has no .RECIPEPREFIX (GNU
    5158-5169)."""
    if gnu_make[3] < 4:
        pytest.skip("make 3.81 has no .RECIPEPREFIX")
    return gnu_make


def _make(gnu_make, cwd, text, args, shell=None):
    """Run make on text, written to a file, and return (returncode, stdout).

    The commands run with shell (default: true, which runs nothing) given on
    the command line, which overrides the makefile's SHELL.
    """
    make, true, _sh, _major = gnu_make
    (cwd / "input.mk").write_bytes(text.encode("utf-8"))
    (cwd / "probe.mk").write_bytes(PROBE.encode("utf-8"))
    proc = subprocess.run(
        [make, "-r", "-R", "-f", "input.mk", *args, f"SHELL={shell or true}"],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=60,
        env=_MAKE_ENV,
    )
    return proc.returncode, proc.stdout


def _readings(gnu_make, cwd, text, goal, settings=(), shell=None):
    """Return what make reads in text: the values of the variables of PROBE,
    the commands that 'make -n' prints for goal, and what the commands print
    when sh (or shell) runs them. Each comes with make's exit status."""
    values = _make(
        gnu_make, cwd, text, ["-s", "-f", "probe.mk", *settings, "__probe__"]
    )
    dry_run = _make(gnu_make, cwd, text, ["-n", *settings, goal])
    run = _make(gnu_make, cwd, text, ["-s", *settings, goal], shell or gnu_make[2])
    return values, dry_run, run


def _assert_make_reads_the_same(gnu_make, cwd, before, after, goal, settings=()):
    """make reads the same values and commands, byte for byte."""
    expected = _readings(gnu_make, cwd, before, goal, settings)
    assert expected[0][0] == 0, "make rejected the input"
    assert _readings(gnu_make, cwd, after, goal, settings) == expected


def _words(dry_run, major):
    """Return the words and the ';', '&' and '|' operators that a POSIX shell
    reads in the commands of 'make -n', without the backslash/newlines, and
    without the recipe prefix TAB that make 3.81 still prints after them (GNU
    2917-2925)."""
    text = re.sub(r"\\\n\t?" if major < 4 else r"\\\n", "", dry_run)
    lexer = shlex.shlex(text, posix=True, punctuation_chars=";&|")
    lexer.whitespace_split = True
    try:
        return list(lexer)
    except ValueError:
        return [text]


def _assert_shell_gets_the_same_words(gnu_make, cwd, before, after, goal, shell=None):
    """make reads the same values, and the commands differ in blanks between
    words only: the shell gets the same words and prints the same."""
    expected = _readings(gnu_make, cwd, before, goal, shell=shell)
    actual = _readings(gnu_make, cwd, after, goal, shell=shell)
    assert expected[0][0] == 0, "make rejected the input"
    assert actual[0] == expected[0]
    assert actual[2] == expected[2]
    assert actual[1][0] == expected[1][0]
    assert _words(actual[1][1], gnu_make[3]) == _words(expected[1][1], gnu_make[3])


class TestDanglingBackslashKept:
    """A backslash followed by whitespace does not continue the line (GNU
    762-769). Before a line that stands alone the line stays as written."""

    @pytest.mark.parametrize("config", sorted(ALL_CONFIGS))
    @pytest.mark.parametrize("name", sorted(DANGLING))
    def test_line_stays_as_written(self, name, config):
        text, _goal = DANGLING[name]
        assert _format(text, ALL_CONFIGS[config]).content == text

    @pytest.mark.parametrize("config", sorted(ALL_CONFIGS))
    @pytest.mark.parametrize("name", sorted(DANGLING))
    def test_make_reads_the_same(self, gnu_make, tmp_path, name, config):
        text, goal = DANGLING[name]
        formatted = _format(text, ALL_CONFIGS[config]).content
        _assert_make_reads_the_same(gnu_make, tmp_path, text, formatted, goal)

    @pytest.mark.parametrize("config", sorted(ALL_CONFIGS))
    @pytest.mark.parametrize("name", sorted(DANGLING))
    def test_second_run_changes_nothing(self, name, config):
        _assert_stable(DANGLING[name][0], ALL_CONFIGS[config])

    @pytest.mark.parametrize("name", sorted(DANGLING_ELSEWHERE))
    def test_other_rules_keep_the_whitespace(self, name):
        text, _goal, config = DANGLING_ELSEWHERE[name]
        formatted = _format(text, config).content

        def dangling(lines):
            return [line.lstrip() for line in lines if line.endswith(BS + " ")]

        assert dangling(text.splitlines())
        assert dangling(formatted.splitlines()) == dangling(text.splitlines())
        _assert_stable(text, config)

    @pytest.mark.parametrize("name", sorted(DANGLING_ELSEWHERE))
    def test_other_rules_make_reads_the_same(self, gnu_make, tmp_path, name):
        text, goal, config = DANGLING_ELSEWHERE[name]
        formatted = _format(text, config).content
        settings = ("A=1", "B=1") if name == "conditional_directive" else ()
        _assert_make_reads_the_same(gnu_make, tmp_path, text, formatted, goal, settings)


class TestDanglingBackslashRepaired:
    """make stops at '   -lfoo' ("missing separator", GNU 11275-11281): the
    whitespace after the backslash goes, as it always did, and the value of X
    goes on over the line (GNU 776-781)."""

    @pytest.mark.parametrize("config", ["default", "no-normalize"])
    def test_line_is_repaired(self, config):
        result = _format(REPAIR, CONFIGS[config])
        assert result.content == "X = a " + BS + "\n   -lfoo\n"
        assert result.warnings == []
        _assert_stable(REPAIR, CONFIGS[config])

    def test_kept_with_trailing_whitespace_kept(self):
        """remove_trailing_whitespace = false never removes it."""
        result = _format(REPAIR, KEEP)
        assert result.content == REPAIR
        assert result.warnings == [f"1: Warning: {WARNING}"]

    def test_make_accepts_the_repaired_lines(self, gnu_make, tmp_path):
        args = ["-s", "-f", "probe.mk", "__probe__"]
        assert _make(gnu_make, tmp_path, REPAIR, args)[0] != 0
        formatted = _format(REPAIR, DEFAULT).content
        returncode, output = _make(gnu_make, tmp_path, formatted, args)
        assert returncode == 0
        assert "[X=a -lfoo]" in output

    @pytest.mark.parametrize(
        "following",
        [
            "",
            "# comment",
            "# bake-format on",
            "include x.mk",
            "ifdef A",
            "else",
            "endif",
            "define D",
            "Y = 1",
            "foo: Y = 1",
            "foo: bar",
            "$(info x)",
            "$(R)",
        ],
    )
    def test_line_before_a_line_that_stands_alone_is_kept(self, following):
        lines = ["X = a " + BS + " ", following]
        assert rule_context.dangling_backslash_repairs(lines, {}) == set()

    @pytest.mark.parametrize(
        ("lines", "repaired"),
        [
            (["X = a " + BS + " ", "   -lfoo"], {0}),
            (["X = a " + BS + " ", "    b)"], {0}),
            (["# c " + BS + " ", "-lfoo"], {0}),
            (["X = a " + BS + " ", T + "-lfoo"], {0}),
            # The second repair joins '   -lbar' to the first logical line.
            (["X = a " + BS + " ", "   -lfoo " + BS + T, "   -lbar"], {0, 1}),
            # The last line, and lines in a rule context, stay.
            (["X = a " + BS + " "], set()),
            (["all:", T + "gcc a.c " + BS + " ", "-lfoo"], set()),
            (["all:", "# c " + BS + " ", "    -lfoo"], set()),
            # A conditional directive, whose next line make may skip
            (["ifdef A " + BS + " ", "   -lfoo", "endif"], set()),
            # A define body is the value of a variable (GNU 4795-4799).
            (["define D", "a " + BS + " ", "   -lfoo", "endef"], set()),
        ],
    )
    def test_repairs(self, lines, repaired):
        assert rule_context.dangling_backslash_repairs(lines, {}) == repaired

    def test_line_before_hidden_lines_is_kept(self):
        """The lines that '# bake-format off' hides follow the line."""
        lines = ["# bake-format off " + BS + " ", "# bake-format on"]
        assert rule_context.dangling_backslash_repairs(lines, {0: ["-lfoo"]}) == set()
        assert rule_context.dangling_backslash_repairs(lines) == set()


class TestDanglingBackslashWarning:
    """Each line that keeps a backslash followed by whitespace is reported."""

    @pytest.mark.parametrize("name", sorted(DANGLING))
    def test_format_and_check_mode(self, name):
        text, _goal = DANGLING[name]
        expected = [f"{DANGLING_LINE[name]}: Warning: {WARNING}"]
        assert _format(text, DEFAULT).warnings == expected
        lines = text.splitlines()
        assert _formatter().format_lines(lines, False, text)[2] == expected
        check_warnings = _formatter().format_lines(lines, True, text)[2]
        assert check_warnings.count(expected[0]) == 1
        assert sum(WARNING in warning for warning in check_warnings) == 1

    def test_define_body_line(self):
        """A line of a define body is kept, as part of the value (GNU
        4795-4799), and reported like every kept line."""
        text = "define D\na \\ \nb\nendef\n"
        result = _format(text, DEFAULT)
        assert result.content == text
        assert result.warnings == [f"2: Warning: {WARNING}"]

    def test_traditional_shape(self):
        text, _goal = DANGLING["dangling_backslash_continued"]
        result = _format(text, DEFAULT, gnu_error_format=False)
        assert result.warnings == [f"Warning: {WARNING} (line 2)"]

    def test_line_number_after_a_region(self):
        """The formatter turns the rule's line number into the line of the
        file."""
        text = "# bake-format off\nA=1\nB=2\n# bake-format on\nX = a \\ \nY = b\n"
        assert _format(text, DEFAULT).warnings == [f"5: Warning: {WARNING}"]
        result = _format(text, DEFAULT, gnu_error_format=False)
        assert result.warnings == [f"Warning: {WARNING} (line 5)"]
        lines = text.splitlines()
        warnings = _formatter().format_lines(lines, True, text)[2]
        assert f"5: Warning: {WARNING}" in warnings

    def test_check_prints_the_line(self, tmp_path, monkeypatch):
        text, _goal = DANGLING["dangling_backslash_continued"]
        (tmp_path / "Makefile").write_bytes(text.encode("utf-8"))
        (tmp_path / "bake.toml").write_bytes(b"")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COLUMNS", "200")  # keep Rich from wrapping the line
        result = _runner().invoke(
            app, ["format", "--config", "bake.toml", "--check", "Makefile"]
        )
        assert f"Makefile:2: Warning: {WARNING}" in result.stdout
        # The kept line is no change: v1.5.0 removed the whitespace and so
        # reported 'Would reformat' with exit code 1.
        assert result.exit_code == 0

    @pytest.mark.parametrize(
        ("text", "config"),
        [
            # Continuations off: ContinuationRule does nothing.
            pytest.param(
                DANGLING["dangling_backslash"][0], NO_NORMALIZE, id="no-normalize"
            ),
            # Repaired: the line continues.
            pytest.param(REPAIR, DEFAULT, id="repaired"),
            # Two backslashes and a space: the backslashes are text.
            pytest.param("X = a \\\\ \nY = b\n", DEFAULT, id="even-backslashes"),
        ],
    )
    def test_no_warning(self, text, config):
        assert _format(text, config).warnings == []


class TestRecipeBlocksThatStay:
    """make passes the backslash/newlines of a recipe line to the shell with
    the whitespace around them (GNU 2917-2925)."""

    @pytest.mark.parametrize("config", sorted(ALL_CONFIGS))
    @pytest.mark.parametrize("name", sorted(SENSITIVE))
    def test_block_stays_as_written(self, name, config):
        text = SENSITIVE[name]
        expected = text
        if name == "quoted" and config in INDENT_CONFIGS:
            # indent_nested_conditionals gives the line that opens the quote
            # the one TAB of a recipe line; its blanks stand outside the
            # quotes, after the blank before the backslash.
            expected = QUOTED_INDENTED
        assert _format(text, ALL_CONFIGS[config]).content == expected
        _assert_stable(text, ALL_CONFIGS[config])

    @pytest.mark.parametrize("config", sorted(INDENT_CONFIGS))
    def test_quoted_block_runs_the_same_when_indented(self, gnu_make, tmp_path, config):
        formatted = _format(QUOTED, ALL_CONFIGS[config]).content
        assert formatted == QUOTED_INDENTED
        _assert_shell_gets_the_same_words(gnu_make, tmp_path, QUOTED, formatted, "all")

    @pytest.mark.parametrize("name", ["word_join", "quoted"])
    def test_make_runs_the_same(self, gnu_make, tmp_path, name):
        text = SENSITIVE[name]
        formatted = _format(text, DEFAULT).content
        _assert_make_reads_the_same(gnu_make, tmp_path, text, formatted, "all")

    def test_the_shell_reads_the_words_of_the_manual(self, gnu_make, tmp_path):
        """'b\\' and 'c' print 'bc' (GNU 2927-2944)."""
        assert _readings(gnu_make, tmp_path, WORD_JOIN, "all")[2] == (0, "a bc\n")

    @pytest.mark.parametrize("config", sorted(ALL_CONFIGS))
    def test_manual_example_runs_the_same(self, gnu_make, tmp_path, config):
        """The four commands still print 'nospace', 'nospace', 'one space'
        and 'one space' (GNU 2927-2944)."""
        formatted = _format(MANUAL_NOSPACE, ALL_CONFIGS[config])
        run = _readings(gnu_make, tmp_path, formatted.content, "all")[2]
        assert run == (0, "nospace\nnospace\none space\none space\n")
        _assert_stable(MANUAL_NOSPACE, ALL_CONFIGS[config])

    @pytest.mark.parametrize(
        ("text", "printed"),
        [
            # The two blanks after the backslash/newline separate the words.
            ("all:\n\t@echo no\\\n  space\n", "no space\n"),
            ('all:\n\t@echo "one \\\n  space"\n', "one   space\n"),
        ],
    )
    def test_continuation_line_without_its_tab(self, gnu_make, tmp_path, text, printed):
        """make keeps all of its leading spaces, so it gets no TAB in their
        place where the spaces matter."""
        assert _format(text, DEFAULT).content == text
        assert _readings(gnu_make, tmp_path, text, "all")[2] == (0, printed)

    def test_continuation_line_with_spaces_between_words_gets_its_tab(
        self, gnu_make, tmp_path
    ):
        """There the spaces only separate words, so it gets a TAB, as
        before."""
        text = "all:\n\t@echo one \\\n  two\n"
        formatted = _format(text, DEFAULT).content
        assert formatted == "all:\n\t@echo one \\\n\ttwo\n"
        _assert_shell_gets_the_same_words(gnu_make, tmp_path, text, formatted, "all")

    def test_recipe_after_a_semicolon(self, gnu_make, tmp_path):
        """The quotes of the manual's example keep their text (GNU
        2946-2963)."""
        formatted = _format(INLINE_RECIPE, DEFAULT).content
        assert formatted == INLINE_RECIPE.replace("all :", "all:", 1)
        _assert_make_reads_the_same(gnu_make, tmp_path, INLINE_RECIPE, formatted, "all")
        _assert_stable(INLINE_RECIPE, DEFAULT)

    def test_recipe_after_a_semicolon_on_a_later_line(self, gnu_make, tmp_path):
        """The lines before the ';' are prerequisites, the lines after it are
        recipe text (GNU 1499-1503, 2917-2925): the quoted text keeps its
        spaces, and the line with the ';' gets the TAB of v1.5.0 among the
        prerequisites, where make reads it as one space (GNU 776-781)."""
        text = SEMICOLON_LATER
        formatted = _format(text, DEFAULT).content
        assert formatted == SEMICOLON_LATER_FORMATTED
        _assert_make_reads_the_same(gnu_make, tmp_path, text, formatted, "all")
        run = _readings(gnu_make, tmp_path, text, "all")[2]
        assert run == (0, "x       y   z\n")

    def test_recipe_prefix_block(self, gnu_make_4, tmp_path):
        """With '.RECIPEPREFIX = >' the lines that start with '>' are recipe
        lines (GNU 5158-5169): the word-joining backslash and the quoted
        lines stay."""
        text = (
            ".RECIPEPREFIX = >\nall:\n>@echo a \\\n>b\\\n>c\n"
            '>@echo "x \\\n    y \\\n  z"\n'
        )
        formatted = _format(text, DEFAULT).content
        assert formatted == text
        _assert_stable(text, DEFAULT)
        _assert_make_reads_the_same(gnu_make_4, tmp_path, text, formatted, "all")
        assert _readings(gnu_make_4, tmp_path, text, "all")[2] == (
            0,
            "a bc\nx     y   z\n",
        )


class TestShellsThatAreNotKnown:
    """With .ONESHELL make gives all lines of a recipe to one shell, newlines
    included (GNU 3094-3097), and another SHELL reads them its own way (GNU
    2965-2969, 3170-3174): every recipe stays as written."""

    PYTHON_LOOP = (
        ".ONESHELL:\nSHELL = python3\n.SHELLFLAGS = -c\nall:\n"
        "\tfor i in range(2):\n\t    for j in range(2):\n\t        print(i, j)\n"
    )
    PYTHON_CALL = "SHELL = python3\nall:\n\t@print(1, \\\n\t      2, \\\n\t  3)\n"
    ONESHELL_ECHO = ".ONESHELL:\nall:\n\t@echo a \\\n\t  b \\\n\tc\n"

    @pytest.mark.parametrize("text", [PYTHON_LOOP, PYTHON_CALL, ONESHELL_ECHO])
    def test_recipe_stays_as_written(self, gnu_make, tmp_path, text):
        formatted = _format(text, DEFAULT).content
        assert formatted == text
        dry_run = _make(gnu_make, tmp_path, text, ["-n", "all"])
        assert _make(gnu_make, tmp_path, formatted, ["-n", "all"]) == dry_run
        _assert_stable(text, DEFAULT)

    @pytest.mark.parametrize(
        "line",
        [
            "SHELL = python3",
            "SHELL := /usr/bin/perl",
            "export SHELL = $(BASH)",
            "SHELL != which bash",
            "SHELL = $(BASH) -e",
            "SHELL = python3 -u",
            "SHELL = /usr/bin/env bash",
            "SHELL = cmd.exe /c",
            "foo: SHELL = python3",
            "%.py: SHELL := python3",
            ".ONESHELL:",
            "all .ONESHELL ::",
            "$(eval .ONESHELL:)",
        ],
    )
    def test_shell_is_opaque(self, line):
        assert line_utils.ShellUtils.recipes_are_shell_opaque([line, "all: ; @:"])

    @pytest.mark.parametrize(
        "line",
        [
            "SHELL = /bin/sh",
            "SHELL := bash",
            "override SHELL = /usr/local/bin/zsh",
            "SHELL = C:/tools/sh.exe",
            "SHELL = ksh # the Korn shell",
            "SHELL = /bin/bash -e",
            "SHELL = /bin/bash -o pipefail",
            "SHELL=/bin/bash -eo pipefail",
            "SHELL := /bin/sh -u",
            "foo: SHELL := /bin/bash -o pipefail",
            "SHELL += -e",
            ".SHELLFLAGS = -ec",
            "# .ONESHELL:",
            ".ONESHELL := 1",
            "all: .ONESHELL",
        ],
    )
    def test_shell_is_not_opaque(self, line):
        assert not line_utils.ShellUtils.recipes_are_shell_opaque([line, "all: ; @:"])

    BASH_RECIPE = "SHELL = /bin/bash\nall:\n\t@echo a \\\n\t  b \\\n\tc\n"

    def test_bash_recipe_is_re_indented_as_before(self):
        """bash reads blanks as sh does, so the recipe is normalized as
        before."""
        formatted = _format(self.BASH_RECIPE, DEFAULT).content
        assert formatted == self.BASH_RECIPE.replace("\tc\n", "\t  c\n")
        _assert_stable(self.BASH_RECIPE, DEFAULT)

    def test_bash_recipe_runs_the_same(self, gnu_make, tmp_path):
        bash = shutil.which("bash")
        if bash is None:
            pytest.skip("bash is not installed")
        formatted = _format(self.BASH_RECIPE, DEFAULT).content
        _assert_shell_gets_the_same_words(
            gnu_make, tmp_path, self.BASH_RECIPE, formatted, "all", shell=bash
        )
        run = _readings(gnu_make, tmp_path, formatted, "all", shell=bash)[2]
        assert run == (0, "a b c\n")


class TestRecipesNormalizedAsBefore:
    """Where blanks only separate words, recipes are re-indented as before."""

    @pytest.mark.parametrize(
        ("text", "expected"),
        [(IF_ELSE, IF_ELSE_FORMATTED), (FOR_LOOP, FOR_LOOP_FORMATTED)],
        ids=["if-else", "for-loop"],
    )
    def test_shell_control_block(self, gnu_make, tmp_path, text, expected):
        formatted = _format(text, DEFAULT).content
        assert formatted == expected
        _assert_stable(text, DEFAULT)
        _assert_shell_gets_the_same_words(gnu_make, tmp_path, text, formatted, "all")

    def test_continuation_lines_get_the_indentation_of_the_first(
        self, gnu_make, tmp_path
    ):
        text = "all:\n\t@echo a \\\n\t    b \\\n\t  c\n"
        formatted = _format(text, DEFAULT).content
        assert formatted == "all:\n\t@echo a \\\n\t    b \\\n\t    c\n"
        _assert_shell_gets_the_same_words(gnu_make, tmp_path, text, formatted, "all")


class TestMakefileSyntax:
    """Outside recipes make condenses the whitespace around a backslash/
    newline into one space (GNU 776-781)."""

    def test_variable_continuation_is_normalized(self, gnu_make, tmp_path):
        text = "X = a\\\n   b    \\\n c\nall: ; @echo [$(X)]\n"
        formatted = _format(text, DEFAULT).content
        assert formatted == "X = a\\\n   b \\\n   c\nall: ; @echo [$(X)]\n"
        _assert_make_reads_the_same(gnu_make, tmp_path, text, formatted, "all")

    def test_define_body_stays_as_written(self, gnu_make, tmp_path):
        """A define body is the value of a variable (GNU 4795-4814)."""
        text = "define BODY\na \\\n    b \\\n  c\nendef\nall: ; @echo [$(BODY)]\n"
        formatted = _format(text, DEFAULT).content
        assert formatted == text
        _assert_make_reads_the_same(gnu_make, tmp_path, text, formatted, "all")

    def test_three_backslashes(self, gnu_make, tmp_path):
        """make keeps one backslash of the three as text, and the whitespace
        before it: 'a\\\\\\' and 'b' give 'a\\ b'. v1.5.0 put a space before
        the last backslash, which made the value 'a  \\\\ b'."""
        text = "Y = x \\\n  a  \\\\\\\n  b\nall: ; @echo [$(Y)]\n"
        formatted = _format(text, DEFAULT).content
        assert formatted == text
        _assert_make_reads_the_same(gnu_make, tmp_path, text, formatted, "all")
        values = _readings(gnu_make, tmp_path, text, "all")[0]
        assert "[Y=x a  \\ b]" in values[1]
        v150 = text.replace("a  \\\\\\\n", "a  \\\\ \\\n")
        assert "[Y=x a  \\\\ b]" in _readings(gnu_make, tmp_path, v150, "all")[0][1]

    def test_even_backslashes_end_the_block(self, gnu_make, tmp_path):
        """Two backslashes do not continue the line (GNU 762-769)."""
        text = "X = a \\\n  b\\\\\nY = c\nall: ; @echo [$(X)] [$(Y)]\n"
        formatted = _format(text, DEFAULT).content
        assert formatted == text
        _assert_make_reads_the_same(gnu_make, tmp_path, text, formatted, "all")

    def test_posix_keeps_the_whitespace_before_the_backslash(self, gnu_make, tmp_path):
        """With .POSIX, GNU make 4.4 and later keep the whitespace before a
        backslash (GNU 783-786), so the value of v1.5.0's output, which
        condensed it, differs there. make 4.3 and 3.81 condense either way."""
        text = ".POSIX:\nY = a\\\n  b\\\n  c   \\\n  d\nall: ; @echo [$(Y)]\n"
        formatted = _format(text, DEFAULT).content
        assert formatted == text
        _assert_make_reads_the_same(gnu_make, tmp_path, text, formatted, "all")
        if _make_release(gnu_make[0]) >= (4, 4):
            values = _readings(gnu_make, tmp_path, text, "all")[0]
            assert "[Y=a b c    d]" in values[1]
            v150 = text.replace("b\\\n  c   \\", "b \\\n  c \\")
            assert "[Y=a b  c  d]" in _readings(gnu_make, tmp_path, v150, "all")[0][1]

    def test_posix_define_body_stays_as_written(self, gnu_make, tmp_path):
        """A define body below .POSIX stays as written too: GNU make 4.4 and
        later keep the whitespace before its backslashes (GNU 783-786,
        4795-4814), so the value of v1.5.0's output, which condensed it,
        differs there. make 4.3 and 3.81 condense either way."""
        text = (
            ".POSIX:\ndefine BODY\na\\\n  b   \\\n      c \\\n  d\nendef\n"
            "all: ; @echo [$(BODY)]\n"
        )
        formatted = _format(text, DEFAULT).content
        assert formatted == text
        _assert_make_reads_the_same(gnu_make, tmp_path, text, formatted, "all")
        if _make_release(gnu_make[0]) >= (4, 4):
            values = _readings(gnu_make, tmp_path, text, "all")[0]
            assert "[BODY=a b    c  d]" in values[1]
            v150 = text.replace("  b   \\\n      c", "  b \\\n  c")
            v150_values = _readings(gnu_make, tmp_path, v150, "all")[0]
            assert "[BODY=a b  c  d]" in v150_values[1]


class TestRecipeValidationOnePass:
    """RecipeValidationRule gives each line of a run of recipe lines without
    their TAB a TAB in one run, so a second run changes nothing."""

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("all:\necho a\necho b\n", "all:\n\techo a\n\techo b\n"),
            (
                "all :\n\t@echo no\\\nspace\nfoo\n",
                "all:\n\t@echo no\\\n\tspace\n\tfoo\n",
            ),
        ],
    )
    def test_run_of_lines(self, text, expected):
        assert _format(text, DEFAULT).content == expected
        _assert_stable(text, DEFAULT)

    @pytest.mark.parametrize("config", ["default", "keep"])
    def test_recipe_prefix_append_after_a_kept_line(self, config):
        """'VPATH = src \\ ' stays as written, so 't5::' starts a rule
        (GNU 762-769); the rules read '.RECIPEPREFIX +=' line by line, as
        before (GNU 5158-5169)."""
        text = ".RECIPEPREFIX += >\nVPATH = src \\ \nt5::\n>@echo r\n>\n"
        _assert_stable(text, CONFIGS[config])


class TestShellUtils:
    """The helpers that decide whether the blanks of a recipe matter."""

    @pytest.mark.parametrize(
        ("block", "sensitive"),
        [
            ([T + "@echo a"], False),
            ([T + "@echo a " + BS, T + "b"], False),
            ([T + "@echo a" + BS, T + "b"], True),
            ([T + "@echo a" + BS, T + " b"], False),
            ([T + "@echo a" + BS, T + BS, T + "b"], True),
            ([T + "@echo 'a " + BS, T + "b'"], True),
            ([T + '@echo "a ' + BS, T + 'b"'], True),
            ([T + '@echo \\"a ' + BS, T + "b"], False),
            ([T + "@cat <<EOF " + BS, T + "x"], True),
            # Without the recipe prefix all of a line's blanks go to the
            # shell; they only separate words here (GNU 2917-2925).
            ([T + "@echo a " + BS, "  b"], False),
            ([T + "@echo a" + BS, "  b"], False),
            # The manual's example: 'no\' and 'space' join (GNU 2927-2944).
            ([T + "@echo no" + BS, "space"], True),
        ],
    )
    def test_recipe_block_is_whitespace_sensitive(self, block, sensitive):
        result = line_utils.ShellUtils.recipe_block_is_whitespace_sensitive(block)
        assert result is sensitive

    def test_recipe_prefix_of_the_block(self):
        """The recipe prefix comes off each continuation line (GNU
        5158-5169)."""
        utils = line_utils.ShellUtils
        assert utils.recipe_block_is_whitespace_sensitive([">@echo a" + BS, ">b"], ">")
        assert not utils.recipe_block_is_whitespace_sensitive(
            [">@echo a" + BS, "> b"], ">"
        )

    @pytest.mark.parametrize(
        ("old", "new"),
        [
            # A TAB in place of spaces that separate words
            ([T + "@echo a " + BS, "  b"], [T + "@echo a " + BS, T + "b"]),
            # 'no' and 'space' would join.
            ([T + "@echo no" + BS, "  space"], [T + "@echo no" + BS, T + "space"]),
        ],
        ids=["separates", "joins"],
    )
    def test_tab_for_spaces_of_a_continuation_line(self, old, new):
        """The guard lets a continuation line get a TAB in place of its
        spaces only where the shell gets the same words."""
        preserved = line_utils.ShellUtils.recipe_rewrite_preserves_shell_text(old, new)
        assert preserved is (old[0].endswith(" " + BS))

    @pytest.mark.parametrize(
        ("old", "new", "preserved"),
        [
            ([T + "@echo a " + BS, T + "  b"], [T + "@echo a " + BS, T + "b"], True),
            ([T + "@echo a" + BS, T + " b"], [T + "@echo a" + BS, T + "b"], False),
            (
                [T + '@echo "a ' + BS, T + ' b"'],
                [T + '@echo "a ' + BS, T + 'b"'],
                False,
            ),
            # make removes the blanks and the '@' before the command (GNU
            # 3037-3038).
            ([T + "@echo 'a"], [T + "  @echo 'a"], True),
            ([T + "@echo a"], [T + "@echo a"], True),
            ([T + "@echo a " + BS, T + "b"], [T + "@echo a " + BS], False),
        ],
    )
    def test_recipe_rewrite_preserves_shell_text(self, old, new, preserved):
        utils = line_utils.ShellUtils
        assert utils.recipe_rewrite_preserves_shell_text(old, new) is preserved

    def test_uses_oneshell(self):
        utils = line_utils.ShellUtils
        assert utils.uses_oneshell([".ONESHELL:"])
        assert not utils.uses_oneshell(["all: .ONESHELL", "# .ONESHELL:"])

    def test_names_target(self):
        utils = line_utils.LineUtils
        assert utils.names_target([".POSIX:"], ".POSIX")
        assert utils.names_target(["a \\", "  .POSIX:"], ".POSIX")
        assert not utils.names_target(["X = .POSIX:"], ".POSIX")
        assert not utils.names_target(["foo: X = .POSIX:"], ".POSIX")
        assert not utils.names_target(["# .POSIX:"], ".POSIX")


# Recipes whose continuation lines start with spaces, without the recipe
# prefix, where the spaces only separate words (GNU 2917-2925), and the output
# of the formatter before this change, which it keeps
SPACE_LED = {
    "aligned": (
        "prog: main.o util.o\n\t@echo $(CC) -o prog      \\\n"
        "        main.o         \\\n        util.o\n",
        "prog: main.o util.o\n\t@echo $(CC) -o prog      \\\n\tmain.o \\\n\tutil.o\n",
        "prog",
    ),
    "flags": (
        "build:\n\t@echo gcc -o prog main.c \\\n        -O2   \\\n        -Wall\n",
        "build:\n\t@echo gcc -o prog main.c \\\n\t-O2 \\\n\t-Wall\n",
        "build",
    ),
    "last_line": (
        "all:\n\t@echo a \\\n\t  b \\\n  c\n",
        "all:\n\t@echo a \\\n\t  b \\\n\t  c\n",
        "all",
    ),
    "mixed": (
        "build:\n\t@echo gcc -o app \\\n\t    main.c \\\n        util.c\n",
        "build:\n\t@echo gcc -o app \\\n\t    main.c \\\n\t    util.c\n",
        "build",
    ),
    "first_line": (
        "build:\n\t@echo a \\\n    b \\\n\t  c\n",
        "build:\n\t@echo a \\\n\tb \\\n\tc\n",
        "build",
    ),
    "two_tabs": (
        "build:\n\t@echo $(CC) $(CFLAGS) \\\n\t\t-I include \\\n            -o $@ $^\n",
        "build:\n\t@echo $(CC) $(CFLAGS) \\\n\t\t-I include \\\n\t\t-o $@ $^\n",
        "build",
    ),
    # TabsRule moves the space-led 'else' to column 1; ShellFormattingRule
    # then indents the block, as before.
    "shell_else": (
        "check:\n\t@if [ -f x ]; then \\\n        echo yes; \\\n    else \\\n"
        "        echo no; \\\n    fi\n",
        "check:\n\t@if [ -f x ]; then \\\n\t\techo yes; \\\n\telse \\\n"
        "\t\techo no; \\\n\tfi\n",
        "check",
    ),
}


class TestContinuationLinesWithoutTheirTab:
    """A continuation line without the recipe prefix passes all of its
    whitespace to the shell (GNU 2917-2925); where that only separates words,
    the recipe is formatted as before, in one run."""

    @pytest.mark.parametrize("name", sorted(SPACE_LED))
    def test_output_as_before(self, name):
        text, expected, _goal = SPACE_LED[name]
        assert _format(text, DEFAULT).content == expected

    @pytest.mark.parametrize("config", sorted(ALL_CONFIGS))
    @pytest.mark.parametrize("name", sorted(SPACE_LED))
    def test_second_run_changes_nothing(self, name, config):
        _assert_stable(SPACE_LED[name][0], ALL_CONFIGS[config])

    @pytest.mark.parametrize("name", sorted(SPACE_LED))
    def test_shell_gets_the_same_words(self, gnu_make, tmp_path, name):
        text, expected, goal = SPACE_LED[name]
        _assert_shell_gets_the_same_words(gnu_make, tmp_path, text, expected, goal)

    def test_check_after_format(self, tmp_path, monkeypatch):
        """'format' and then 'format --check' finds nothing to change."""
        text = SPACE_LED["aligned"][0]
        (tmp_path / "Makefile").write_bytes(text.encode("utf-8"))
        (tmp_path / "bake.toml").write_bytes(b"")
        monkeypatch.chdir(tmp_path)
        runner = _runner()
        args = ["format", "--config", "bake.toml"]
        assert runner.invoke(app, [*args, "Makefile"]).exit_code == 0
        assert runner.invoke(app, [*args, "--check", "Makefile"]).exit_code == 0


class TestTargetsAndShellsNamedInText:
    """Only a rule names a special target (GNU 2410-2423), and only makefile
    syntax sets SHELL (GNU 2897-2900, 4938-4951): text in a recipe line, in
    a function call or in a define body that no '$(eval ...)' reads leaves
    the recipes of a makefile as before."""

    @pytest.mark.parametrize(
        "lines",
        [
            ["test:", T + "SHELL=/bin/sh ./run-tests.sh"],
            ["run:", T + "export SHELL=/bin/bash; ./x"],
            ["all:", T + '@echo "add .ONESHELL: to use one shell"'],
            ["$(info note: .ONESHELL: is not used here)", "all: ; @:"],
            ["define HELP", "Use .ONESHELL: if you want one shell", "endef"],
            ["define HELP", "SHELL = python3", "endef"],
        ],
    )
    def test_shell_is_not_opaque(self, lines):
        assert not line_utils.ShellUtils.recipes_are_shell_opaque(lines)

    @pytest.mark.parametrize(
        "lines",
        [
            # A define body that '$(eval ...)' may read as makefile syntax
            ["define HELP", ".ONESHELL:", "endef", "$(eval $(HELP))"],
            ["define HELP", "SHELL = python3", "endef", "$(eval $(HELP))"],
            ["$(eval SHELL = python3)", "all: ; @:"],
            # A target in a reference, which may expand to .ONESHELL
            ["$(if x,.ONESHELL): ; @:"],
        ],
    )
    def test_shell_is_opaque(self, lines):
        assert line_utils.ShellUtils.recipes_are_shell_opaque(lines)

    def test_hidden_lines_count(self):
        """A '.ONESHELL:' line that '# bake-format off' hides counts."""
        lines = ["# bake-format off", "# bake-format on", "all: ; @:"]
        utils = line_utils.ShellUtils
        assert utils.recipes_are_shell_opaque(lines, {0: [".ONESHELL:"]})
        assert not utils.recipes_are_shell_opaque(lines, {0: ["all:", T + "@:"]})

    @pytest.mark.parametrize(
        "lines",
        [
            ["all:", T + "@echo see .POSIX: in the manual"],
            ["$(info .POSIX: is a special target)"],
        ],
    )
    def test_posix_is_not_named(self, lines):
        assert not line_utils.LineUtils.names_target(lines, ".POSIX")

    def test_first_target_line(self):
        lines = ["X = a", "all: ; @:", ".POSIX:", ".POSIX:"]
        assert line_utils.LineUtils.first_target_line(lines, ".POSIX") == 2
        assert line_utils.LineUtils.first_target_line(lines, ".ONESHELL") is None

    RECIPES = {
        "recipe_assigns_shell": (
            "test:\n\tSHELL=/bin/sh ./run-tests.sh\nbuild:\n"
            "\t@echo gcc -o prog main.c \\\n\t    -O2     \\\n\t  -Wall\n",
            "test:\n\tSHELL=/bin/sh ./run-tests.sh\nbuild:\n"
            "\t@echo gcc -o prog main.c \\\n\t    -O2 \\\n\t    -Wall\n",
            "build",
        ),
        "recipe_names_oneshell": (
            'all:\n\t@echo "add .ONESHELL: to use one shell"\n'
            "\t@if [ -d / ]; then \\\n\techo yes; \\\n\tfi\n",
            'all:\n\t@echo "add .ONESHELL: to use one shell"\n'
            "\t@if [ -d / ]; then \\\n\t\techo yes; \\\n\tfi\n",
            "all",
        ),
        "recipe_names_posix": (
            "SRCS = a.c     \\\n       b.c     \\\n       c.c\nall:\n"
            '\t@echo "see .POSIX: in the manual [$(SRCS)]"\n',
            "SRCS = a.c     \\\n       b.c \\\n       c.c\nall:\n"
            '\t@echo "see .POSIX: in the manual [$(SRCS)]"\n',
            "all",
        ),
        # make 4.x reads the lines above .POSIX in the usual way (GNU 783-786).
        "posix_below": (
            "X = a    \\\n      b   \\\n   c\nall: ; @echo [$(X)]\n.POSIX:\n",
            "X = a    \\\n      b \\\n      c\nall: ; @echo [$(X)]\n.POSIX:\n",
            "all",
        ),
    }

    @pytest.mark.parametrize("name", sorted(RECIPES))
    def test_formatted_as_before(self, name):
        text, expected, _goal = self.RECIPES[name]
        assert _format(text, DEFAULT).content == expected
        _assert_stable(text, DEFAULT)

    @pytest.mark.parametrize("name", sorted(RECIPES))
    def test_make_reads_the_same(self, gnu_make, tmp_path, name):
        text, expected, goal = self.RECIPES[name]
        _assert_shell_gets_the_same_words(gnu_make, tmp_path, text, expected, goal)


class TestCheckModeLineNumbers:
    """Check mode reads the lines that format mode reads: a recipe line that
    RecipeValidationRule gives its TAB stays in place, so later messages
    point at the lines of the file."""

    def test_warning_below_a_line_without_its_tab(self):
        text = "all:\necho a\nX = a \\ \nY = b\n"
        lines = text.splitlines()
        expected = f"3: Warning: {WARNING}"
        assert _formatter().format_lines(lines, False, text)[2] == [expected]
        assert expected in _formatter().format_lines(lines, True, text)[2]
        traditional = MakefileFormatter(
            Config(formatter=FormatterConfig(), gnu_error_format=False)
        )
        warnings = traditional.format_lines(lines, True, text)[2]
        assert f"Warning: {WARNING} (line 3)" in warnings

    @pytest.mark.parametrize(
        ("text", "config", "messages"),
        [
            (
                "all:\necho a\necho b\nX = 1",
                DEFAULT,
                [
                    "2: Error: Missing required tab separator in recipe line",
                    "3: Error: Missing required tab separator in recipe line",
                    "4: Warning: Missing final newline",
                ],
            ),
            (
                "all:\necho a\necho b\necho c\nall2:\n\t@echo hi\n"
                ".PHONY: all2 all2\nX = 1",
                DEFAULT,
                [
                    "7: Warning: Consider adding targets to .PHONY declaration: all",
                    "8: Warning: Missing final newline",
                ],
            ),
            (
                "all:\necho a\necho b\nA = 1\nBB = 2",
                {"align_variable_assignments": True},
                [
                    "Lines 4-5: Variable assignments would be aligned",
                    "5: Warning: Missing final newline",
                ],
            ),
        ],
        ids=["final-newline", "phony", "alignment"],
    )
    def test_messages_point_at_their_lines(self, text, config, messages):
        warnings = _formatter(**config).format_lines(text.splitlines(), True, text)[2]
        for message in messages:
            assert message in warnings

    def test_without_the_fix_check_still_fails(self):
        """With fix_missing_recipe_tabs off, check mode reports the line as
        before and still finds a change."""
        text = "all:\necho hi\n"
        formatter = _formatter(fix_missing_recipe_tabs=False)
        lines, _errors, warnings = formatter.format_lines(text.splitlines(), True, text)
        assert "2: Error: Missing required tab separator in recipe line" in warnings
        assert lines != text.splitlines()


class TestRegionMarkerAtTheEnd:
    """A '# bake-format off' line whose region runs to the end of the file is
    the line that the warning reports, not the last line of the file."""

    TEXT = "A = 1\n# bake-format off \\ \nX = 1\nY = 2\n"

    def test_format_and_check_mode(self):
        lines = self.TEXT.splitlines()
        expected = f"2: Warning: {WARNING}"
        assert _format(self.TEXT, DEFAULT).warnings == [expected]
        assert expected in _formatter().format_lines(lines, True, self.TEXT)[2]
        result = _format(self.TEXT, DEFAULT, gnu_error_format=False)
        assert result.warnings == [f"Warning: {WARNING} (line 2)"]

    def test_final_newline_still_points_at_the_end(self):
        text = self.TEXT.rstrip("\n")
        warnings = _formatter().format_lines(text.splitlines(), True, text)[2]
        assert f"2: Warning: {WARNING}" in warnings
        assert "4: Warning: Missing final newline" in warnings

    def test_check_prints_the_line(self, tmp_path, monkeypatch):
        (tmp_path / "Makefile").write_bytes(self.TEXT.encode("utf-8"))
        (tmp_path / "bake.toml").write_bytes(b"")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COLUMNS", "200")  # keep Rich from wrapping the line
        result = _runner().invoke(
            app, ["format", "--config", "bake.toml", "--check", "Makefile"]
        )
        assert f"Makefile:2: Warning: {WARNING}" in result.stdout


AUTO_GROUP_AFTER = {
    "auto_insert_phony_declarations": True,
    "group_phony_declarations": True,
    "phony_at_top": True,
}


class TestPhonyAfterAKeptLine:
    """A kept line whose backslash whitespace follows does not continue onto
    the rule below it (GNU 762-769), so the grouped '.PHONY:' line goes before
    the rule, not between the rule and its recipe."""

    TEXTS = {
        "assignment": "X ?= a \\ \nt2:\n\t@printf '%s\\n' 'a  b'\nall: t2\n",
        "comment": "X = 1\n# note \\ \nt2:\n\t@printf '%s\\n' 'a  b'\n.PHONY: t2\n",
        "vpath": "VPATH = src \\ \nt2:\n\t@printf '%s\\n' 'a  b'\n",
    }

    @pytest.mark.parametrize("name", sorted(TEXTS))
    def test_rule_keeps_its_recipe(self, name):
        lines = _format(self.TEXTS[name], AUTO_GROUP_AFTER).content.splitlines()
        rule = lines.index("t2:")
        assert lines[rule + 1] == "\t@printf '%s\\n' 'a  b'"
        assert any(line.startswith(".PHONY:") for line in lines[:rule])
        _assert_stable(self.TEXTS[name], AUTO_GROUP_AFTER)

    @pytest.mark.parametrize("name", sorted(TEXTS))
    def test_make_runs_the_recipe(self, gnu_make, tmp_path, name):
        text = self.TEXTS[name]
        formatted = _format(text, AUTO_GROUP_AFTER).content
        assert _readings(gnu_make, tmp_path, formatted, "t2")[2] == (0, "a  b\n")
        assert _readings(gnu_make, tmp_path, text, "t2")[2] == (0, "a  b\n")

    def test_insertion_point(self):
        parser = line_utils.MakefileParser
        lines = ["X ?= a \\ ", "t2:", T + "@printf x", "all: t2"]
        assert parser.find_phony_insertion_point(lines) == 1
        lines[0] = "X ?= a \\"
        assert parser.find_phony_insertion_point(lines) == 2


# Lines that make 3.81 reads on while make 4.x stops at them ("missing
# separator"): an 'override' line without an assignment, which make 3.81
# reports as an invalid override directive, and a line with '=' after a name
# with blanks, which make 3.81 reads as an assignment
READ_BY_MAKE_381 = [
    "override X",
    "override",
    "foo bar = 1",
    "foo bar += 1",
    "       -lpthread -DFOO=1",
    "-lfoo Y = b",
]


class TestRepairOnlyWhereEveryMakeStops:
    """The whitespace after a backslash goes only where both make 3.81 and
    make 4.x reject the next line on its own."""

    @pytest.mark.parametrize("following", READ_BY_MAKE_381)
    def test_line_is_kept(self, following):
        text = "X = a \\ \n" + following + "\nall: ; @echo [$(X)]\n"
        result = _format(text, DEFAULT)
        assert result.content == text
        assert result.warnings == [f"1: Warning: {WARNING}"]
        assert rule_context.dangling_backslash_repairs(text.splitlines(), {}) == set()

    @pytest.mark.parametrize("following", ["=", " = x", "+= x", "private X"])
    def test_empty_name_is_repaired(self, following):
        """make stops at these lines ("empty variable name", "missing
        separator")."""
        lines = ["X = a \\ ", following]
        assert rule_context.dangling_backslash_repairs(lines, {}) == {0}

    @pytest.mark.parametrize("following", READ_BY_MAKE_381)
    def test_only_make_4_stops(self, gnu_make, tmp_path, following):
        """make 3.81 reads the input, with X set to 'a \\ ', so the repair
        would change its value; make 4.x rejects the input."""
        text = "X = a \\ \n" + following + "\nall: ; @echo [$(X)]\n"
        args = ["-s", "-f", "probe.mk", "__probe__"]
        returncode, output = _make(gnu_make, tmp_path, text, args)
        if gnu_make[3] < 4:
            assert returncode == 0
            assert "[X=a \\ ]" in output
        else:
            assert returncode != 0


class TestStableWhereMakeStops:
    """The first line of a continued rule keeps its spaces: make reads the
    lines as one rule (GNU 1209-1219), and a TAB would make them a recipe
    line that make rejects ("recipe commences before first target",
    11292-11297). The recipe after the ';' is judged the same way on the next
    run."""

    TEXT = "  d \\\nall: ; @echo 'h \\\n$(R)\ninclude $(NONE)\n"

    @pytest.mark.parametrize("config", sorted(ALL_CONFIGS))
    def test_second_run_changes_nothing(self, config):
        assert _format(self.TEXT, ALL_CONFIGS[config]).content == self.TEXT
        _assert_stable(self.TEXT, ALL_CONFIGS[config])


# The configurations that the tests below check besides ALL_CONFIGS
MORE_CONFIGS = {
    **ALL_CONFIGS,
    "no-fix": {"fix_missing_recipe_tabs": False},
    "conservative": {
        "auto_insert_phony_declarations": False,
        "ensure_final_newline": False,
        "group_phony_declarations": False,
        "phony_at_top": False,
    },
    "auto-group": AUTO_GROUP_AFTER,
    "auto-ungroup": {
        "auto_insert_phony_declarations": True,
        "group_phony_declarations": False,
    },
    "align": {"align_variable_assignments": True},
    "no-space": {"space_around_assignment": False, "space_after_colon": False},
    "space-before": {"space_before_colon": True},
}
# Those that change no line but recipe continuation lines
SAME_LINES_CONFIGS = ["default", "keep", "no-fix", "no-normalize", "indent2", "indent4"]

# Recipes whose continuation lines start with spaces or with the TAB, after
# backslashes with and without a blank before them, with the output of v1.5.0,
# which one run gives. make removes one recipe prefix character after a
# backslash/newline (GNU 2917-2925): a TAB in place of the spaces after 'do\'
# would join 'do' and 'echo', while the two TABs that ShellFormattingRule gives
# the loop body leave a blank, and a TAB after 'done; \' joins nothing.
MIXED_PREFIXES = {
    "for": (
        "build:\n\t@for f in a b; do\\\n    echo $$f; \\\n\tdone; \\\n    echo end\n",
        "build:\n\t@for f in a b; do\\\n\t\techo $$f; \\\n\tdone; \\\n\techo end\n",
        "build",
    ),
    "if": (
        "check:\n\t@if [ -f x ]; then\\\n \techo yes; \\\n\tfi; \\\n    echo done\n",
        "check:\n\t@if [ -f x ]; then\\\n\t\techo yes; \\\n\tfi; \\\n\techo done\n",
        "check",
    ),
    "case": (
        'os:\n\t@case "$(OS)" in\\\n \tlinux) echo l;; \\\n\tesac; \\\n    echo end\n',
        'os:\n\t@case "$(OS)" in\\\n\t\tlinux) echo l;; \\\n\tesac; \\\n\techo end\n',
        "os",
    ),
}
# A 'then\' in the middle of a recipe line, and the output of v1.5.0
MID_BLOCK = (
    "build:\n\t@echo start; \\\n    echo mid; \\\n\tif [ -f x ]; then\\\n"
    "        echo yes; \\\n\tfi\n"
)
MID_BLOCK_FORMATTED = {
    "default": "build:\n\t@echo start; \\\n\techo mid; \\\n\tif [ -f x ]; then \\\n"
    "\t\techo yes; \\\n\tfi\n",
    "no-normalize": "build:\n\t@echo start; \\\n\techo mid; \\\n\tif [ -f x ]; then\\\n"
    "\t\techo yes; \\\n\tfi\n",
}


class TestMixedRecipePrefixes:
    """One run gives the final text where a recipe line's continuation lines
    mix TABs and leading spaces (GNU 2917-2925)."""

    @pytest.mark.parametrize("config", SAME_LINES_CONFIGS)
    @pytest.mark.parametrize("name", sorted(MIXED_PREFIXES))
    def test_output_of_v150(self, name, config):
        text, expected, _goal = MIXED_PREFIXES[name]
        assert _format(text, MORE_CONFIGS[config]).content == expected

    @pytest.mark.parametrize("config", sorted(MORE_CONFIGS))
    @pytest.mark.parametrize("name", sorted(MIXED_PREFIXES))
    def test_second_run_changes_nothing(self, name, config):
        _assert_stable(MIXED_PREFIXES[name][0], MORE_CONFIGS[config])

    @pytest.mark.parametrize("name", sorted(MIXED_PREFIXES))
    def test_shell_runs_the_same(self, gnu_make, tmp_path, name):
        text, expected, goal = MIXED_PREFIXES[name]
        _assert_shell_gets_the_same_words(gnu_make, tmp_path, text, expected, goal)

    @pytest.mark.parametrize("name", sorted(MIXED_PREFIXES))
    def test_check_after_format(self, tmp_path, monkeypatch, name):
        """'format' and then 'format --check' finds nothing to change."""
        (tmp_path / "Makefile").write_bytes(MIXED_PREFIXES[name][0].encode("utf-8"))
        (tmp_path / "bake.toml").write_bytes(b"")
        monkeypatch.chdir(tmp_path)
        runner = _runner()
        args = ["format", "--config", "bake.toml"]
        assert runner.invoke(app, [*args, "Makefile"]).exit_code == 0
        assert runner.invoke(app, [*args, "--check", "Makefile"]).exit_code == 0

    @pytest.mark.parametrize("config", sorted(MID_BLOCK_FORMATTED))
    def test_then_in_the_middle(self, gnu_make, tmp_path, config):
        formatted = _format(MID_BLOCK, MORE_CONFIGS[config]).content
        assert formatted == MID_BLOCK_FORMATTED[config]
        _assert_stable(MID_BLOCK, MORE_CONFIGS[config])
        _assert_shell_gets_the_same_words(
            gnu_make, tmp_path, MID_BLOCK, formatted, "build"
        )


class TestKeepShellText:
    """ShellUtils.keep_shell_text keeps each line's new indentation only where
    the shell gets the same words; make removes one recipe prefix character
    after a backslash/newline (GNU 2917-2925)."""

    LOOP = [T + "@for f in a b; do" + BS, "    echo $$f; " + BS, T + "done"]

    def test_tab_after_a_word_is_undone(self):
        """'do\\' and the TAB's line would run 'doecho'."""
        new = [self.LOOP[0], T + "echo $$f; " + BS, self.LOOP[2]]
        assert line_utils.ShellUtils.keep_shell_text(self.LOOP, new) == self.LOOP

    def test_prefix_and_one_more_tab_are_kept(self):
        """make removes the first TAB; the second one ends the word."""
        new = [self.LOOP[0], T + T + "echo $$f; " + BS, self.LOOP[2]]
        assert line_utils.ShellUtils.keep_shell_text(self.LOOP, new) == new

    def test_tab_after_a_blank_is_kept(self):
        old = [T + "@echo a " + BS, "    b"]
        new = [old[0], T + "b"]
        assert line_utils.ShellUtils.keep_shell_text(old, new) == new

    def test_each_line_on_its_own(self):
        old = [T + "@echo a" + BS, "    b " + BS, "    c"]
        new = [old[0], T + "b " + BS, T + "c"]
        expected = [old[0], old[1], T + "c"]
        assert line_utils.ShellUtils.keep_shell_text(old, new) == expected

    def test_blanks_in_quotes_stay(self):
        old = [T + '@echo "a ' + BS, '    b"']
        new = [old[0], T + 'b"']
        assert line_utils.ShellUtils.keep_shell_text(old, new) == old

    @pytest.mark.parametrize("opaque", [False, True])
    def test_recipe_prefix_may_come_and_go(self, opaque):
        """The text that the shell gets stays the same, with any shell."""
        utils = line_utils.ShellUtils
        old = [T + "@echo h " + BS, "x"]
        new = [old[0], T + "x"]
        assert utils.keep_shell_text(old, new, opaque=opaque) == new
        assert utils.keep_shell_text(new, old, opaque=opaque) == old

    @pytest.mark.parametrize("opaque", [False, True])
    @pytest.mark.parametrize(
        ("opener", "closer"), [("'", "'"), ('"', '"'), ("<<EOF ", "")]
    )
    def test_start_of_a_quoted_line_stays(self, opaque, opener, closer):
        """make 3.81 prints the recipe prefix of a line that starts inside
        quotes or a here-document as part of the text (GNU 2917-2925)."""
        utils = line_utils.ShellUtils
        old = [T + "@cat " + opener + "h " + BS, "x " + BS, "y" + closer]
        new = [old[0], T + "x " + BS, T + "y" + closer]
        assert utils.keep_shell_text(old, new, opaque=opaque) == old
        assert utils.keep_shell_text(new, old, opaque=opaque) == new

    def test_unknown_shell_keeps_the_blanks_of_the_first_line(self):
        """With .ONESHELL make passes on the blanks at the start of a recipe
        line after the first (GNU 3107-3110)."""
        utils = line_utils.ShellUtils
        old = [T + "    for j in range(2):"]
        new = [T + "for j in range(2):"]
        assert utils.keep_shell_text(old, new, opaque=True) == old
        assert utils.keep_shell_text(old, new) == new


# A rule line continued onto a line with a ';' recipe that continues onto a
# line at column 1, the goals that make -n runs, and v1.5.0's output. make
# reads a line that does not start with the recipe prefix, with the lines that
# it continues over, as makefile syntax (GNU 1209-1219, 776-781), here a rule
# whose recipe starts after the ';' (1499-1503), and passes the recipe text to
# the shell as written (2917-2925). The output is the input: v1.5.0 gave
# '  d \' a TAB, which made the lines a recipe line, of t2's recipe in
# "rule_above" ("No rule to make target 't3'") and one that make rejects in
# "spaces" ("recipe commences before first target", 11292-11297).
CONTINUED_RULES = {
    "first_line": (
        "d \\\nall: ; @echo 'h \\\nx'\n",
        ["d", "all"],
        "d \\\nall: ; @echo 'h \\\nx'\n",
    ),
    "spaces": (
        "  d \\\nall: ; @echo 'h \\\nx'\n",
        ["d", "all"],
        "\td \\\nall: ; @echo 'h \\\nx'\n",
    ),
    "rule_above": (
        "t2:\n\t@echo a\n  d \\\nt3: ; echo util.o \\\nx;\n",
        ["d", "t2", "t3"],
        "t2:\n\t@echo a\n\td \\\nt3: ; echo util.o \\\nx;\n",
    ),
    "include_below": (
        "  d \\\nall: ; @echo 'h \\\n$(R)\ninclude $(NONE)\n",
        ["d", "all"],
        "\td \\\nall: ; @echo 'h \\\n$(R)\ninclude $(NONE)\n",
    ),
}
# The configurations that change no line of these makefiles
KEEPS_CONTINUED_RULES = [
    "default",
    "keep",
    "no-fix",
    "indent2",
    "indent4",
    "align",
]


class TestContinuedRuleWithASemicolonRecipe:
    """A continued rule line whose ';' recipe continues onto column 1 stays
    as written, make reads the same rule and recipe, and a second run changes
    nothing."""

    @pytest.mark.parametrize("config", sorted(MORE_CONFIGS))
    @pytest.mark.parametrize("name", sorted(CONTINUED_RULES))
    def test_second_run_changes_nothing(self, name, config):
        _assert_stable(CONTINUED_RULES[name][0], MORE_CONFIGS[config])

    # The quoted text after the ';' starts with two spaces, which the shell
    # keeps (GNU 2946-2969); '  d \' keeps its spaces.
    QUOTED_SPACES = [
        "  d \\\nall2: ; @echo 'h \\\n  x'\n",
        "t0:\n\t@echo a\n  d \\\nall2: ; @echo 'h \\\n  x'\n",
    ]

    @pytest.mark.parametrize("config", sorted(MORE_CONFIGS))
    @pytest.mark.parametrize("text", QUOTED_SPACES)
    def test_quoted_spaces_stay(self, text, config):
        formatted = _format(text, MORE_CONFIGS[config]).content
        assert formatted.endswith("\n  x'\n") or formatted.endswith("\n  x'")
        _assert_stable(text, MORE_CONFIGS[config])

    @pytest.mark.parametrize("config", KEEPS_CONTINUED_RULES)
    @pytest.mark.parametrize("text", QUOTED_SPACES)
    def test_quoted_spaces_run_the_same(self, gnu_make, tmp_path, text, config):
        """The rule keeps its first line, so make reads the rule as written."""
        formatted = _format(text, MORE_CONFIGS[config]).content
        assert formatted == text
        run = _readings(gnu_make, tmp_path, text, "all2")[2]
        assert run == (0, "h   x\n" if gnu_make[3] < 4 else "h \\\n  x\n")

    @pytest.mark.parametrize("config", KEEPS_CONTINUED_RULES)
    @pytest.mark.parametrize("name", sorted(CONTINUED_RULES))
    def test_output_is_the_input(self, name, config):
        text, _goals, _v150 = CONTINUED_RULES[name]
        assert _format(text, MORE_CONFIGS[config]).content == text

    @pytest.mark.parametrize(
        "name",
        sorted(name for name, rule in CONTINUED_RULES.items() if rule[2] != rule[0]),
    )
    def test_v150_made_a_recipe_line(self, gnu_make, tmp_path, name):
        """make -n runs other commands from v1.5.0's output than from the
        input, or rejects it."""
        text, goals, v150 = CONTINUED_RULES[name]
        dry_run = _make(gnu_make, tmp_path, text, ["-n", *goals])
        assert dry_run[0] == 0
        assert _make(gnu_make, tmp_path, v150, ["-n", *goals]) != dry_run

    @pytest.mark.parametrize(
        "config", ["no-normalize", "auto-group", "auto-ungroup", "no-space"]
    )
    @pytest.mark.parametrize("name", sorted(CONTINUED_RULES))
    def test_make_reads_the_same_rules(self, gnu_make, tmp_path, name, config):
        """Where other lines change, make still reads the rule and runs the
        same recipe: the shell gets the same words (GNU 2917-2925)."""
        text, goals, _v150 = CONTINUED_RULES[name]
        formatted = _format(text, MORE_CONFIGS[config]).content
        assert (
            "\n  d \\\n" in formatted
            or "\nd \\\n" in formatted
            or (formatted.startswith(("  d \\\n", "d \\\n")))
        )
        expected = _make(gnu_make, tmp_path, text, ["-n", *goals])
        actual = _make(gnu_make, tmp_path, formatted, ["-n", *goals])
        assert actual[0] == expected[0] == 0
        assert _words(actual[1], gnu_make[3]) == _words(expected[1], gnu_make[3])

    @pytest.mark.parametrize(
        "config",
        ["default", "keep", "indent2", "indent4", "auto-group", "auto-ungroup"],
    )
    def test_make_prints_the_same_command(self, gnu_make, tmp_path, config):
        """make 3.81 prints a TAB at the start of a continuation line in
        'make -n' (GNU 2917-2925): the line gets none."""
        for text, goals, _v150 in CONTINUED_RULES.values():
            formatted = _format(text, MORE_CONFIGS[config]).content
            assert "\n\tx" not in formatted
            dry_run = _make(gnu_make, tmp_path, text, ["-n", *goals])
            assert dry_run[0] == 0
            assert _make(gnu_make, tmp_path, formatted, ["-n", *goals]) == dry_run

    @pytest.mark.parametrize(
        ("config", "expected"),
        [
            ("auto-group", ".PHONY: all\n\nd \\\nall: ; @echo 'h \\\nx'\n"),
            ("auto-ungroup", ".PHONY: all\nd \\\nall: ; @echo 'h \\\nx'\n"),
        ],
    )
    def test_phony_goes_above_the_rule(self, config, expected):
        """A '.PHONY' line between the lines of the rule would end it there
        (GNU 762-769)."""
        formatted = _format(CONTINUED_RULES["first_line"][0], MORE_CONFIGS[config])
        assert formatted.content == expected


# A recipe line whose first continuation line TabsRule gives a TAB for its
# spaces, while it would leave the others as they are, and the text that v1.5.0
# gave on its second run, which one run now gives
FIRST_LINE_GETS_A_TAB = {
    "kept_dangling_line_above": (
        "t0:\n\techo x\\ \n\t\tb  \\\n    $(V) g k=v\t\\\n\t    g g \n",
        "t0:\n\techo x\\ \n\t\tb  \\\n\t$(V) g k=v \\\n\tg g\n",
        "t0",
    ),
    "flag_with_equals": (
        "build:\n\t@echo $(CC) -o prog \\\n        -DFOO=1 \\\n        main.c\n",
        "build:\n\t@echo $(CC) -o prog \\\n\t-DFOO=1 \\\n\tmain.c\n",
        "build",
    ),
    "word_with_equals": (
        "build:\n\t@echo cmd \\\n    a \\\n    k=v x \\\n    c\n",
        "build:\n\t@echo cmd \\\n\ta \\\n\tk=v x \\\n\tc\n",
        "build",
    ),
}


class TestFirstContinuationLineGetsATab:
    """ContinuationRule gives the continuation lines the indentation that
    TabsRule gives the first of them, so one run gives the final text."""

    @pytest.mark.parametrize("name", sorted(FIRST_LINE_GETS_A_TAB))
    def test_output(self, name):
        text, expected, _goal = FIRST_LINE_GETS_A_TAB[name]
        assert _format(text, DEFAULT).content == expected

    @pytest.mark.parametrize("config", sorted(MORE_CONFIGS))
    @pytest.mark.parametrize("name", sorted(FIRST_LINE_GETS_A_TAB))
    def test_second_run_changes_nothing(self, name, config):
        _assert_stable(FIRST_LINE_GETS_A_TAB[name][0], MORE_CONFIGS[config])

    @pytest.mark.parametrize("name", sorted(FIRST_LINE_GETS_A_TAB))
    def test_shell_gets_the_same_words(self, gnu_make, tmp_path, name):
        text, expected, goal = FIRST_LINE_GETS_A_TAB[name]
        _assert_shell_gets_the_same_words(gnu_make, tmp_path, text, expected, goal)


# Recipe continuation lines that look like makefile syntax, with the goal:
# make passes their text to the shell (GNU 2897-2905, 2917-2925), so they stay
# as written, where v1.5.0 rewrote them as assignments, rules and pattern rules
SHELL_TEXT_LINES = {
    "pipefail_assignment": (
        "SHELL := /bin/bash -o pipefail\nbuild:\n\t@echo building && \\\n"
        "\t  echo step2 && \\\nCGO_ENABLED=0 ./show.sh\n",
        "build",
    ),
    "docker_port": ("run:\n\t@docker run \\\n-p 8080:80 image\n", "run"),
    "quoted_host_port": ('run:\n\t@echo "a \\\nhost:port" k=v\n', "run"),
    "joined_assignment": ("run:\n\t@echo a\\\nCGO_ENABLED=0 ./show.sh\n", "run"),
    "pattern_rule": ("x:\n\t@printf %s \\\n%.o:%.c\n", "x"),
    "semicolon_recipe": ("all: ; @echo a \\\nk=v host:port\n", "all"),
}

# Stand-ins for the programs of SHELL_TEXT_LINES, which print what they get
STUBS = {
    "show.sh": '#!/bin/sh\necho "[show.sh $*] [CGO_ENABLED=$CGO_ENABLED]"\n',
    "docker": '#!/bin/sh\nfor a in "$@"; do echo "[$a]"; done\n',
}


def _run_with_stubs(gnu_make, cwd, text, goal):
    """Run goal of text with make and the makefile's own SHELL, with STUBS in
    the directory and on PATH; return (returncode, stdout)."""
    make, _true, _sh, _major = gnu_make
    for name, script in STUBS.items():
        (cwd / name).write_bytes(script.encode("utf-8"))
        (cwd / name).chmod(0o755)
    (cwd / "input.mk").write_bytes(text.encode("utf-8"))
    proc = subprocess.run(
        [make, "-r", "-R", "-s", "-f", "input.mk", goal],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=60,
        env={"PATH": f"{cwd}{os.pathsep}{os.defpath}", "LC_ALL": "C"},
    )
    return proc.returncode, proc.stdout


class TestRecipeTextThatLooksLikeMakefileSyntax:
    """No spacing rule rewrites a recipe continuation line, with or without
    the recipe prefix."""

    @pytest.mark.parametrize("name", sorted(SHELL_TEXT_LINES))
    def test_default_output_is_the_input(self, name):
        text, _goal = SHELL_TEXT_LINES[name]
        assert _format(text, DEFAULT).content == text

    @pytest.mark.parametrize("config", sorted(MORE_CONFIGS))
    @pytest.mark.parametrize("name", sorted(SHELL_TEXT_LINES))
    def test_column_1_lines_stay(self, name, config):
        text, _goal = SHELL_TEXT_LINES[name]
        formatted = _format(text, MORE_CONFIGS[config]).content.splitlines()
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if index and lines[index - 1].endswith(BS) and line[:1] not in " \t":
                assert line in formatted
        _assert_stable(text, MORE_CONFIGS[config])

    @pytest.mark.parametrize("config", ["auto-group", "auto-ungroup"])
    @pytest.mark.parametrize("name", sorted(SHELL_TEXT_LINES))
    def test_phony_names_only_the_goal(self, name, config):
        text, goal = SHELL_TEXT_LINES[name]
        formatted = _format(text, MORE_CONFIGS[config]).content
        declared = [
            word
            for line in formatted.splitlines()
            if line.startswith(".PHONY:")
            for word in line[len(".PHONY:") :].split()
        ]
        assert set(declared) <= {goal}

    @pytest.mark.parametrize("config", ["default", "align", "auto-group"])
    @pytest.mark.parametrize("name", sorted(SHELL_TEXT_LINES))
    def test_make_runs_the_same(self, gnu_make, tmp_path, name, config):
        text, goal = SHELL_TEXT_LINES[name]
        if "bash" in text and shutil.which("bash") is None:
            pytest.skip("bash is not installed")
        formatted = _format(text, MORE_CONFIGS[config]).content
        dry_run = _make(gnu_make, tmp_path, text, ["-n", goal])
        assert dry_run[0] == 0
        assert _make(gnu_make, tmp_path, formatted, ["-n", goal]) == dry_run
        run = _run_with_stubs(gnu_make, tmp_path, text, goal)
        assert _run_with_stubs(gnu_make, tmp_path, formatted, goal) == run

    @pytest.mark.parametrize("config", sorted(INDENT_CONFIGS))
    def test_semicolon_recipe_in_a_conditional(self, gnu_make, tmp_path, config):
        """ConditionalRule leaves the recipe text after the ';' as it is."""
        text = "ifdef V\nifdef W\nall: ; @echo a \\\n  k=v\nendif\nendif\n"
        formatted = _format(text, MORE_CONFIGS[config]).content
        assert "\n  k=v\n" in formatted
        settings = ("V=1", "W=1")
        dry_run = _make(gnu_make, tmp_path, text, ["-n", *settings, "all"])
        assert _make(gnu_make, tmp_path, formatted, ["-n", *settings, "all"]) == (
            dry_run
        )


# Backslashes next to ';', '&' and '|', which end a word anyway: the blocks are
# normalized as on v1.5.0 (output of v1.5.0, goal)
OPERATOR_BOUNDARIES = {
    # CPython's config Makefile
    "exit_semicolon": (
        "E = yes\nstamp:\n\t@if [ $(E) = yes ]; then \\\n"
        '\t\techo "Error: not found" ;\\\n\t\texit 0;\\\n\tfi\n',
        "E = yes\nstamp:\n\t@if [ $(E) = yes ]; then \\\n"
        '\t\techo "Error: not found" ; \\\n\t\texit 0; \\\n\tfi\n',
        "stamp",
    ),
    "pipe": (
        "deps:\n\t@printf 'a\\n\\nb\\n' \\\n\t  | grep -v '^$$' |\\\n\tsed -e 's|$$|:|'\n",
        "deps:\n\t@printf 'a\\n\\nb\\n' \\\n\t  | grep -v '^$$' | \\\n\t  sed -e 's|$$|:|'\n",
        "deps",
    ),
    "pipe_first": (
        "all:\n\t@printf '%s\\n' a\\\n    | cat\n",
        "all:\n\t@printf '%s\\n' a\\\n\t| cat\n",
        "all",
    ),
    "and_first": (
        "all:\n\t@printf a\\\n    && printf b\n",
        "all:\n\t@printf a\\\n\t&& printf b\n",
        "all",
    ),
}


class TestOperatorBoundaries:
    """A POSIX shell ends a word at ';', '&' and '|', so the blanks next to
    them do not matter."""

    @pytest.mark.parametrize("name", sorted(OPERATOR_BOUNDARIES))
    def test_output_of_v150(self, name):
        text, expected, _goal = OPERATOR_BOUNDARIES[name]
        assert _format(text, DEFAULT).content == expected
        _assert_stable(text, DEFAULT)

    @pytest.mark.parametrize("name", sorted(OPERATOR_BOUNDARIES))
    def test_shell_runs_the_same(self, gnu_make, tmp_path, name):
        text, expected, goal = OPERATOR_BOUNDARIES[name]
        _assert_shell_gets_the_same_words(gnu_make, tmp_path, text, expected, goal)

    @pytest.mark.parametrize(
        ("block", "sensitive"),
        [
            ([T + "@true " + BS, T + "exit 1;" + BS, T + "fi"], False),
            ([T + "@a " + BS, T + "b |" + BS, T + "sed x"], False),
            ([T + "@a" + BS, T + "| cat"], False),
            # The two '&' would make one '&&'.
            ([T + "@true " + BS, T + "a &&" + BS, T + "&& b"], True),
            # '2>' and '&1' would make '2>&1'.
            ([T + "@true " + BS, T + "a 2>" + BS, T + "&1"], True),
            # An escaped ';' is part of a word.
            ([T + "@true " + BS, T + "-exec rm {} \\;" + BS, T + "-print"], True),
        ],
    )
    def test_recipe_block_is_whitespace_sensitive(self, block, sensitive):
        result = line_utils.ShellUtils.recipe_block_is_whitespace_sensitive(block)
        assert result is sensitive


class TestShellWithArguments:
    """make runs the first word of SHELL as the shell and passes the words
    after it as arguments (GNU 3170-3174): bash with '-o pipefail' reads
    blanks as sh does, so the recipes are formatted as on v1.5.0."""

    RECIPES = {
        "pipefail": "SHELL = /bin/bash -o pipefail\nall:\n\t@echo a \\\n\t  b \\\n\tc\n",
        "argcomplete": "SHELL=/bin/bash -eo pipefail\nall:\n\t@echo a \\\n\t  b \\\n\tc\n",
    }
    FORMATTED = {
        "pipefail": "SHELL = /bin/bash -o pipefail\nall:\n\t@echo a \\\n\t  b \\\n"
        "\t  c\n",
        "argcomplete": "SHELL = /bin/bash -eo pipefail\nall:\n\t@echo a \\\n"
        "\t  b \\\n\t  c\n",
    }

    @pytest.mark.parametrize("name", sorted(RECIPES))
    def test_output_of_v150(self, name):
        assert _format(self.RECIPES[name], DEFAULT).content == self.FORMATTED[name]
        _assert_stable(self.RECIPES[name], DEFAULT)

    @pytest.mark.parametrize("name", sorted(RECIPES))
    def test_bash_runs_the_same(self, gnu_make, tmp_path, name):
        bash = shutil.which("bash")
        if bash is None:
            pytest.skip("bash is not installed")
        text = self.RECIPES[name]
        run = _readings(gnu_make, tmp_path, text, "all", shell=bash)[2]
        assert run == (0, "a b c\n")
        formatted = self.FORMATTED[name]
        assert _readings(gnu_make, tmp_path, formatted, "all", shell=bash)[2] == run


class TestContinuationsOffWithRepairedLines:
    """With normalize_line_continuations = false, the run of lines that
    WhitespaceRule makes continue ends with a line that TabsRule gives a TAB:
    make reads a continuation line's leading whitespace as one space (GNU
    776-781), so the value is that of v1.5.0's output. make rejects the input
    ("missing separator", GNU 11275-11281)."""

    TEXT = "SOURCES = main.c \\  \n    utils.c \\\t\n        parser.c\n"
    PROBE_GOAL = "all: ; @echo [$(SOURCES)]\n"

    def test_output(self):
        formatted = _format(self.TEXT + self.PROBE_GOAL, NO_NORMALIZE).content
        assert formatted.startswith("SOURCES = main.c \\\n    utils.c \\\n\tparser.c\n")
        _assert_stable(self.TEXT + self.PROBE_GOAL, NO_NORMALIZE)

    def test_make_reads_the_value(self, gnu_make, tmp_path):
        text = self.TEXT + self.PROBE_GOAL
        assert _make(gnu_make, tmp_path, text, ["-n", "all"])[0] != 0
        formatted = _format(text, NO_NORMALIZE).content
        run = _make(gnu_make, tmp_path, formatted, ["-s", "all"], gnu_make[2])
        assert run == (0, "[main.c utils.c parser.c]\n")


# Inputs where one run gives the final text: v1.5.0 needed two runs for
# phony_above_rule and, without ContinuationRule, for escaped_backslash and
# rule_below_recipe, and changed what the shell gets in the others (goal, and
# whether make reads the output as it reads the input)
ONE_RUN = {
    # With auto-inserted .PHONY lines, TabsRule reads the rule's continuation
    # line the same with the inserted line above the rule as without it.
    "phony_above_rule": (
        "CFLAGS = -O2\nall: main.o \\\n    util.o\n\t@echo [$@]\nmain.o util.o: ; @:\n",
        "all",
        True,
    ),
    # '\\\\' and the backslash/newline: 'f' joins the escaped backslash.
    "escaped_backslash": (
        "t2: dep ; @echo two$(V) \\\n  echo yes; \\\\\\\nf\t\\\n\t  b\ndep: ; @:\n",
        "t2",
        True,
    ),
    # 'z\' and 'main.o' join; the blanks of the other lines only separate.
    "joined_words": (
        "all: ; @echo util.o  \\\n\t    || z\\\n\tmain.o\\\n\t \tfi  \\\n\t \tdo\n",
        "all",
        True,
    ),
    # '  d \' keeps its spaces below the kept line: make reads it, with the
    # lines that it continues over, as a rule of d and t1 (GNU 1209-1219).
    # v1.5.0 gave it a TAB, which turned the rule into a shell loop of t1's
    # recipe.
    "rule_below_kept_line": (
        "t1: | dep\n\t-@true && $(V)      \\\n        -O2\\ \n  d \\\n"
        "t1: ; @for f in a b; do -O2      \\\n\t  util.o  \\\n\t\tmain.o\ndep: ; @:\n",
        "t1",
        True,
    ),
    # ShellFormattingRule gives 'Y=b\' its TABs; 'c' joins 'b' ('Y=bc'), so it
    # keeps column 1 against the indentation of the block and gets the TAB
    # alone, which RecipeValidationRule gives it below 'Y=b\' on the next run.
    "joined_below_tabbed_line": (
        'V = 1\nt1:\n\t@if [ -n "$(V)" ]; then \\\n  X=a; \\\nY=b\\\n'
        'c; printf \'[%s]\\n\' "$$X" "$$Y"; \\\n\tfi\n',
        "t1",
        True,
    ),
    # The same below 'else\', which 'printf' joins ('elseprintf'), as in a
    # reviewer's fuzz input (vgen, seed 31, case 87)
    "else_joined": (
        "V = 1\nt1:\n\tif [ -n \"$(V)\" ]; then\\\n  printf '[%s]' yes; \\\n"
        "else\\\nprintf '[%s]' no; \\\n \tfi\n",
        "t1",
        False,
    ),
    # Without ContinuationRule, TabsRule gives '  b \' a TAB, below which
    # RecipeValidationRule gives 'c' one on the next run; v1.5.0 needed two
    # runs (the shape of a reviewer's fuzz input, g3, seed 31, case 20).
    "rule_below_recipe": (
        "x:\n\t@echo a\nd \\\nt1: ; @echo $(V) \\\n  b \\\nc\n",
        "t1",
        True,
    ),
}


class TestOneRunMoreShapes:
    """A second run of the formatter changes nothing."""

    @pytest.mark.parametrize(
        ("name", "config"),
        [(name, config) for name in sorted(ONE_RUN) for config in sorted(MORE_CONFIGS)],
    )
    def test_second_run_changes_nothing(self, name, config):
        _assert_stable(ONE_RUN[name][0], MORE_CONFIGS[config])

    @pytest.mark.parametrize(
        "config", ["default", "indent4", "auto-ungroup", "no-normalize"]
    )
    @pytest.mark.parametrize(
        "name", sorted(name for name, case in ONE_RUN.items() if case[2])
    )
    def test_shell_gets_the_same_words(self, gnu_make, tmp_path, name, config):
        text, goal, _same = ONE_RUN[name]
        formatted = _format(text, MORE_CONFIGS[config]).content
        _assert_shell_gets_the_same_words(gnu_make, tmp_path, text, formatted, goal)


# The outputs that the make-backed tests above check, also where no GNU make
# runs (Windows)
OUTPUTS = [
    pytest.param(
        "define BODY\na \\\n    b \\\n  c\nendef\nall: ; @echo [$(BODY)]\n",
        None,
        id="define-body",
    ),
    pytest.param(
        "Y = x \\\n  a  \\\\\\\n  b\nall: ; @echo [$(Y)]\n",
        None,
        id="three-backslashes",
    ),
    pytest.param(
        "X = a \\\n  b\\\\\nY = c\nall: ; @echo [$(X)] [$(Y)]\n",
        None,
        id="even-backslashes",
    ),
    pytest.param(
        ".POSIX:\nY = a\\\n  b\\\n  c   \\\n  d\nall: ; @echo [$(Y)]\n",
        None,
        id="posix",
    ),
    pytest.param(TestShellsThatAreNotKnown.PYTHON_LOOP, None, id="python-loop"),
    pytest.param(TestShellsThatAreNotKnown.PYTHON_CALL, None, id="python-call"),
    pytest.param(TestShellsThatAreNotKnown.ONESHELL_ECHO, None, id="oneshell"),
    pytest.param(
        INLINE_RECIPE, INLINE_RECIPE.replace("all :", "all:", 1), id="inline-recipe"
    ),
    pytest.param(
        SEMICOLON_LATER, SEMICOLON_LATER_FORMATTED, id="semicolon-on-a-later-line"
    ),
    pytest.param(
        ".RECIPEPREFIX = >\nall:\n>@echo a \\\n>b\\\n>c\n"
        '>@echo "x \\\n    y \\\n  z"\n',
        None,
        id="recipe-prefix",
    ),
    pytest.param("all:\n\t@echo no\\\n  space\n", None, id="no-space"),
    pytest.param('all:\n\t@echo "one \\\n  space"\n', None, id="quoted-spaces"),
]


class TestOutputsWithoutMake:
    """The formatter's side of the make-backed tests."""

    @pytest.mark.parametrize(("text", "expected"), OUTPUTS)
    def test_output(self, text, expected):
        assert _format(text, DEFAULT).content == (
            text if expected is None else expected
        )
        _assert_stable(text, DEFAULT)


# Recipes whose recipe prefix is '>' (GNU 5158-5169), with continuation lines
# at column 1 or that start with a TAB, which is no recipe prefix there. make
# removes only the '>' that starts a line after a backslash/newline
# (2917-2925), so a TAB at the start of a continuation line reaches the shell,
# and after a backslash with no blank before it, it splits a word. Each
# makefile comes with the formatter's output, the goal, what make prints, the
# lines that keep column 1 and v1.5.0's output, whose TABs split words. make
# 3.81 has no .RECIPEPREFIX, so these makefiles run with make 4.x only.
RECIPE_PREFIX_CONTINUATIONS = {
    # The example of the manual (GNU 2927-2944), with '>' as the prefix
    "manual": (
        ".RECIPEPREFIX = >\nall:\n>@echo no\\\n\tmore\\\nspace\n",
        None,
        "all",
        "no morespace\n",
        ["space"],
        ".RECIPEPREFIX = >\nall:\n>@echo no\\\n\tmore \\\n\tspace\n",
    ),
    "for_loop": (
        ".RECIPEPREFIX = >\nt2:\n>@true; \\\n    for f in a b; do echo x\\\ny$$f; \\\n"
        "\tdone\n",
        ".RECIPEPREFIX = >\nt2:\n>@true; \\\n\tfor f in a b; do echo x\\\ny$$f; \\\n"
        "\tdone\n",
        "t2",
        "xya\nxyb\n",
        ["y$$f; \\"],
        ".RECIPEPREFIX = >\nt2:\n>@true; \\\n\tfor f in a b; do echo x \\\n"
        "\t\ty$$f; \\\n\tdone\n",
    ),
    "below_a_spaced_line": (
        ".RECIPEPREFIX = >\nt2:\n>@echo a \\\n    echo f\\\nh\n",
        ".RECIPEPREFIX = >\nt2:\n>@echo a \\\n\techo f\\\nh\n",
        "t2",
        "a echo fh\n",
        ["h"],
        ".RECIPEPREFIX = >\nt2:\n>@echo a \\\n\techo f \\\n\th\n",
    ),
    "if_block": (
        '.RECIPEPREFIX = >\nall:\n>@echo start; \\\n    if [ -n "x" ]; then \\\n'
        "    Y=b\\\nc; echo $$Y; \\\n    fi\n",
        '.RECIPEPREFIX = >\nall:\n>@echo start; \\\n\tif [ -n "x" ]; then \\\n'
        "\t\tY=b\\\nc; echo $$Y; \\\n\tfi\n",
        "all",
        "start\nbc\n",
        ["c; echo $$Y; \\"],
        '.RECIPEPREFIX = >\nall:\n>@echo start; \\\n\tif [ -n "x" ]; then \\\n'
        "\t\tY=b \\\n\t\tc; echo $$Y; \\\n\tfi\n",
    ),
    "loop_closed_by_the_prefix": (
        ".RECIPEPREFIX = >\nall:\n>@for i in 1 2; do \\\n    echo $$i\\\n$$i; \\\n"
        ">done\n",
        ".RECIPEPREFIX = >\nall:\n>@for i in 1 2; do \\\n\techo $$i\\\n$$i; \\\n"
        ">done\n",
        "all",
        "11\n22\n",
        ["$$i; \\", ">done"],
        ".RECIPEPREFIX = >\nall:\n>@for i in 1 2; do \\\n\techo $$i \\\n\t$$i; \\\n"
        "\t>done\n",
    ),
    "after_a_semicolon": (
        ".RECIPEPREFIX = >\nall: ; @echo a\\\nb\n",
        None,
        "all",
        "ab\n",
        ["b"],
        ".RECIPEPREFIX = >\nall: ; @echo a\\\n\tb\n",
    ),
}


class TestRecipePrefixContinuationLines:
    """A continuation line of a recipe whose prefix is not the TAB gets no
    TAB, and one run gives the final text (GNU 2917-2925, 5158-5169)."""

    @pytest.mark.parametrize("name", sorted(RECIPE_PREFIX_CONTINUATIONS))
    def test_output(self, name):
        text, expected = RECIPE_PREFIX_CONTINUATIONS[name][:2]
        assert _format(text, DEFAULT).content == (expected or text)

    @pytest.mark.parametrize("config", sorted(MORE_CONFIGS))
    @pytest.mark.parametrize("name", sorted(RECIPE_PREFIX_CONTINUATIONS))
    def test_lines_keep_column_1(self, name, config):
        text, _expected, _goal, _printed, kept, _v150 = RECIPE_PREFIX_CONTINUATIONS[
            name
        ]
        lines = _format(text, MORE_CONFIGS[config]).content.splitlines()
        for line in kept:
            assert line in lines
        _assert_stable(text, MORE_CONFIGS[config])

    @pytest.mark.parametrize("name", sorted(RECIPE_PREFIX_CONTINUATIONS))
    def test_check_mode_reports_no_missing_tab(self, name):
        """make reads the line as part of the recipe line above it, so no
        recipe prefix is missing (GNU 776-781)."""
        text = RECIPE_PREFIX_CONTINUATIONS[name][0]
        for config in (DEFAULT, {"fix_missing_recipe_tabs": False}):
            _lines, errors, warnings = _formatter(**config).format_lines(
                text.splitlines(), True, text
            )
            result = _formatter(**config).format(text)
            messages = errors + warnings + result.errors + result.warnings
            assert not any("Missing required tab" in m for m in messages)

    @pytest.mark.parametrize("name", ["below_a_spaced_line", "if_block"])
    def test_check_after_format(self, tmp_path, monkeypatch, name):
        """'format' and then 'format --check' find nothing to change."""
        text = RECIPE_PREFIX_CONTINUATIONS[name][0]
        (tmp_path / "Makefile").write_bytes(text.encode("utf-8"))
        (tmp_path / "bake.toml").write_bytes(b"")
        monkeypatch.chdir(tmp_path)
        runner = _runner()
        args = ["format", "--config", "bake.toml"]
        assert runner.invoke(app, [*args, "Makefile"]).exit_code == 0
        assert runner.invoke(app, [*args, "--check", "Makefile"]).exit_code == 0

    @pytest.mark.parametrize("config", ["default", "keep", "no-normalize", "indent4"])
    @pytest.mark.parametrize("name", sorted(RECIPE_PREFIX_CONTINUATIONS))
    def test_make_prints_the_same(self, gnu_make_4, tmp_path, name, config):
        text, _expected, goal, printed, _kept, v150 = RECIPE_PREFIX_CONTINUATIONS[name]
        formatted = _format(text, MORE_CONFIGS[config]).content
        assert _readings(gnu_make_4, tmp_path, text, goal)[2] == (0, printed)
        assert _readings(gnu_make_4, tmp_path, formatted, goal)[2] == (0, printed)
        # v1.5.0's TABs reach the shell.
        assert _readings(gnu_make_4, tmp_path, v150, goal)[2] != (0, printed)


# Recipe continuation lines at column 1 that start inside quotes or a
# here-document, with the goal. make removes the TAB that starts a
# continuation line (GNU 2917-2925), but make 3.81 prints it, as part of the
# quoted text, in the command that it echoes and in 'make -n'; v1.5.0 gave the
# lines a TAB.
QUOTED_CONTINUATIONS = {
    "single_quotes_after_semicolon": ("all2: ; @echo 'h \\\nx'\n", "all2"),
    "single_quotes": ("all:\n\t@echo 'a \\\nb'\n", "all"),
    "double_quotes": ('all:\n\techo "a \\\nb"\n', "all"),
    "here_document": ("all:\n\t@cat <<EOF \\\ntext \\\nEOF\n", "all"),
    "kept_line_above": ("X = a \\ \nall2: ; @echo 'h \\\nx'\n", "all2"),
}
# The configurations that change no line of these makefiles
KEEPS_QUOTED_LINES = ["default", "keep", "no-normalize", "no-fix", "indent2", "indent4"]


class TestQuotedContinuationLines:
    """A recipe continuation line that starts inside quotes or a
    here-document gets no TAB, so make prints the same command (GNU
    2946-2969)."""

    @pytest.mark.parametrize("config", KEEPS_QUOTED_LINES)
    @pytest.mark.parametrize("name", sorted(QUOTED_CONTINUATIONS))
    def test_output_is_the_input(self, name, config):
        text = QUOTED_CONTINUATIONS[name][0]
        assert _format(text, MORE_CONFIGS[config]).content == text

    @pytest.mark.parametrize("config", sorted(MORE_CONFIGS))
    @pytest.mark.parametrize("name", sorted(QUOTED_CONTINUATIONS))
    def test_second_run_changes_nothing(self, name, config):
        _assert_stable(QUOTED_CONTINUATIONS[name][0], MORE_CONFIGS[config])

    @pytest.mark.parametrize("name", sorted(QUOTED_CONTINUATIONS))
    def test_check_mode_reports_no_missing_tab(self, name):
        text = QUOTED_CONTINUATIONS[name][0]
        for config in (DEFAULT, {"fix_missing_recipe_tabs": False}):
            _lines, errors, warnings = _formatter(**config).format_lines(
                text.splitlines(), True, text
            )
            result = _formatter(**config).format(text)
            messages = errors + warnings + result.errors + result.warnings
            assert not any("Missing required tab" in m for m in messages)

    @pytest.mark.parametrize("name", sorted(QUOTED_CONTINUATIONS))
    def test_tab_shows_in_make_381(self, gnu_make, tmp_path, name):
        """The TAB that v1.5.0 added: make 4.x removes it from the command
        that it prints and runs; make 3.81 prints it, and runs the same."""
        text, goal = QUOTED_CONTINUATIONS[name]
        lines = text.split("\n")
        tabbed = "\n".join(
            (
                "\t" + line
                if index > 0
                and line
                and line[0] not in " \t"
                and lines[index - 1].endswith("\\")
                and not lines[index - 1].endswith(" \\ ")
                else line
            )
            for index, line in enumerate(lines)
        )
        assert tabbed != text
        before = _readings(gnu_make, tmp_path, text, goal)
        after = _readings(gnu_make, tmp_path, tabbed, goal)
        assert before[1][0] == 0
        assert after[2] == before[2]
        if gnu_make[3] < 4:
            assert after[1] != before[1]
        else:
            assert after[1] == before[1]


# Recipe lines that other rules re-indent, with a continuation line that
# starts inside quotes, the formatter's output, the line that keeps its start,
# and v1.5.0's output. The start of such a line stays, the TAB included: make
# 3.81 prints the TAB as part of the quoted text (GNU 2917-2925, 2946-2969).
QUOTED_LINE_STARTS = {
    # ContinuationRule gives the lines the TAB of the first continuation line.
    "opened_above": (
        'all:\n\t@echo a \\\n"b \\\nc"\n',
        'all:\n\t@echo a \\\n\t"b \\\nc"\n',
        'c"',
        'all:\n\t@echo a \\\n\t"b \\\n\tc"\n',
    ),
    # ContinuationRule gives the lines the indentation of 'all: ...'.
    "tab_after_a_semicolon": (
        "d \\\nall: ; @echo 'h \\\n\tx'\n",
        "d \\\nall: ; @echo 'h \\\n\tx'\n",
        "\tx'",
        "d \\\nall: ; @echo 'h \\\nx'\n",
    ),
}


class TestQuotedLineStarts:
    """No rule changes the start of a recipe continuation line that begins
    inside quotes (see ShellUtils.keep_shell_text)."""

    @pytest.mark.parametrize("name", sorted(QUOTED_LINE_STARTS))
    def test_output(self, name):
        text, expected, _line, _v150 = QUOTED_LINE_STARTS[name]
        assert _format(text, DEFAULT).content == expected

    @pytest.mark.parametrize("config", sorted(MORE_CONFIGS))
    @pytest.mark.parametrize("name", sorted(QUOTED_LINE_STARTS))
    def test_line_keeps_its_start(self, name, config):
        text, _expected, line, _v150 = QUOTED_LINE_STARTS[name]
        assert line in _format(text, MORE_CONFIGS[config]).content.splitlines()
        _assert_stable(text, MORE_CONFIGS[config])

    @pytest.mark.parametrize("name", sorted(QUOTED_LINE_STARTS))
    def test_make_prints_the_quoted_text(self, gnu_make, tmp_path, name):
        """make prints the quoted line as in the input; make 3.81 prints
        v1.5.0's line otherwise."""
        text, expected, line, v150 = QUOTED_LINE_STARTS[name]
        goal = "all"
        printed = _make(gnu_make, tmp_path, text, ["-n", goal])
        formatted = _make(gnu_make, tmp_path, expected, ["-n", goal])
        old = _make(gnu_make, tmp_path, v150, ["-n", goal])
        assert printed[0] == formatted[0] == old[0] == 0
        quoted = printed[1].splitlines()[-1]
        assert formatted[1].splitlines()[-1] == quoted
        if gnu_make[3] < 4:
            assert old[1].splitlines()[-1] != quoted
        _assert_shell_gets_the_same_words(gnu_make, tmp_path, text, expected, goal)


# A line that ends with backslashes that continue nothing, an even run or a
# backslash that whitespace follows (GNU 762-769), above an indented
# directive or reference that make reads as makefile syntax (1209-1219). The
# grouped '.PHONY' line goes after the indented line, as in v1.5.0: right
# above it, '.PHONY:' would give it a rule context (2878-2884), in which
# TabsRule gives it a TAB on the next run, which makes it a recipe line of
# .PHONY.
PHONY_ABOVE_INDENTED_LINES = {
    "sinclude": "SEP = \\\\\n  sinclude foo.mk\nall:\n\t@echo [$(Y)]\n",
    "header": "# header\nSEP = \\\\\n  sinclude foo.mk\nall:\n\t@echo [$(Y)]\n",
    "call": "F = $(eval Y := f$(1))\nR =\nSEP = \\\\\n  $(call F,x)\n"
    "all:\n\t@echo [$(Y)]\n",
    "kept_line": "F = $(eval Y := f$(1))\nR =\nX = a \\ \n  $(call F,x)\n"
    "all:\n\t@echo [$(Y)]\n",
    "reference": "SEP = \\\\\n  ${R}\nall:\n\t@echo [$(Y)]\n",
}
PHONY_CONFIGS = {
    "auto-group": AUTO_GROUP_AFTER,
    "keep-auto-group": {**AUTO_GROUP_AFTER, **KEEP},
    "keep-no-normalize-auto": {
        **KEEP,
        **NO_NORMALIZE,
        "auto_insert_phony_declarations": True,
    },
}


class TestPhonyBelowIndentedLines:
    """Inserted '.PHONY' lines leave an indented directive or reference makefile
    syntax, and a second run changes nothing."""

    @pytest.mark.parametrize("config", sorted(PHONY_CONFIGS))
    @pytest.mark.parametrize("name", sorted(PHONY_ABOVE_INDENTED_LINES))
    def test_second_run_changes_nothing(self, name, config):
        text = PHONY_ABOVE_INDENTED_LINES[name]
        formatted = _format(text, PHONY_CONFIGS[config]).content
        indented = next(line for line in text.splitlines() if line.startswith("  "))
        assert indented in formatted.splitlines()
        assert ".PHONY: all" in formatted
        _assert_stable(text, PHONY_CONFIGS[config])

    @pytest.mark.parametrize("name", sorted(PHONY_ABOVE_INDENTED_LINES))
    def test_make_reads_the_same(self, gnu_make, tmp_path, name):
        text = PHONY_ABOVE_INDENTED_LINES[name]
        (tmp_path / "foo.mk").write_bytes(b"Y = 1\n")
        formatted = _format(text, AUTO_GROUP_AFTER).content
        twice = _format(formatted, AUTO_GROUP_AFTER).content
        expected = _readings(gnu_make, tmp_path, text, "all")
        assert expected[2][0] == 0
        assert expected[2][1] in ("[1]\n", "[fx]\n", "[]\n")
        for output in (formatted, twice):
            actual = _readings(gnu_make, tmp_path, output, "all")
            assert actual[0] == expected[0]
            assert actual[2] == expected[2]

    def test_insertion_point(self):
        parser = line_utils.MakefileParser
        assert (
            parser.find_phony_insertion_point(
                ["SEP = \\\\", "  sinclude foo.mk", "all:", T + "@echo"]
            )
            == 2
        )
        assert (
            parser.find_phony_insertion_point(
                ["SEP = \\\\", T + "include foo.mk", "all:", T + "@echo"]
            )
            == 2
        )
        # A line at column 1 after the even run starts a new statement.
        assert (
            parser.find_phony_insertion_point(["SEP := \\\\", "all:", T + "@echo"]) == 1
        )

    def test_fixture_with_kept_whitespace(self):
        """In tests/fixtures/complex, '    utils.c \\<TAB>' follows such a line
        (GNU 762-769); with remove_trailing_whitespace off, one run gives the
        final text."""
        path = os.path.join(os.path.dirname(__file__), "fixtures", "complex")
        with open(os.path.join(path, "input.mk"), encoding="utf-8") as handle:
            text = handle.read()
        _assert_stable(text, PHONY_CONFIGS["keep-auto-group"])

    def test_check_after_format(self, tmp_path, monkeypatch):
        """'format' and then 'format --check' find nothing to change."""
        text = PHONY_ABOVE_INDENTED_LINES["sinclude"]
        (tmp_path / "Makefile").write_bytes(text.encode("utf-8"))
        (tmp_path / "bake.toml").write_bytes(
            b"[formatter]\nauto_insert_phony_declarations = true\n"
            b"group_phony_declarations = true\nphony_at_top = true\n"
        )
        monkeypatch.chdir(tmp_path)
        runner = _runner()
        args = ["format", "--config", "bake.toml"]
        assert runner.invoke(app, [*args, "Makefile"]).exit_code == 0
        assert runner.invoke(app, [*args, "--check", "Makefile"]).exit_code == 0


# A comment that continues over lines with leading spaces, with and without a
# kept line above it, as in a reviewer's input that only make 4.x reads
# ('.RECIPEPREFIX', GNU 5158-5169), and the output, which v1.5.0 gave on its
# second run (for "comment") or gave by joining the kept line to the comment
# ("below_a_kept_line"). make reads the whole logical line as a comment (GNU
# 730-733, 776-781): TabsRule gives the first continuation line a TAB, and
# ContinuationRule gives the others the same, so one run gives the final text.
CONTINUED_COMMENTS = {
    "comment": (
        "W = a\n# c note: x    \\\n $(V)\t\\\n  b -lfoo\nall: ; @echo [$(W)]\n",
        "W = a\n# c note: x    \\\n\t$(V) \\\n\tb -lfoo\nall: ; @echo [$(W)]\n",
    ),
    "below_a_kept_line": (
        "W = a\n# c: \\  \n# c note: x    \\\n $(V)\t\\\n  b -lfoo\n"
        "all: ; @echo [$(W)]\n",
        "W = a\n# c: \\  \n# c note: x    \\\n\t$(V) \\\n\tb -lfoo\n"
        "all: ; @echo [$(W)]\n",
    ),
    "recipe_prefix": (
        ".RECIPEPREFIX = >\nW = a\n# c: \\  \n# c note: x    \\\n $(V)\t\\\n"
        "  b -lfoo\nall:\n>@echo [$(W)]\n",
        ".RECIPEPREFIX = >\nW = a\n# c: \\  \n# c note: x    \\\n\t$(V) \\\n"
        "\tb -lfoo\nall:\n>@echo [$(W)]\n",
    ),
}


class TestContinuedComments:
    """One run gives the final text of a comment's continuation lines."""

    @pytest.mark.parametrize("name", sorted(CONTINUED_COMMENTS))
    def test_output(self, name):
        text, expected = CONTINUED_COMMENTS[name]
        assert _format(text, DEFAULT).content == expected

    @pytest.mark.parametrize("config", sorted(MORE_CONFIGS))
    @pytest.mark.parametrize("name", sorted(CONTINUED_COMMENTS))
    def test_second_run_changes_nothing(self, name, config):
        _assert_stable(CONTINUED_COMMENTS[name][0], MORE_CONFIGS[config])

    @pytest.mark.parametrize("name", ["comment", "below_a_kept_line"])
    def test_make_reads_the_same(self, gnu_make, tmp_path, name):
        text, expected = CONTINUED_COMMENTS[name]
        _assert_make_reads_the_same(gnu_make, tmp_path, text, expected, "all")

    def test_make_4_reads_the_same(self, gnu_make_4, tmp_path):
        text, expected = CONTINUED_COMMENTS["recipe_prefix"]
        _assert_make_reads_the_same(gnu_make_4, tmp_path, text, expected, "all")


# A header comment that continues over lines of text (GNU 730-733), with the
# goal, and v1.5.0's output, which make rejects: v1.5.0 put the grouped
# '.PHONY' line and a blank line right below the comment, which ended the
# comment there and left its other lines as recipe lines without a rule
# ("recipe commences before first target", 11292-11297). The declaration now
# goes below the comment's last line.
PHONY_BELOW_CONTINUED_COMMENTS = {
    "two_lines": (
        "# c \\\n  x \\\n\ty\nall: ; @echo [$@]\n",
        "all",
        "# c \\\n.PHONY: all\n\n\tx \\\n\ty\nall: ; @echo [$@]\n",
    ),
    "usage": (
        "# Usage: make all \\\n  more text\nall:\n\t@echo [$@]\n",
        "all",
        "# Usage: make all \\\n.PHONY: all\n\n\tmore text\nall:\n\t@echo [$@]\n",
    ),
}


class TestPhonyBelowContinuedComments:
    """The grouped '.PHONY' line does not end a comment that continues over
    lines of text."""

    @pytest.mark.parametrize("config", sorted(PHONY_CONFIGS))
    @pytest.mark.parametrize("name", sorted(PHONY_BELOW_CONTINUED_COMMENTS))
    def test_second_run_changes_nothing(self, name, config):
        text = PHONY_BELOW_CONTINUED_COMMENTS[name][0]
        lines = _format(text, PHONY_CONFIGS[config]).content.splitlines()
        assert lines[0] == text.splitlines()[0]
        assert not lines[1].startswith(".PHONY")
        _assert_stable(text, PHONY_CONFIGS[config])

    @pytest.mark.parametrize("name", sorted(PHONY_BELOW_CONTINUED_COMMENTS))
    def test_make_reads_the_same(self, gnu_make, tmp_path, name):
        text, goal, v150 = PHONY_BELOW_CONTINUED_COMMENTS[name]
        formatted = _format(text, AUTO_GROUP_AFTER).content
        expected = _readings(gnu_make, tmp_path, text, goal)
        assert expected[2] == (0, "[all]\n")
        assert _readings(gnu_make, tmp_path, formatted, goal)[2] == expected[2]
        assert _readings(gnu_make, tmp_path, v150, goal)[2][0] != 0


# A continued rule at column 1 right after an assignment, with its recipe: the
# grouped '.PHONY' line goes above the rule's first line. Between the rule and
# its recipe it would take the recipe over (GNU 2878-2884), which v1.5.0 did
# for the first case, and the branch also for the second, where a comment on
# the rule line continues over the next line (GNU 730-733).
PHONY_ABOVE_CONTINUED_RULES = {
    "continued_rule": (
        "CFLAGS = -O2\nall: main.o " + BS + "\n    util.o\n\t@echo [$@]\n"
        "main.o util.o: ; @:\n",
        "CFLAGS = -O2\n.PHONY: all\n\nall: main.o " + BS + "\n    util.o\n"
        "\t@echo [$@]\nmain.o util.o: ; @:\n",
        ["all"],
    ),
    "comment_continued_over_a_line": (
        "X ?= -lx " + BS * 2 + "\na.x b.x: %.x: %.y # n: " + BS + "\n\talpha $(V)\n"
        "\t@echo [$@]\n%.y: ; @:\n",
        "X ?= -lx " + BS * 2 + "\n.PHONY: b.x\n\na.x b.x: %.x: %.y # n: " + BS + "\n"
        "\talpha $(V)\n\t@echo [$@]\n%.y: ; @:\n",
        ["a.x", "b.x"],
    ),
}


class TestPhonyAboveContinuedRules:
    @pytest.mark.parametrize("name", sorted(PHONY_ABOVE_CONTINUED_RULES))
    def test_output(self, name):
        text, expected, _goals = PHONY_ABOVE_CONTINUED_RULES[name]
        assert _format(text, AUTO_GROUP_AFTER).content == expected
        _assert_stable(text, AUTO_GROUP_AFTER)

    @pytest.mark.parametrize("config", sorted(PHONY_CONFIGS))
    @pytest.mark.parametrize("name", sorted(PHONY_ABOVE_CONTINUED_RULES))
    def test_make_runs_the_same_commands(self, gnu_make, tmp_path, name, config):
        text, _expected, goals = PHONY_ABOVE_CONTINUED_RULES[name]
        formatted = _format(text, PHONY_CONFIGS[config]).content
        expected = _make(gnu_make, tmp_path, text, ["-n", *goals])
        assert expected[0] == 0
        assert _make(gnu_make, tmp_path, formatted, ["-n", *goals]) == expected
        _assert_stable(text, PHONY_CONFIGS[config])


# Inputs from the reviewers' fuzz runs that only make 4.x reads (.RECIPEPREFIX,
# GNU 5158-5169), which needed two runs, with a goal
FUZZ_RECIPE_PREFIX = {
    # gnu2, seed 71, case 181
    "gnu2_71_181": (
        ".RECIPEPREFIX = >\nt2:\n>  @echo a\t\\\n    e;\t\\\n    && f\\\nh\n"
        "> -@printf '%s\\n' $$HOME\nt1:\n> @echo $$HOME\n>echo x y\nt2:\n"
        '> @echo a  \\\n>    b\n>@true && "q  r"\nt3:\n> @echo a\nifdef A\n'
        "t3 :  ; @echo x y \\\n>    b\t\\\n        e;\\\t\n> -@printf '%s\\n' a\n"
        " \nendif\nshow: ; @echo ''\n",
        "t2",
    ),
    # gnu1, seed 41, case 192
    "gnu1_41_192": (
        ".RECIPEPREFIX = >\n.POSIX:\n \t \nb.x: dep ; @echo one   \n"
        ">@echo one \t\\\n  b\\\nf   \\\nc d\na.x b.x: %.x: %.y\n>@echo [$@]\n"
        "define D1\n  \t@echo d\\\n    -lfoo $(V) \\\\\\\n  alpha\t\\\n \tx.o $(V)\n"
        "endef\nt2: TV = a   \\\n -lfoo alpha\n%.y: ; @:\nshow: ; @echo ''\n",
        "b.x",
    ),
}


class TestRecipePrefixFuzzInputs:
    """One run gives the final text, and the shell gets the same words."""

    @pytest.mark.parametrize("config", sorted(MORE_CONFIGS))
    @pytest.mark.parametrize("name", sorted(FUZZ_RECIPE_PREFIX))
    def test_second_run_changes_nothing(self, name, config):
        _assert_stable(FUZZ_RECIPE_PREFIX[name][0], MORE_CONFIGS[config])

    @pytest.mark.parametrize("config", ["default", "keep", "no-normalize"])
    @pytest.mark.parametrize("name", sorted(FUZZ_RECIPE_PREFIX))
    def test_shell_gets_the_same_words(self, gnu_make_4, tmp_path, name, config):
        text, goal = FUZZ_RECIPE_PREFIX[name]
        formatted = _format(text, MORE_CONFIGS[config]).content
        _assert_shell_gets_the_same_words(gnu_make_4, tmp_path, text, formatted, goal)


# A line that starts with spaces and continues onto a rule or an assignment,
# with the goal, what make prints and v1.5.0's output. make reads the logical
# line as that rule or assignment (GNU 1209-1219, 776-781), as it reads
# 'echo hello world: done' on one line, which keeps its spaces too. v1.5.0
# gave the first line a TAB, which made it a recipe line of the rule above.
CONTINUED_DEFINITIONS = {
    "assignment": (
        "t2:\n\t@echo a\n  X \\\n  = 1\nall: ; @echo [$(X)]\n",
        "all",
        "[1]\n",
        "t2:\n\t@echo a\n\tX \\\n\t= 1\nall: ; @echo [$(X)]\n",
    ),
    "rule": (
        "all:\n    echo hello \\\n      world: done\ndone: ; @echo [$@]\n",
        "world",
        "[done]\n",
        "all:\n\techo hello \\\n      world: done\ndone: ; @echo [$@]\n",
    ),
}


class TestContinuedDefinitionKeepsItsSpaces:
    """TabsRule reads the logical line that a line with leading spaces starts
    (GNU 1209-1219)."""

    @pytest.mark.parametrize("config", sorted(MORE_CONFIGS))
    @pytest.mark.parametrize("name", sorted(CONTINUED_DEFINITIONS))
    def test_first_line_keeps_its_spaces(self, name, config):
        text = CONTINUED_DEFINITIONS[name][0]
        first = next(line for line in text.splitlines() if line.startswith("  "))
        assert first in _format(text, MORE_CONFIGS[config]).content.splitlines()
        _assert_stable(text, MORE_CONFIGS[config])

    @pytest.mark.parametrize("config", ["default", "keep", "no-normalize", "no-fix"])
    @pytest.mark.parametrize("name", sorted(CONTINUED_DEFINITIONS))
    def test_make_reads_the_same(self, gnu_make, tmp_path, name, config):
        text, goal, printed, v150 = CONTINUED_DEFINITIONS[name]
        formatted = _format(text, MORE_CONFIGS[config]).content
        assert _readings(gnu_make, tmp_path, text, goal)[2] == (0, printed)
        assert _readings(gnu_make, tmp_path, formatted, goal)[2] == (0, printed)
        assert _readings(gnu_make, tmp_path, v150, goal)[2] != (0, printed)


# Recipe lines indented with spaces, as broken makefiles often have them, whose
# logical line make reads as no rule and no assignment: it removes the comment
# before it looks for a ':' or '=' (GNU 1212-1227), and a ':' after the ';' of
# the line separates nothing (1480-1503). make stops at them ("missing
# separator", 11275-11281), and the formatter gives the first line its TAB,
# with v1.5.0's output, and the goal.
SPACE_INDENTED_RECIPES = {
    "semicolon_before_colon": (
        "deploy:\n    cd dist; \\\n        scp app host:/srv\n",
        "deploy:\n\tcd dist; \\\n        scp app host:/srv\n",
        "deploy",
    ),
    "colon_in_comment": (
        "build:\n    gcc -c main.c \\\n        -o main.o # note: fast\n",
        "build:\n\tgcc -c main.c \\\n\t-o main.o # note: fast\n",
        "build",
    ),
    "if_then": (
        "check:\n    if [ -f x ]; then \\\n        cp a b:c; fi\n",
        "check:\n\tif [ -f x ]; then \\\n\t\tcp a b:c; fi\n",
        "check",
    ),
    "url_in_comment": (
        "dl:\n    curl -LO $(URL) \\\n        -o out.tgz  # https://example.com\n",
        "dl:\n\tcurl -LO $(URL) \\\n\t-o out.tgz  # https://example.com\n",
        "dl",
    ),
    "note_in_comment": (
        "app:\n    echo cc -o app main.c \\\n        util.c  # note: links both\n",
        "app:\n\techo cc -o app main.c \\\n        util.c  # note: links both\n",
        "app",
    ),
    "todo_in_comment": (
        "app:\n    echo cc -o app main.c \\\n        util.c  # TODO: fix\n",
        "app:\n\techo cc -o app main.c \\\n        util.c  # TODO: fix\n",
        "app",
    ),
    # A static pattern rule needs a '%' in its target pattern (GNU 2598-2605).
    "two_colons": (
        "all:\n    scp a \\\n        u@h:/a/b v@w:/c\n",
        "all:\n\tscp a \\\n        u@h:/a/b v@w:/c\n",
        "all",
    ),
}

# Lines with leading spaces that start a continued assignment, followed by a
# recipe line: an assignment ends the rule context (GNU 2881-2884), so make
# rejects the recipe line after it ("recipe commences before first target",
# 11292-11297). With the TAB, as in v1.5.0, both stay recipe lines of the rule
# above and make accepts the output. A conditional directive in between counts
# as a recipe line that may follow: which lines make reads after it depends on
# its condition (GNU 5399-5421). With indent_nested_conditionals, TabsRule
# reads the lines as make reads them and keeps the assignment, as v1.5.0 did.
ASSIGNMENTS_BEFORE_RECIPE_LINES = {
    "assignment_before_a_conditional": (
        "t:\n\t@echo a\n  X \\\n  = 1\nifdef NOPE\nendif\n\t@echo b\n",
        "t:\n\t@echo a\n\tX \\\n\t= 1\nifdef NOPE\nendif\n\t@echo b\n",
        "t",
    ),
    "assignment_before_a_recipe_line": (
        "t:\n\t@echo a\n  X \\\n  = 1\n\t@echo b\n",
        "t:\n\t@echo a\n\tX \\\n\t= 1\n\t@echo b\n",
        "t",
    ),
    "target_variable_before_a_recipe_line": (
        "t:\n\t@echo a\n  t \\\n  : X = 1\n\t@echo b\n",
        "t:\n\t@echo a\n\tt \\\n\t: X = 1\n\t@echo b\n",
        "t",
    ),
    "assignment_before_an_indented_line": (
        "t:\n\t@echo a\n  X \\\n  = 1\n    echo b\n",
        "t:\n\t@echo a\n\tX \\\n\t= 1\n\techo b\n",
        "t",
    ),
}
NOT_INDENT_CONFIGS = sorted(set(MORE_CONFIGS) - set(INDENT_CONFIGS))


class TestSpaceIndentedRecipesRepaired:
    """A line with leading spaces that starts a continued line that make
    rejects gets its TAB, as in v1.5.0, so that make accepts the output."""

    @pytest.mark.parametrize("name", sorted(SPACE_INDENTED_RECIPES))
    def test_output_is_that_of_v150(self, name):
        text, v150, _goal = SPACE_INDENTED_RECIPES[name]
        assert _format(text, DEFAULT).content == v150
        _assert_stable(text, DEFAULT)

    @pytest.mark.parametrize("config", sorted(MORE_CONFIGS))
    @pytest.mark.parametrize("name", sorted(SPACE_INDENTED_RECIPES))
    def test_first_line_gets_its_tab(self, name, config):
        text, v150, _goal = SPACE_INDENTED_RECIPES[name]
        first = next(
            line for line in v150.splitlines()[1:] if not line.startswith("\t@")
        )
        assert first in _format(text, MORE_CONFIGS[config]).content.splitlines()
        _assert_stable(text, MORE_CONFIGS[config])

    @pytest.mark.parametrize("config", ["default", "keep", "no-normalize", "indent4"])
    @pytest.mark.parametrize("name", sorted(SPACE_INDENTED_RECIPES))
    def test_make_accepts_the_output(self, gnu_make, tmp_path, name, config):
        text, _v150, goal = SPACE_INDENTED_RECIPES[name]
        formatted = _format(text, MORE_CONFIGS[config]).content
        assert _make(gnu_make, tmp_path, text, ["-n", goal])[0] != 0
        returncode, commands = _make(gnu_make, tmp_path, formatted, ["-n", goal])
        assert returncode == 0
        assert commands

    def test_recipe_runs_as_written(self, gnu_make, tmp_path):
        text, _v150, goal = SPACE_INDENTED_RECIPES["note_in_comment"]
        formatted = _format(text, DEFAULT).content
        run = _make(gnu_make, tmp_path, formatted, ["-s", goal], gnu_make[2])
        assert run == (0, "cc -o app main.c util.c\n")

    @pytest.mark.parametrize("name", sorted(SPACE_INDENTED_RECIPES))
    def test_check_reports_the_change(self, tmp_path, monkeypatch, name):
        text, _v150, _goal = SPACE_INDENTED_RECIPES[name]
        (tmp_path / "Makefile").write_bytes(text.encode("utf-8"))
        (tmp_path / "bake.toml").write_bytes(b"")
        monkeypatch.chdir(tmp_path)
        result = _runner().invoke(
            app, ["format", "--config", "bake.toml", "--check", "Makefile"]
        )
        assert result.exit_code == 1


class TestAssignmentsBeforeRecipeLinesRepaired:
    """A continued assignment that a recipe line follows gets the TAB, as in
    v1.5.0, so that make accepts the output."""

    @pytest.mark.parametrize("name", sorted(ASSIGNMENTS_BEFORE_RECIPE_LINES))
    def test_output_is_that_of_v150(self, name):
        text, v150, _goal = ASSIGNMENTS_BEFORE_RECIPE_LINES[name]
        assert _format(text, DEFAULT).content == v150
        _assert_stable(text, DEFAULT)

    @pytest.mark.parametrize("config", NOT_INDENT_CONFIGS)
    @pytest.mark.parametrize("name", sorted(ASSIGNMENTS_BEFORE_RECIPE_LINES))
    def test_first_line_gets_its_tab(self, name, config):
        text, v150, _goal = ASSIGNMENTS_BEFORE_RECIPE_LINES[name]
        first = v150.splitlines()[2]
        assert first in _format(text, MORE_CONFIGS[config]).content.splitlines()
        _assert_stable(text, MORE_CONFIGS[config])

    @pytest.mark.parametrize("config", ["default", "keep", "no-normalize"])
    @pytest.mark.parametrize("name", sorted(ASSIGNMENTS_BEFORE_RECIPE_LINES))
    def test_make_accepts_the_output(self, gnu_make, tmp_path, name, config):
        text, _v150, goal = ASSIGNMENTS_BEFORE_RECIPE_LINES[name]
        formatted = _format(text, MORE_CONFIGS[config]).content
        assert _make(gnu_make, tmp_path, text, ["-n", goal])[0] != 0
        assert _make(gnu_make, tmp_path, formatted, ["-n", goal])[0] == 0


# Logical lines that start with spaces, and whether make reads a rule or an
# assignment in them that both makes accept (see
# rule_context.accepted_definition): its kind, or None
ACCEPTED_DEFINITIONS = {
    "cd dist; scp app host:/srv": None,
    "gcc -c main.c -o main.o # note: fast": None,
    "if [ -f x ]; then cp a b:c; fi": None,
    "echo cc -o app main.c util.c  # note: links both": None,
    "scp a u@h:/a/b v@w:/c": None,
    "perl -e 'use File::Spec;' -e 'x'": None,
    "echo 'a: b' c": None,
    "out.o a::=b cc": None,
    "a b &: c": None,
    "a %.o: b": None,
    "define := x": None,
    "X ::= 1": None,
    "$(V) = 1": None,
    "t: != x": None,
    "d t3: ; echo util.o x;": rule_context.RULE,
    "echo hello world: done": rule_context.RULE,
    "rsync -av dist/ user@host:/srv/www/": rule_context.RULE,
    "a.o : %.o: %.c": rule_context.RULE,
    "X = 1": rule_context.ASSIGNMENT,
    "override X += 2 3": rule_context.ASSIGNMENT,
    "w1 w2: X = 1": rule_context.TARGET_VARIABLE,
}


class TestAcceptedDefinitions:
    """rule_context.accepted_definition takes a logical line for a rule or an
    assignment only where both makes accept it as one."""

    @pytest.mark.parametrize("text", sorted(ACCEPTED_DEFINITIONS))
    def test_kind(self, text):
        assert rule_context.accepted_definition(text) == ACCEPTED_DEFINITIONS[text]

    @pytest.mark.parametrize("text", sorted(ACCEPTED_DEFINITIONS))
    def test_make_accepts_the_definitions(self, gnu_make, tmp_path, text):
        """Written over two lines below a rule, a definition that it takes is
        one that make accepts; make 3.81 has no '&:' and '::=', which it
        takes for none."""
        words = text.split(" ")
        cut = max(1, len(words) // 2)
        makefile = (
            "all:\n\t@echo a\n  "
            + " ".join(words[:cut])
            + " \\\n    "
            + " ".join(words[cut:])
            + "\n"
        )
        returncode = _make(gnu_make, tmp_path, makefile, ["-n", "all"])[0]
        if ACCEPTED_DEFINITIONS[text] is not None:
            assert returncode == 0


# Lines with leading spaces that start a continued rule or assignment that make
# accepts, followed by no recipe line: make reads the rule or the assignment
# (GNU 1209-1219), so the lines keep their spaces, with the goal and what make
# prints, which v1.5.0's TAB changed.
KEPT_DEFINITIONS = {
    "rule_with_a_host": (
        "deploy:\n    rsync -av dist/ \\\n        user@host:www\nwww: ; @echo [$@]\n",
        "user@host",
        "[www]\n",
        "deploy:\n\trsync -av dist/ \\\n        user@host:www\nwww: ; @echo [$@]\n",
    ),
    "static_pattern_rule": (
        "all: a.o\n  a.o \\\n  : %.o: %.c\n\t@echo [$@ $<]\n%.c: ; @:\n",
        "all",
        "[a.o a.c]\n",
        "all: a.o\n\ta.o \\\n\t: %.o: %.c\n\t@echo [$@ $<]\n%.c: ; @:\n",
    ),
    # Makefile syntax with leading whitespace after the assignment is no
    # recipe line (see rule_context.recipe_line_follows).
    "assignment_before_an_indented_assignment": (
        "t:\n\t@echo a\n  X \\\n  = 1\n  Y = 2\nall: ; @echo [$(X)][$(Y)]\n",
        "all",
        "[1][2]\n",
        "t:\n\t@echo a\n\tX \\\n\t= 1\n  Y = 2\nall: ; @echo [$(X)][$(Y)]\n",
    ),
    # The indented line continues the comment (GNU 730-733).
    "assignment_before_a_continued_comment": (
        "t:\n\t@echo a\n  X \\\n  = 1\n# c \\\n  more\nall: ; @echo [$(X)]\n",
        "all",
        "[1]\n",
        "t:\n\t@echo a\n\tX \\\n\t= 1\n# c \\\n\tmore\nall: ; @echo [$(X)]\n",
    ),
}


class TestKeptDefinitions:
    """A continued rule or assignment that make accepts keeps its spaces."""

    @pytest.mark.parametrize("config", sorted(MORE_CONFIGS))
    @pytest.mark.parametrize("name", sorted(KEPT_DEFINITIONS))
    def test_first_line_keeps_its_spaces(self, name, config):
        text = KEPT_DEFINITIONS[name][0]
        first = next(line for line in text.splitlines() if line.startswith("  "))
        assert first in _format(text, MORE_CONFIGS[config]).content.splitlines()
        _assert_stable(text, MORE_CONFIGS[config])

    @pytest.mark.parametrize("name", sorted(KEPT_DEFINITIONS))
    def test_make_reads_the_same(self, gnu_make, tmp_path, name):
        text, goal, printed, v150 = KEPT_DEFINITIONS[name]
        formatted = _format(text, DEFAULT).content
        assert _readings(gnu_make, tmp_path, text, goal)[2] == (0, printed)
        assert _readings(gnu_make, tmp_path, formatted, goal)[2] == (0, printed)
        assert _readings(gnu_make, tmp_path, v150, goal)[2] != (0, printed)


# Define bodies whose lines look like rules or assignments, with the goal that
# prints the value. A body is the value of a variable (GNU 4795-4799), so no
# spacing rule changes it; v1.5.0's PatternSpacingRule and TargetSpacingRule
# put a space after a ':' there, which changed the value, and so the commands
# of an eval'd template (8.10, lines 6378-6386).
DEFINE_BODIES = {
    "pattern_on_a_space_led_line": (
        "define BODY\na \\\n\tb \\\n  %.o:%.c\nendef\nall: ; @: $(info [$(BODY)])\n",
        "all",
    ),
    "eval_template": (
        "define R\n$(1):\n\t@printf '[%s]' a \\\n\tb \\\n    %.o:%.c\nendef\n"
        "$(eval $(call R,e2))\nall: e2\n",
        "all",
    ),
    "rule_template": (
        "define T\n$(1):$(2)\n\t@echo [$$@ $$<]\nendef\n$(eval $(call T,a,b))\n"
        "b: ; @:\nall: a\n",
        "all",
    ),
    "key_value_text": (
        "define BODY\nkey:value\nother:  thing\nendef\nall: ; @: $(info [$(BODY)])\n",
        "all",
    ),
    "colons_in_text": (
        "define BODY\nhttp%3A:x\na.o: %.o:%.c\nendef\nall: ; @: $(info [$(BODY)])\n",
        "all",
    ),
}


class TestDefineBodiesKeptBySpacingRules:
    """No spacing rule changes a line of a define body."""

    @pytest.mark.parametrize("config", SAME_LINES_CONFIGS + ["space-before"])
    @pytest.mark.parametrize("name", sorted(DEFINE_BODIES))
    def test_body_stays_as_written(self, name, config):
        text = DEFINE_BODIES[name][0]
        formatted = _format(text, MORE_CONFIGS[config]).content
        body = text.split("endef")[0]
        assert formatted.split("endef")[0] == body
        _assert_stable(text, MORE_CONFIGS[config])

    @pytest.mark.parametrize("name", sorted(DEFINE_BODIES))
    def test_make_reads_the_same(self, gnu_make, tmp_path, name):
        text, goal = DEFINE_BODIES[name]
        formatted = _format(text, DEFAULT).content
        _assert_make_reads_the_same(gnu_make, tmp_path, text, formatted, goal)


# A define body whose continuation line looks like a rule: v1.5.0's PhonyRule
# took 'host' for a target and put '.PHONY: host' into the body or above it
DEFINE_BODY_CONTINUATIONS = {
    "first_continuation_line": "define V\na \\\n  host:port\nendef\n"
    "all: ; @echo '[$(V)]'\n",
    "later_continuation_line": "define V\na \\\n\tb \\\n  host:port \\\n  x=y\n"
    "endef\nall: ; @echo '[$(V)]'\n",
}


class TestPhonyLeavesDefineBodyContinuations:
    """A continuation line of a define body names no target: it is part of
    the value (GNU 4795-4799), and of the logical line above it (762-769)."""

    @pytest.mark.parametrize("config", ["auto-group", "auto-ungroup"])
    @pytest.mark.parametrize("name", sorted(DEFINE_BODY_CONTINUATIONS))
    def test_no_phony_line(self, name, config):
        text = DEFINE_BODY_CONTINUATIONS[name]
        formatted = _format(text, MORE_CONFIGS[config]).content
        assert "host" not in "".join(
            line for line in formatted.splitlines() if line.startswith(".PHONY")
        )
        assert formatted.split("endef")[0] == text.split("endef")[0]
        _assert_stable(text, MORE_CONFIGS[config])

    @pytest.mark.parametrize("name", sorted(DEFINE_BODY_CONTINUATIONS))
    def test_check_mode_names_no_target(self, name):
        text = DEFINE_BODY_CONTINUATIONS[name]
        warnings = _formatter().format_lines(text.splitlines(), True, text)[2]
        assert not any("host" in warning for warning in warnings)

    @pytest.mark.parametrize("name", sorted(DEFINE_BODY_CONTINUATIONS))
    def test_make_reads_the_same(self, gnu_make, tmp_path, name):
        text = DEFINE_BODY_CONTINUATIONS[name]
        formatted = _format(text, MORE_CONFIGS["auto-ungroup"]).content
        assert (
            _readings(gnu_make, tmp_path, formatted, "all")[2]
            == _readings(gnu_make, tmp_path, text, "all")[2]
        )


# Recipes with a shell comment or bash's $'...' quotes, whose later
# continuation lines start inside quotes, with the shell that runs them. A '#'
# that starts a word starts a comment, in which quotes are text, and which ends
# at the newline: the backslash before it is comment text (make passes it to
# the shell, GNU 744-746; sh, bash, dash, ksh and zsh all run the line after
# 'echo a # c \'). In $'...' a backslash quotes the next character, so "\'"
# ends nothing. v1.5.0 re-indented the quoted lines, which changed what the
# command prints.
SHELL_QUOTE_TRACKING = {
    "apostrophe_in_a_comment": (
        "all:\n\t@printf '[%s]' a; # it's " + BS + "\n\tprintf '[%s]' 'b " + BS + "\n"
        "\t    c " + BS + "\n\t  d'\n",
        "sh",
    ),
    "escaped_quote_in_ansi_c_quotes": (
        "SHELL = /bin/bash\nall:\n\t@printf '[%s]' $$'a" + BS + "'b " + BS + "\n"
        "\t    c " + BS + "\n\t  d'\n",
        "bash",
    ),
    "quotes_after_ansi_c_quotes": (
        "all:\n\t@printf '[%s]' $$'it" + BS + "'s' 'x " + BS + "\n    y'\n",
        "bash",
    ),
}


def _shell(name):
    """Return the path of a shell, or skip."""
    path = shutil.which(name)
    if path is None:
        pytest.skip(f"{name} is not installed")
    return path


class TestShellCommentsAndAnsiCQuotes:
    """Quote tracking knows shell comments and $'...' (see
    line_utils._line_break_states)."""

    @pytest.mark.parametrize("config", SAME_LINES_CONFIGS)
    @pytest.mark.parametrize("name", sorted(SHELL_QUOTE_TRACKING))
    def test_output_is_the_input(self, name, config):
        text = SHELL_QUOTE_TRACKING[name][0]
        assert _format(text, MORE_CONFIGS[config]).content == text

    @pytest.mark.parametrize("name", sorted(SHELL_QUOTE_TRACKING))
    def test_command_prints_the_same(self, gnu_make, tmp_path, name):
        text, shell = SHELL_QUOTE_TRACKING[name]
        formatted = _format(text, DEFAULT).content
        path = _shell(shell)
        expected = _readings(gnu_make, tmp_path, text, "all", shell=path)
        assert expected[2][0] == 0
        assert _readings(gnu_make, tmp_path, formatted, "all", shell=path) == expected

    def test_line_after_a_comment_is_re_indented_as_before(self):
        """The apostrophe in the comment opens no quote, so the next line
        gets the TAB that v1.5.0 gave it."""
        text = "all:\n\t@echo a; # it's fine " + BS + "\n    echo b\n"
        expected = "all:\n\t@echo a; # it's fine " + BS + "\n\techo b\n"
        assert _format(text, DEFAULT).content == expected
        _assert_stable(text, DEFAULT)

    @pytest.mark.parametrize(
        ("block", "starts_in_quotes"),
        [
            (["\t@echo a # it's " + BS, "\tb"], False),
            (["\t@echo a#b's " + BS, "\tc'"], True),
            (["\t@printf $$'a" + BS + "'b " + BS, "\t c'"], True),
            (["\t@printf $$$$'a" + BS + "'b " + BS, "\t c'"], False),
            (["\t@echo \"# it's " + BS, '\t c"'], True),
        ],
    )
    def test_last_line_starts_in_quotes(self, block, starts_in_quotes):
        utils = line_utils.ShellUtils
        assert utils.last_line_starts_in_quotes(block) is starts_in_quotes

    def test_backslash_in_a_comment_joins_nothing(self):
        utils = line_utils.ShellUtils
        assert not utils.recipe_block_is_whitespace_sensitive(
            ["\t@echo a # c" + BS, "\techo b"]
        )
        assert utils.recipe_block_is_whitespace_sensitive(["\t@echo a" + BS, "\tb"])


# A recipe line whose first continuation line begins inside quotes at column
# 1: it keeps its start (make 3.81 prints a TAB there, GNU 2917-2925), and the
# line below it, outside the quotes, takes the TAB that v1.5.0 gave it, not the
# start of the quoted line.
QUOTED_FIRST_LINE = 'all:\n\t@echo "a \\\nb  c" \\\n    d\n'
QUOTED_FIRST_LINE_FORMATTED = 'all:\n\t@echo "a \\\nb  c" \\\n\td\n'


class TestLineBelowAQuotedColumnOneLine:
    def test_output(self):
        assert _format(QUOTED_FIRST_LINE, DEFAULT).content == (
            QUOTED_FIRST_LINE_FORMATTED
        )
        _assert_stable(QUOTED_FIRST_LINE, DEFAULT)

    def test_shell_gets_the_same_words(self, gnu_make, tmp_path):
        _assert_shell_gets_the_same_words(
            gnu_make, tmp_path, QUOTED_FIRST_LINE, QUOTED_FIRST_LINE_FORMATTED, "all"
        )


# Output that is the same as v1.5.0's, or differs in blanks between words only,
# with the goal: GNU-neutral, make and the shell read the same.
NEUTRAL_SHAPES = {
    # The backslashes of 'a\\' are text: the line continues nothing (GNU
    # 762-769), so the block below it starts at 'printf', whose first
    # continuation line gives the indentation, where v1.5.0 took that of the
    # 'printf' line ('\t    c' / '\t    d').
    "even_backslash_run": (
        "all:\n\t@printf '[%s]' a\\\\\n\t    printf '[%s]' b \\\n\t      c \\\n\t  d\n",
        "all:\n\t@printf '[%s]' a\\\\\n\t    printf '[%s]' b \\\n\t      c \\\n"
        "\t      d\n",
    ),
    # '<<' that starts no here-document keeps the block as written, where
    # v1.5.0 gave the line a TAB: the shell reads the same words either way.
    "shift_in_arithmetic": (
        "all:\n\t@echo $$((1<<2)) \\\n    foo\n",
        "all:\n\t@echo $$((1<<2)) \\\n    foo\n",
    ),
    "here_string": (
        'all:\n\t@cat <<< "x" \\\n    ; echo y\n',
        'all:\n\t@cat <<< "x" \\\n    ; echo y\n',
    ),
}


class TestNeutralShapes:
    @pytest.mark.parametrize("name", sorted(NEUTRAL_SHAPES))
    def test_output(self, name):
        text, expected = NEUTRAL_SHAPES[name]
        assert _format(text, DEFAULT).content == expected
        _assert_stable(text, DEFAULT)

    @pytest.mark.parametrize("name", sorted(NEUTRAL_SHAPES))
    def test_shell_gets_the_same_words(self, gnu_make, tmp_path, name):
        text, expected = NEUTRAL_SHAPES[name]
        shell = _shell("bash") if name == "here_string" else None
        _assert_shell_gets_the_same_words(
            gnu_make, tmp_path, text, expected, "all", shell=shell
        )


class TestComputedRecipePrefix:
    """A .RECIPEPREFIX that '$(eval ...)' sets is not seen (GNU 6378-6386):
    the output stays that of v1.5.0, a known gap."""

    def test_output_is_that_of_v150(self):
        text = "$(eval .RECIPEPREFIX = >)\nall: ; @echo a\\\nb\n"
        expected = "$(eval .RECIPEPREFIX = >)\nall: ; @echo a\\\n\tb\n"
        assert _format(text, DEFAULT).content == expected


class TestWarningOnTheCommandLine:
    """'format' prints warnings with --check or --verbose only, as it does for
    every warning; it still keeps the line."""

    @pytest.mark.parametrize(
        ("options", "printed"),
        [([], False), (["--check"], True), (["--verbose"], True)],
        ids=["format", "check", "verbose"],
    )
    def test_printed(self, tmp_path, monkeypatch, options, printed):
        text = "all:\n\techo a\nX = a \\ \nY = b\n"
        (tmp_path / "Makefile").write_bytes(text.encode("utf-8"))
        (tmp_path / "bake.toml").write_bytes(b"[formatter]\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COLUMNS", "200")
        result = _runner().invoke(
            app, ["format", "--config", "bake.toml", *options, "Makefile"]
        )
        assert result.exit_code == 0
        assert (f"Makefile:3: Warning: {WARNING}" in result.stdout) is printed
        assert (tmp_path / "Makefile").read_bytes() == text.encode("utf-8")

    def test_line_number_without_the_tab_fix(self):
        """Format mode numbers the warning by file line with
        fix_missing_recipe_tabs off too."""
        text = "all:\necho a\necho b\necho c\nX = a \\ \nY = b\n"
        result = _format(text, {"fix_missing_recipe_tabs": False})
        assert f"5: Warning: {WARNING}" in result.warnings


# A backslash that whitespace follows and that stays, and the line below it,
# which then stands alone (GNU 762-769), with the formatter's output and the
# goal. Where that line is text in a rule context, it is a recipe line that
# lacks its TAB and gets it, also below a line with '=' or an even run of
# backslashes; where make's recipe prefix is no TAB (5158-5169), a TAB makes
# no recipe line of it, so the whitespace after the backslash goes, as in
# v1.5.0. A line that is makefile syntax keeps its spaces.
LINES_BELOW_KEPT_BACKSLASHES = {
    "recipe_line_with_an_equals_sign": (
        "all:\n\tFOO=1 echo run " + BS + " \n    --flag\n",
        "all:\n\tFOO=1 echo run " + BS + " \n\t--flag\n",
        "all",
    ),
    "even_run_with_an_equals_sign": (
        "all:\n\t@echo a=b" + BS * 2 + "\n    echo c\n",
        "all:\n\t@echo a=b" + BS * 2 + "\n\techo c\n",
        "all",
    ),
    "even_run_of_an_inline_recipe": (
        "all: ; @echo a=b" + BS * 2 + "\n    echo c\n",
        "all: ; @echo a=b" + BS * 2 + "\n\techo c\n",
        "all",
    ),
}


class TestLinesBelowKeptBackslashes:
    @pytest.mark.parametrize("name", sorted(LINES_BELOW_KEPT_BACKSLASHES))
    def test_output(self, name):
        text, expected, _goal = LINES_BELOW_KEPT_BACKSLASHES[name]
        assert _format(text, DEFAULT).content == expected
        _assert_stable(text, DEFAULT)

    @pytest.mark.parametrize("config", ["default", "no-normalize", "indent4"])
    @pytest.mark.parametrize("name", sorted(LINES_BELOW_KEPT_BACKSLASHES))
    def test_make_accepts_the_output(self, gnu_make, tmp_path, name, config):
        text, _expected, goal = LINES_BELOW_KEPT_BACKSLASHES[name]
        formatted = _format(text, MORE_CONFIGS[config]).content
        assert _make(gnu_make, tmp_path, text, ["-n", goal])[0] != 0
        assert _make(gnu_make, tmp_path, formatted, ["-n", goal])[0] == 0

    def test_kept_line_is_reported(self):
        text = LINES_BELOW_KEPT_BACKSLASHES["recipe_line_with_an_equals_sign"][0]
        assert _format(text, DEFAULT).warnings == [f"2: Warning: {WARNING}"]

    def test_text_below_a_non_tab_prefix_is_repaired(self, gnu_make_4, tmp_path):
        """make 4.x reads '  b c' below a '>' recipe line as makefile text,
        with or without a TAB, so the backslash continues the line, as in
        v1.5.0."""
        text = ".RECIPEPREFIX = >\nall:\n>@echo a " + BS + " \n  b c\n"
        expected = ".RECIPEPREFIX = >\nall:\n>@echo a " + BS + "\n\tb c\n"
        assert rule_context.dangling_backslash_repairs(text.splitlines(), {}) == {2}
        assert _format(text, DEFAULT).content == expected
        assert _make(gnu_make_4, tmp_path, text, ["-n", "all"])[0] != 0
        assert _make(gnu_make_4, tmp_path, expected, ["-n", "all"])[0] == 0

    def test_makefile_syntax_below_keeps_its_spaces(self, gnu_make, tmp_path):
        text = "X = a " + BS + " \n  sinclude foo.mk\nall: ; @echo [$(X)]\n"
        assert _format(text, DEFAULT).content == text
        (tmp_path / "foo.mk").write_bytes(b"Y = 1\n")
        _assert_make_reads_the_same(gnu_make, tmp_path, text, text, "all")


# A line below an assignment whose last backslash continues nothing, after
# an even run of backslashes (GNU 762-769): make reads the line on its own,
# and the assignment ended the rule context (2881-2884), so a TAB would make
# it a recipe line that make rejects ("recipe commences before first target",
# 11292-11297). It keeps its spaces, as in v1.5.0, which took the even run for
# a continuation. make reads a line of '\;' as nothing and rejects '-lfoo'
# with or without the TAB.
LINES_BELOW_AN_ASSIGNMENT = {
    "escaped_semicolon": "SRC += a" + BS * 2 + "\n    " + BS + ";\n"
    "all: ; @echo '[$(SRC)]'\n",
    "target_variable": "all: X = a" + BS * 2 + "\n    " + BS + ";\n"
    "all: ; @echo '[$(X)]'\n",
    "text": "SRC += a" + BS * 2 + "\n    -lfoo\nall: ; @echo '[$(SRC)]'\n",
}


class TestLinesBelowAnAssignmentThatContinuesNothing:
    @pytest.mark.parametrize("config", SAME_LINES_CONFIGS)
    @pytest.mark.parametrize("name", sorted(LINES_BELOW_AN_ASSIGNMENT))
    def test_output_is_the_input(self, name, config):
        text = LINES_BELOW_AN_ASSIGNMENT[name]
        assert _format(text, MORE_CONFIGS[config]).content == text

    @pytest.mark.parametrize("name", ["escaped_semicolon", "target_variable"])
    def test_make_reads_the_same(self, gnu_make, tmp_path, name):
        text = LINES_BELOW_AN_ASSIGNMENT[name]
        formatted = _format(text, DEFAULT).content
        _assert_make_reads_the_same(gnu_make, tmp_path, text, formatted, "all")


# Rule lines without targets: a line whose first word starts with an escaped
# ';', such as the '\;' of 'find ... -exec rm {} \;' on a line of its own.
# make 3.81 and 4.4.1 accept it, define nothing with it and end the rule
# context there, as after an assignment (a ';' that is not escaped starts a
# recipe without a rule, GNU 11292-11297). Such a line keeps its spaces where
# no recipe line may follow it (see rule_context.recipe_line_follows), also
# right below a backslash that continues nothing (GNU 762-769), where a TAB
# would make it a recipe line; a backslash that whitespace follows stays above
# it.
SEMI = BS + ";"
LINES_WITHOUT_TARGETS = {
    "after_a_recipe_line": "pre:\n\t@echo pre\n    " + SEMI + "\n",
    "below_an_even_run_of_a_recipe_line": (
        "pre:\n\t@echo pre\n\tX=1 echo x " + BS * 4 + "\n  " + SEMI * 2 + "\n"
    ),
    "below_an_even_run": "pre:\n\t@echo pre " + BS * 2 + "\n  " + SEMI + "\n",
    "below_a_kept_comment_line": (
        "pre:\n\t@echo pre\n# note: x=" + BS + " \n    " + SEMI + "\n"
    ),
    "below_a_kept_recipe_line": (
        "pre:\n\t@printf '[%s]' a " + BS + " \n        " + SEMI + "\n"
    ),
    "below_a_kept_assignment": (
        "X = a " + BS + " \n    " + SEMI + "\npre: ; @echo '[$(X)]'\n"
    ),
    # Makefile syntax with leading whitespace is no recipe line.
    "before_an_indented_assignment": (
        "pre:\n\t@echo pre\n    " + SEMI + "\n  X = 1\nall: ; @echo '[$(X)]'\n"
    ),
    "before_an_override_line": (
        "pre:\n\t@echo pre\n    " + SEMI + "\noverride X = c\nall: ; @:\n"
    ),
}

# The same lines before a recipe line, which make rejects after them, also
# past a conditional directive: they get the TAB, as in v1.5.0, and both
# lines are recipe lines of the rule.
LINES_WITHOUT_TARGETS_BEFORE_A_RECIPE_LINE = {
    "after_a_recipe_line": (
        "pre:\n\t@echo pre\n    " + SEMI + "\n\t@echo after\n",
        "pre:\n\t@echo pre\n\t" + SEMI + "\n\t@echo after\n",
    ),
    "before_a_conditional": (
        "pre:\n\t@echo pre\n    " + SEMI + "\nifdef NOPE\nendif\n\t@echo after\n",
        "pre:\n\t@echo pre\n\t" + SEMI + "\nifdef NOPE\nendif\n\t@echo after\n",
    ),
    "below_an_even_run": (
        "pre:\n\t@printf '[%s]' a " + BS * 2 + "\n  " + SEMI * 2 + "\n\t@echo after\n",
        "pre:\n\t@printf '[%s]' a " + BS * 2 + "\n\t" + SEMI * 2 + "\n\t@echo after\n",
    ),
}


class TestRuleLinesWithoutTargets:
    @pytest.mark.parametrize("config", SAME_LINES_CONFIGS)
    @pytest.mark.parametrize("name", sorted(LINES_WITHOUT_TARGETS))
    def test_output_is_the_input(self, name, config):
        text = LINES_WITHOUT_TARGETS[name]
        assert _format(text, MORE_CONFIGS[config]).content == text

    @pytest.mark.parametrize("name", sorted(LINES_WITHOUT_TARGETS))
    def test_a_tab_changes_what_make_reads(self, gnu_make, tmp_path, name):
        text = LINES_WITHOUT_TARGETS[name]
        lines = text.split("\n")
        index = next(
            i for i, line in enumerate(lines) if line.lstrip().startswith(SEMI)
        )
        lines[index] = "\t" + lines[index].lstrip()
        expected = _readings(gnu_make, tmp_path, text, "pre")
        assert expected[0][0] == 0, "make rejected the input"
        assert _readings(gnu_make, tmp_path, "\n".join(lines), "pre") != expected

    @pytest.mark.parametrize("name", sorted(LINES_WITHOUT_TARGETS_BEFORE_A_RECIPE_LINE))
    def test_before_a_recipe_line(self, gnu_make, tmp_path, name):
        text, expected = LINES_WITHOUT_TARGETS_BEFORE_A_RECIPE_LINE[name]
        assert _format(text, DEFAULT).content == expected
        _assert_stable(text, DEFAULT)
        assert _make(gnu_make, tmp_path, text, ["-n", "pre"])[0] != 0
        assert _make(gnu_make, tmp_path, expected, ["-n", "pre"])[0] == 0

    @pytest.mark.parametrize(
        "line", ["override X = c", "-include $(NONE)", "  include $(NONE)"]
    )
    def test_before_a_line_that_keeps_the_381_rule_context(
        self, gnu_make, tmp_path, line
    ):
        """make 3.81 keeps the rule context after an 'override' line or an
        'include' directive, so a recipe line may follow past it: the line
        gets the TAB, as in v1.5.0, and make 3.81 accepts the output. make 4.x
        ends the rule context there and rejects the input and the output
        alike."""
        text = "pre:\n\t@echo pre\n    " + SEMI + "\n" + line + "\n\t@echo after\n"
        expected = text.replace("    " + SEMI, "\t" + SEMI)
        assert _format(text, DEFAULT).content == expected
        assert _make(gnu_make, tmp_path, text, ["-n", "pre"])[0] != 0
        accepted = _make(gnu_make, tmp_path, expected, ["-n", "pre"])[0] == 0
        assert accepted is (gnu_make[3] < 4)

    @pytest.mark.parametrize(
        ("line", "targetless"),
        [
            (SEMI, True),
            (SEMI * 2, True),
            (SEMI + " " + SEMI, True),
            (SEMI + "x", True),
            (SEMI + "  # c", True),
            ("x" + SEMI, False),
            (BS * 2 + ";", False),
            (";", False),
            ("-lfoo", False),
        ],
    )
    def test_targetless_rule_line(self, gnu_make, tmp_path, line, targetless):
        """rule_context.targetless_rule_line agrees with make: the line is
        accepted, adds no command, and a recipe line after it is rejected."""
        assert rule_context.targetless_rule_line(line) is targetless
        text = "pre:\n\t@echo pre\n    " + line + "\n"
        code, dry_run = _make(gnu_make, tmp_path, text, ["-n", "pre"])
        assert (code == 0 and dry_run == "echo pre\n") is targetless
        after = _make(gnu_make, tmp_path, text + "\t@echo after\n", ["-n", "pre"])
        assert after[0] != 0


class TestTextBelowAKeptAssignmentLine:
    """Text with a reference below an assignment whose backslash whitespace
    follows: dangling_backslash_repairs keeps that backslash, since the
    reference may expand to a rule (GNU 1231-1236), and TabsRule gives the
    text its TAB. No rule context reaches a recipe line after an assignment
    (2881-2884), so WhitespaceRule then makes the backslash continue the
    line, as in v1.5.0, and make reads the assignment over the text."""

    TEXT = (
        "V = 1\nX += -lm" + BS + " \n  b " + BS + "\n    $(V)\nall: ; @echo '[$(X)]'\n"
    )

    def test_one_run(self):
        _assert_stable(self.TEXT, DEFAULT)

    def test_make_accepts_the_output(self, gnu_make, tmp_path):
        formatted = _format(self.TEXT, DEFAULT).content
        assert _make(gnu_make, tmp_path, self.TEXT, ["-n", "all"])[0] != 0
        shell = gnu_make[2]
        assert _make(gnu_make, tmp_path, formatted, ["-s", "all"], shell) == (
            0,
            "[-lm b 1]\n",
        )


# A rule whose first line starts with spaces, which TabsRule keeps, and the
# continuation line of its inline recipe at column 1: the rule is the line's
# context (GNU 1499-1503), so it gets the TAB that make removes (2917-2925) in
# one run, also where PhonyRule puts a '.PHONY' line above the rule.
CONTINUED_RULE_RECIPE = "# c\t" + BS + "\n\t\tmore: x\n  X1 " + BS + "\n"
CONTINUED_RULE_RECIPE += "  e1: ; @echo e " + BS + "\nx\n# c\t" + BS + "\nmore: x\n"


# The same lines where the first line starts an assignment: the line at column
# 1 is part of the value (GNU 776-781) and stays as it is, wherever the
# assignment stands.
CONTINUED_ASSIGNMENT_VALUE = CONTINUED_RULE_RECIPE.replace("  X1 ", "  X1 = a ")

CONTINUED_LINE_CONFIGS = {
    "default": DEFAULT,
    "no-normalize": NO_NORMALIZE,
    "no-normalize-auto": {**NO_NORMALIZE, "auto_insert_phony_declarations": True},
    "no-normalize-ungroup": {
        **NO_NORMALIZE,
        "auto_insert_phony_declarations": True,
        "group_phony_declarations": False,
    },
}


class TestContinuedRuleRecipeLine:
    @pytest.mark.parametrize("config", sorted(CONTINUED_LINE_CONFIGS))
    def test_one_run(self, config):
        formatted = _format(CONTINUED_RULE_RECIPE, CONTINUED_LINE_CONFIGS[config])
        assert "\tx" in formatted.content.splitlines()
        _assert_stable(CONTINUED_RULE_RECIPE, CONTINUED_LINE_CONFIGS[config])

    @pytest.mark.parametrize(
        "config", ["no-normalize", "no-normalize-auto", "no-normalize-ungroup"]
    )
    def test_assignment_value_stays(self, config):
        formatted = _format(CONTINUED_ASSIGNMENT_VALUE, CONTINUED_LINE_CONFIGS[config])
        assert "x" in formatted.content.splitlines()
        _assert_stable(CONTINUED_ASSIGNMENT_VALUE, CONTINUED_LINE_CONFIGS[config])

    def test_make_reads_the_same(self, gnu_make, tmp_path):
        formatted = _format(CONTINUED_RULE_RECIPE, DEFAULT).content
        _assert_shell_gets_the_same_words(
            gnu_make, tmp_path, CONTINUED_RULE_RECIPE, formatted, "e1"
        )


# Continuation lines of an assignment and of a comment that look like rules:
# they continue the logical line above them (GNU 762-769, 730-733), so they
# name no target, and v1.5.0's '.PHONY: e3' or '.PHONY: more' named one that
# make does not have (inside the value or the comment, it changed them).
NON_RULE_CONTINUATIONS = {
    "assignment": "X = a " + BS + "\n  e3: ; @echo e\nall: ; @echo [$(X)]\n",
    "comment": "# c " + BS + "\nmore: x\nall: ; @echo [$(X)]\n",
}


class TestPhonyLeavesNonRuleContinuations:
    @pytest.mark.parametrize("config", ["auto-group", "auto-ungroup"])
    @pytest.mark.parametrize("name", sorted(NON_RULE_CONTINUATIONS))
    def test_no_phony_line(self, name, config):
        text = NON_RULE_CONTINUATIONS[name]
        formatted = _format(text, MORE_CONFIGS[config]).content
        phony = [line for line in formatted.splitlines() if line.startswith(".PHONY")]
        assert not any(word in " ".join(phony) for word in ("e3", "more"))
        _assert_stable(text, MORE_CONFIGS[config])

    @pytest.mark.parametrize("name", sorted(NON_RULE_CONTINUATIONS))
    def test_make_reads_the_same(self, gnu_make, tmp_path, name):
        text = NON_RULE_CONTINUATIONS[name]
        formatted = _format(text, MORE_CONFIGS["auto-ungroup"]).content
        _assert_make_reads_the_same(gnu_make, tmp_path, text, formatted, "all")
