"""Tests for special target and suffix rule validation that follows GNU make.

SpecialTargetValidationRule and SuffixValidationRule report only what GNU make
reads: every special target of the GNU make 4.4.1 manual is known, special
targets may be repeated, assignments to special variables are no rules, and
every message carries the number of the line it is about. SuffixValidationRule
only removes errors from the ones it gave before this change: a suffix rule
keeps an error only where the rule gave it before and make's suffix list,
which starts from the default list, does not hold the suffix. Line numbers in
docstrings refer to the GNU make 4.4.1 manual.
"""

import os
import re
import shutil
import subprocess
from collections import Counter
from typing import NamedTuple

import pytest
from typer.testing import CliRunner

from mbake.cli import app
from mbake.config import Config, FormatterConfig
from mbake.constants.makefile_targets import DEFAULT_SUFFIXES
from mbake.core.formatter import MakefileFormatter
from mbake.core.rules.special_target_validation import SpecialTargetValidationRule
from mbake.core.rules.suffix_validation import SuffixValidationRule
from mbake.plugins.base import FormatResult, FormatterPlugin
from mbake.utils.line_utils import split_makefile_lines

# make runs with a minimal environment so that no inherited variable (such as
# MAKEFLAGS) changes what it reads.
_MAKE_ENV = {"PATH": os.defpath, "LC_ALL": "C"}

GNU = {"_global": {"gnu_error_format": True}}
TRADITIONAL = {"_global": {"gnu_error_format": False}}

# The special targets of section 4.9 (lines 2229-2429) and .WAIT (5.4.1,
# lines 3351-3352 and 3376-3378).
SPECIAL_TARGETS = [
    ".PHONY",
    ".SUFFIXES",
    ".DEFAULT",
    ".PRECIOUS",
    ".INTERMEDIATE",
    ".NOTINTERMEDIATE",
    ".SECONDARY",
    ".SECONDEXPANSION",
    ".DELETE_ON_ERROR",
    ".IGNORE",
    ".LOW_RESOLUTION_TIME",
    ".SILENT",
    ".EXPORT_ALL_VARIABLES",
    ".NOTPARALLEL",
    ".ONESHELL",
    ".POSIX",
    ".WAIT",
]

# The default suffix list of the manual (10.2, lines 7545-7549).
MANUAL_DEFAULT_SUFFIXES = [
    ".out",
    ".a",
    ".ln",
    ".o",
    ".c",
    ".cc",
    ".C",
    ".cpp",
    ".p",
    ".f",
    ".F",
    ".m",
    ".r",
    ".y",
    ".l",
    ".ym",
    ".lm",
    ".s",
    ".S",
    ".mod",
    ".sym",
    ".def",
    ".h",
    ".info",
    ".dvi",
    ".tex",
    ".texinfo",
    ".texi",
    ".txinfo",
    ".w",
    ".ch",
    ".web",
    ".sh",
    ".elc",
    ".el",
]

# The recipe line that tells that make ran a suffix rule of the tests
SUFFIX_RULE_RAN = "echo SUFFIX-RULE"

# A suffix rule of the tests, and a define body that declares its suffixes
_SUFFIX_RULE = ".x.o:\n\t@echo SUFFIX-RULE\n"
_SETUP = "define SETUP\n.SUFFIXES: .x .o\nendef\n"

# The suffix rule '.x.o' in each form that make reads as a rule: alone at the
# start of its line, with a comment (GNU 730-737), indented, and continued
# (776-781). Only the first is checked, as before this change.
_RULE_FORMS = {
    "column-0": ".x.o:\n\tcp $< $@\n",
    "comment": ".x.o: # c\n\tcp $< $@\n",
    "indented": "  .x.o:\n\tcp $< $@\n",
    "continued": ".x.o: \\\n\n\tcp $< $@\n",
}

# Rules for .SUFFIXES other than one whose one target is .SUFFIXES, and lines
# that one GNU make reads as such a rule, each adding '.x' to the list here
_MORE_DECLARATIONS = {
    "before": "x .SUFFIXES: .x",
    "after": ".SUFFIXES x: .x",
    "phony": ".SUFFIXES .PHONY: .x",
    "tab": "dummy\t.SUFFIXES: .x",
    "continued": "x \\\n.SUFFIXES: .x",
    "twice": ".SUFFIXES .SUFFIXES: .x",
    "private": "private .SUFFIXES: .x",
    "override": "override .SUFFIXES: .x",
    "dot-slash": "./.SUFFIXES: .x",
    "dot-slashes": ".//.SUFFIXES: .x",
    "double-colon": "x .SUFFIXES:: .x",
    "grouped": ".SUFFIXES x &: .x ; @true",
    "undefine": "undefine .SUFFIXES: .x",
    "recipe-prefix": ".RECIPEPREFIX = >\nall: ;\n\t.SUFFIXES: .x\n.RECIPEPREFIX =",
}

# Rules for .SUFFIXES without prerequisites that do not empty the list here:
# only a line '.SUFFIXES:' alone, outside conditionals and define bodies, in
# a makefile that reads no other makefile text, does
_KEPT_LISTS = {
    "before": "x .SUFFIXES:",
    "after": ".SUFFIXES x:",
    "private": "private .SUFFIXES:",
    "recipe": "x .SUFFIXES: ; @true",
    "dot-slash": "./.SUFFIXES:",
    "space": ".SUFFIXES :",
    "tab": ".SUFFIXES\t:",
    "double-colon": ".SUFFIXES::",
    "comment": ".SUFFIXES: # none",
    "override": "override .SUFFIXES:",
    "undefine": "undefine .SUFFIXES:",
    "grouped": ".SUFFIXES x &: ; @true",
    "conditional": "ifdef NOSUF\n.SUFFIXES:\nendif",
    "define-body": "define CLEAR\n.SUFFIXES:\nendef",
    "continued": "x \\\n.SUFFIXES:",
    "include": "-include more.mk\n.SUFFIXES:",
    "eval": ".SUFFIXES:\n$(eval X = 1)",
    "call": ".SUFFIXES:\nX := $(call f,1)",
    "makefiles": "MAKEFILES += more.mk\n.SUFFIXES:",
    "makeflags-file": "MAKEFLAGS += -f more.mk\n.SUFFIXES:",
    "reference-before": "E :=\n.SUFFIXES:\nX := $(E) .SUFFIXES",
    "recipe-prefix": ".RECIPEPREFIX = >\nall: ;\n\t.SUFFIXES:\n.RECIPEPREFIX =",
}

# Rules for .SUFFIXES, and lines like them, that make may read otherwise than
# mbake can: the suffix list is not known, so no suffix rule gets an error.
# At the shapes that TestAgainstGnuMake.test_unknown_shapes and
# test_list_kept_by_unknown_shapes run, GNU make runs the suffix rule (make
# 3.81 only at '.SUFFIXES/', make 4.4.1 only after a byte order mark); mbake
# does not tell what make reads at the others.
_UNKNOWN_SHAPES = {
    "escaped-blank": "x\\ .SUFFIXES:\n.SUFFIXES: .q",
    "escaped-tab": "x\\\t.SUFFIXES:\n.SUFFIXES: .q",
    "no-break-space": ".SUFFIXES: .q\n.SUFFIXES:\xa0",
    "no-break-space-target": ".SUFFIXES: .q\nx\xa0.SUFFIXES:",
    "unit-separator": ".SUFFIXES: .q\n.SUFFIXES:\x1f",
    "ideographic-space": ".SUFFIXES: .q\n.SUFFIXES:\u3000",
    "vertical-tab": "x .SUFFIXES:\x0b.q",
    "bar-after": ".SUFFIXES: .q|",
    "bar-before": "x .SUFFIXES: |.q",
    "escaped-semicolon": ".SUFFIXES: .q\\;",
    "slash": ".SUFFIXES/: .q",
    "byte-order-mark": "\ufeff.SUFFIXES: .q",
    "variable": "Q = .q\n.SUFFIXES: $(Q)",
    "wildcard": ".SUFFIXES: .q*",
    "parent-directory": "../.SUFFIXES: .q",
    "triple-colon": ".SUFFIXES::: .q",
    "static-pattern": ".SUFFIXES: %.q: %.r",
}


def _runner() -> CliRunner:
    """Return a CliRunner that keeps stdout and stderr apart."""
    try:
        return CliRunner(mix_stderr=False)  # click < 8.2
    except TypeError:
        return CliRunner()  # click >= 8.2 always captures stderr separately


def _special(text, config=GNU, **context):
    """Return the FormatResult of SpecialTargetValidationRule for text."""
    return SpecialTargetValidationRule().format(text.splitlines(), config, **context)


def _suffix(text, config=GNU, **context):
    """Return the FormatResult of SuffixValidationRule for text."""
    return SuffixValidationRule().format(text.splitlines(), config, **context)


def _both(text, config=GNU):
    """Return the errors and warnings of both rules for text."""
    special, suffix = _special(text, config), _suffix(text, config)
    return special.errors + suffix.errors, special.warnings + suffix.warnings


def _formatter(gnu_error_format=True, **config):
    return MakefileFormatter(
        Config(formatter=FormatterConfig(**config), gnu_error_format=gnu_error_format)
    )


def _format_messages(text, gnu_error_format=True, check_only=True, **config):
    """Return the formatter's errors and the warnings of the two rules.

    The lines are split as format_file splits a file: only a newline ends a
    line (GNU 757-758).
    """
    _, errors, warnings = _formatter(gnu_error_format, **config).format_lines(
        split_makefile_lines(text), check_only, text
    )
    ours = ("special target", "Special target", "suffix", "Suffix")
    return errors, [w for w in warnings if any(key in w for key in ours)]


class _SuffixRuleBefore(FormatterPlugin):
    """SuffixValidationRule as it was before this change (mbake 1.4.6).

    It ran at priority 15, after the rules that change lines before it, and
    gave its errors without a line number. Only its errors are kept here.
    """

    def __init__(self) -> None:
        super().__init__("suffix_validation_before", priority=15)

    def format(self, lines, config, check_mode=False, **context):
        errors = []
        declared = set()
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(".SUFFIXES:"):
                content = line[line.find(":") + 1 :].strip()
                seen = set()
                for suffix in content.split():
                    if not suffix.startswith("."):
                        errors.append(
                            f"Invalid suffix '{suffix}' - suffixes must start with '.'"
                        )
                        continue
                    if suffix in seen:
                        errors.append(
                            f"Duplicate suffix '{suffix}' in .SUFFIXES declaration"
                        )
                    seen.add(suffix)
                declared.update(s for s in content.split() if s.startswith("."))
            elif re.match(r"^\.[^:]+\.\w+:\s*$", stripped):
                match = re.match(r"^(\.[^:]+\.\w+):", line)
                if match and len(match.group(1).split(".")) == 3:
                    target = match.group(1)
                    for part in target.split(".")[1:]:
                        if "." + part not in declared:
                            errors.append(
                                f"Suffix rule '{target}' uses undeclared suffix "
                                f"'.{part}'"
                            )
        return FormatResult(
            lines=list(lines),
            changed=False,
            errors=errors,
            warnings=[],
            check_messages=[],
        )


def _formatter_before(gnu_error_format=True, **config):
    """A formatter with the suffix check as it was before this change."""
    formatter = _formatter(gnu_error_format, **config)
    rules = [
        rule
        for rule in formatter.rules
        if rule.name not in ("suffix_validation", "special_target_validation")
    ]
    position = next(i for i, rule in enumerate(rules) if rule.priority >= 15)
    rules.insert(position, _SuffixRuleBefore())
    formatter.rules = rules
    return formatter


def _error_texts(errors):
    """Return the errors without their line numbers and 'Error:' shape."""
    texts = []
    for error in errors:
        error = re.sub(r" \(line \d+\)\Z", "", error)
        texts.append(re.sub(r"\A(?:\d+: Error: |Line \d+: |Error: )", "", error))
    return Counter(texts)


class GnuMake(NamedTuple):
    """A GNU make to run, with its version."""

    path: str
    true: str
    version: tuple[int, int]


@pytest.fixture(scope="module", params=["make", "gmake"])
def gnu_make(request):
    """Return a GNU make (make, and gmake when it is another program), or skip."""
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
    match = re.match(r"GNU Make (\d+)\.(\d+)", version)
    if match is None:
        pytest.skip("make is not GNU make")
    return GnuMake(make, true, (int(match.group(1)), int(match.group(2))))


def _make(gnu_make, tmp_path, text, *args, touch=(), shell=None):
    """Write text to tmp_path/Makefile, create the files touch, and run make.

    make runs in tmp_path with SHELL set on its command line (the 'true'
    program unless shell is given), so no recipe runs a command. Nothing is
    appended after the text's last line.
    """
    (tmp_path / "Makefile").write_text(text, encoding="utf-8")
    for name in touch:
        (tmp_path / name).write_text("", encoding="utf-8")
    return subprocess.run(
        [gnu_make.path, "-f", "Makefile", f"SHELL={shell or gnu_make.true}", *args],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        env=_MAKE_ENV,
    )


def _make_suffixes(gnu_make, tmp_path, text):
    """Return the suffix list that make has once it has read text, without
    the default suffixes ('-r', GNU 8538-8539)."""
    proc = _make(gnu_make, tmp_path, text, "-r", "-p", "-n")
    lines = [line for line in proc.stdout.splitlines() if line.startswith(".SUFFIXES:")]
    assert len(lines) == 1, proc.stdout[-2000:]
    return lines[0].split()[1:]


class TestSpecialTargets:
    """Every special target of the manual is known, and may be repeated."""

    @pytest.mark.parametrize("name", SPECIAL_TARGETS)
    def test_special_target_with_prerequisites(self, name):
        """GNU 2229-2429, 3351-3352."""
        assert _both(f"{name}: .x1\n") == ([], [])

    @pytest.mark.parametrize("name", [n for n in SPECIAL_TARGETS if n != ".PHONY"])
    def test_special_target_without_prerequisites(self, name):
        """Only .PHONY gets a warning (see test_phony_without_prerequisites).
        Without prerequisites, .IGNORE and .SILENT apply to every target (GNU
        2339-2344, 2383-2388), as .NOTINTERMEDIATE and .SECONDARY do
        (2283-2284, 2315-2317)."""
        assert _both(f"{name}:\n") == ([], [])

    @pytest.mark.parametrize("name", SPECIAL_TARGETS)
    def test_repeated_special_target(self, name):
        """Any target may be the target of several rules, whose prerequisites
        make merges (GNU 2545-2548): there is no 'cannot be declared multiple
        times'."""
        text = f"{name}: .x1\n{name}: .x2\n{name}: .x3\n"
        assert _both(text) == ([], [])

    def test_repeated_posix_without_prerequisites(self):
        """The case of the issue: '.POSIX:' twice (GNU 2417-2429, 2545-2548)."""
        assert _both(".POSIX:\n.POSIX:\nall:\n\t@echo ok\n") == ([], [])

    def test_notintermediate(self):
        """.NOTINTERMEDIATE is a special target of make 4.4 (GNU 2279-2287)."""
        assert _both(".NOTINTERMEDIATE:\n.NOTINTERMEDIATE: x.b %.o\n") == ([], [])

    def test_unknown_special_target_is_a_warning(self):
        """make reads an unknown dot target as an ordinary target, which is
        never the default goal (GNU 1440-1447): a warning on its own line."""
        result = _special("all:\n\t@echo ok\n.KEEP_STATE:\n")
        assert result.errors == []
        assert result.warnings == ["3: Warning: Unknown special target '.KEEP_STATE'"]

    @pytest.mark.parametrize(
        "name", [".SECOND_EXPANSION", ".DEFAULT_GOAL", ".NOEXPORT", ".MAKE"]
    )
    def test_names_that_are_no_special_targets(self, name):
        """A misspelt .SECONDEXPANSION, '.DEFAULT_GOAL' written as a rule, and
        names that the manual does not list as targets are ordinary targets
        (GNU 1440-1447, 2229-2429)."""
        result = _special(f"{name}: all\n")
        assert result.errors == []
        assert result.warnings == [f"1: Warning: Unknown special target '{name}'"]

    def test_traditional_warning(self):
        """With gnu_error_format off, the 'Line N:' shape."""
        result = _special(".KEEP_STATE:\n", TRADITIONAL)
        assert result.warnings == ["Line 1: Unknown special target '.KEEP_STATE'"]

    @pytest.mark.parametrize(
        "name",
        [
            ".DEFAULT_GOAL",
            ".RECIPEPREFIX",
            ".SHELLFLAGS",
            ".LIBPATTERNS",
            ".VARIABLES",
            ".FEATURES",
            ".INCLUDE_DIRS",
            ".EXTRA_PREREQS",
            ".LOADED",
            ".ANY_NAME",
        ],
    )
    @pytest.mark.parametrize("operator", ["=", ":=", "::=", ":::=", "+=", "?=", "!="])
    @pytest.mark.parametrize("space", ["", " "])
    def test_special_variable_assignments(self, name, operator, space):
        """An assignment to a special variable (GNU 6.14, lines 5062-5303),
        or to any name, is no rule, with or without spaces around the
        operator (6.5, lines 4577-4579)."""
        text = f"{name}{space}{operator}{space}x\n"
        assert _both(text) == ([], [])

    def test_ignore_and_silent_without_prerequisites(self):
        """Both apply to every target (GNU 2339-2344, 2383-2388)."""
        assert _both(".IGNORE:\n.SILENT:\nall:\n\t@echo ok\n") == ([], [])

    @pytest.mark.parametrize(
        "text",
        [".PHONY:\n", ".PHONY: # no targets\n", ".PHONY: ; @echo\n", ".PHONY:: \n"],
    )
    def test_phony_without_prerequisites(self, text):
        """.PHONY does nothing without prerequisites (GNU 2236-2240); the
        comment and the recipe are none (3.1, lines 730-737; 4.2, lines
        1499-1503)."""
        result = _special(text)
        assert result.warnings == [
            "1: Warning: Special target '.PHONY' typically requires prerequisites"
        ]

    @pytest.mark.parametrize(
        "text", [".PHONY: all\n", ".PHONY: \\\n  all clean\n", ".PHONY:all\n"]
    )
    def test_phony_with_prerequisites(self, text):
        """A continued line is one logical line (GNU 776-781)."""
        assert _special(text).warnings == []

    @pytest.mark.parametrize(
        "text",
        [
            ".C:\n\t$(CXX) -o $@ $<\n",
            ".SUFFIXES: .FOO\n.FOO:\n\tcp $< $@\n",
            ".FOO:\n\tcp $< $@\n.SUFFIXES: .FOO\n",
            "x .SUFFIXES: .FOO\n.FOO:\n\tcp $< $@\n",
        ],
    )
    def test_single_suffix_rule_is_known(self, text):
        """A rule whose target is a known suffix is a single-suffix rule, a
        special target too (GNU 2431-2438, 8479-8489); .C is a default suffix
        (7545-7549), and a rule with several targets is one rule for each
        (2451-2453)."""
        assert _both(text) == ([], [])

    def test_single_suffix_rule_of_a_cleared_suffix(self):
        """'.SUFFIXES:' empties the list (GNU 8529-8536), so '.C' is an
        ordinary target."""
        assert _special(".SUFFIXES:\n.C:\n\t$(CXX) -o $@ $<\n").warnings == [
            "2: Warning: Unknown special target '.C'"
        ]

    @pytest.mark.parametrize(
        "text",
        [
            "define BODY\n.KEEP_STATE:\n.SUFFIXES: a\n.x.o:\nendef\n",
            "all:\n\t.KEEP_STATE:\n\t.SUFFIXES: a\n\t.x.o:\n",
            "X = a \\\n.KEEP_STATE: b\n",
            ".KEEP_STATE: X = 1\n.SUFFIXES: X = 1\n",
        ],
        ids=["define-body", "recipe", "continued-assignment", "target-variable"],
    )
    def test_lines_that_are_no_rules(self, text):
        """A define body is a value (GNU 4795-4799), a recipe line goes to
        the shell (744-746), a continued line belongs to the line it
        continues (776-781), and 'T: X = 1' sets a target-specific variable
        (4938-4951)."""
        assert _both(text) == ([], [])

    @pytest.mark.parametrize(
        "text",
        [
            ".KEEP_STATE:\n",
            ".POSIX:\n.POSIX:\n",
            ".SUFFIXES:\n.SUFFIXES: a .c .c\n.x.y:\n\tcp $< $@\n",
        ],
    )
    def test_lines_are_left_as_they_are(self, text):
        """The rules only report."""
        lines = text.splitlines()
        for rule in (SpecialTargetValidationRule(), SuffixValidationRule()):
            result = rule.format(list(lines), GNU)
            assert result.lines == lines
            assert result.changed is False


class TestSuffixRules:
    """Suffix rules are checked against the suffix list as make has it."""

    def test_default_suffixes_hold_the_manual_list(self):
        """GNU 7545-7549, and '.yl' of GNU make 4.4.1."""
        assert set(MANUAL_DEFAULT_SUFFIXES) <= DEFAULT_SUFFIXES
        assert DEFAULT_SUFFIXES - set(MANUAL_DEFAULT_SUFFIXES) == {".yl"}

    @pytest.mark.parametrize("rule", [".c.o", ".a.o", ".cpp.o", ".y.c", ".yl.c"])
    def test_default_suffix_rule(self, rule):
        """'.c' and '.o' are on the default list (GNU 8491-8498)."""
        assert _suffix(f"{rule}:\n\tcp $< $@\n").errors == []

    def test_added_suffix(self):
        """'.SUFFIXES: .x' adds '.x' to the list (GNU 8521-8527)."""
        assert _suffix(".SUFFIXES: .x\n.x.o:\n\tcp $< $@\n").errors == []

    def test_undeclared_suffix(self):
        """'.x' is neither declared nor a default suffix."""
        assert _suffix(".SUFFIXES: .c .o\n\n.x.o:\n\tcp $< $@\n").errors == [
            "3: Error: Suffix rule '.x.o' uses undeclared suffix '.x'"
        ]

    def test_cleared_suffixes(self):
        """'.SUFFIXES:' empties the list (GNU 8529-8536)."""
        assert _suffix(".SUFFIXES:\n.c.o:\n\tcp $< $@\n").errors == [
            "2: Error: Suffix rule '.c.o' uses undeclared suffix '.c'",
            "2: Error: Suffix rule '.c.o' uses undeclared suffix '.o'",
        ]
        text = ".SUFFIXES:\n.SUFFIXES: .c .o\n.c.o:\n\tcp $< $@\n"
        assert _suffix(text).errors == []

    def test_suffix_added_below_the_rule(self):
        """make finds suffix rules once it has read the makefile (see the
        make-backed tests)."""
        assert _suffix(".x.o:\n\tcp $< $@\n.SUFFIXES: .x\n").errors == []

    def test_suffix_cleared_below_the_rule(self):
        """make empties the list below the rule, so it is no suffix rule
        (GNU 8529-8536), but the lines above it declared both suffixes, and
        the rule gave no error for them before this change, so it gives
        none now."""
        text = ".SUFFIXES: .c .o\n.c.o:\n\tcp $< $@\n.SUFFIXES:\n.SUFFIXES: .x\n"
        assert _suffix(text).errors == []
        assert _suffix(".c.o:\n\tcp $< $@\n.SUFFIXES:\n").errors == [
            "1: Error: Suffix rule '.c.o' uses undeclared suffix '.c'",
            "1: Error: Suffix rule '.c.o' uses undeclared suffix '.o'",
        ]

    def test_errors_are_only_removed(self):
        """'.c' was declared above the rule, so the rule gave no error for it
        before this change, and gives none now, although '.SUFFIXES:' empties
        the list (GNU 8529-8536). '.o' was not declared, and the list does
        not hold it once it is emptied."""
        text = ".SUFFIXES: .c\n.SUFFIXES:\n.c.o:\n\tcp $< $@\n"
        assert _suffix(text).errors == [
            "3: Error: Suffix rule '.c.o' uses undeclared suffix '.o'"
        ]

    @pytest.mark.parametrize(
        "declaration", list(_KEPT_LISTS.values()), ids=list(_KEPT_LISTS)
    )
    def test_only_a_plain_clear_empties_the_list(self, declaration):
        """The list is emptied here only by a line '.SUFFIXES:' alone,
        outside conditionals (GNU 7.2) and define bodies (4795-4799), in a
        makefile that reads no other makefile text (842-843, 938-942,
        6289-6295, 6383-6385, 7174-7175), where GNU make 3.81 and 4.4.1 both
        empty it (8529-8536). Other rules for .SUFFIXES without prerequisites
        leave the list as it is here, so that it holds every suffix that make
        may have: make may skip a conditional, other makefile text may add
        suffixes again, and with '.SUFFIXES::' make 4.4.1 keeps the list. So
        '.c.o' gets no error, also where make empties the list, as at
        'x .SUFFIXES:' (see TestAgainstGnuMake.test_default_suffix_rule)."""
        assert _suffix(f"{declaration}\n.c.o:\n\tcp $< $@\n").errors == []

    @pytest.mark.parametrize(
        "declaration",
        [
            ".SUFFIXES: \\\n  .x",
            ".SUFFIXES: .x # .y comment",
            ".SUFFIXES: .x ; @echo inline",
            ".SUFFIXES : .x",
            ".SUFFIXES:: .x",
        ],
        ids=["continued", "comment", "inline-recipe", "space", "double-colon"],
    )
    def test_declaration_read_as_make_reads_it(self, declaration):
        """A logical line (GNU 776-781) cut at its comment (730-737), with
        the prerequisites before the inline recipe (1488, 1499-1503). GNU
        make 4.4.1 adds the prerequisites of '.SUFFIXES::' too (see
        TestAgainstGnuMake.test_double_colon)."""
        result = _suffix(f"{declaration}\n.x.o:\n\tcp $< $@\n")
        assert (result.errors, result.warnings) == ([], [])

    def test_variable_reference(self):
        """A reference stands for the suffixes of its value (GNU 4117-4121),
        which are not known here."""
        result = _suffix("L = .x\n.SUFFIXES: $(L)\n.x.o:\n\tcp $< $@\n")
        assert (result.errors, result.warnings) == ([], [])

    def test_assignment_to_suffixes_variable(self):
        """'.SUFFIXES := .x' sets a variable, not the suffix list."""
        assert _suffix(".SUFFIXES := .x\n.x.o:\n\tcp $< $@\n").errors == [
            "2: Error: Suffix rule '.x.o' uses undeclared suffix '.x'"
        ]

    @pytest.mark.parametrize("rule", list(_RULE_FORMS.values()), ids=list(_RULE_FORMS))
    def test_rule_forms(self, rule):
        """make reads each form as a rule (GNU 730-737, 776-781), but only
        a rule alone on its line, at its start, is checked, as before this
        change."""
        errors = _suffix(rule).errors
        if rule.startswith(".x.o:\n"):
            assert errors == [
                "1: Error: Suffix rule '.x.o' uses undeclared suffix '.x'"
            ]
        else:
            assert errors == []

    def test_two_targets_are_no_suffix_rule(self):
        """'.c .o:' (here continued) has two targets (GNU 1492-1497)."""
        assert _suffix(".c\\\n.o:\n\tcp $< $@\n.a b.c:\n").errors == []

    def test_single_suffix_with_a_dot(self):
        """'.tar.gz' declared is one suffix (GNU 8479-8489)."""
        result = _suffix(".SUFFIXES: .tar.gz\n.tar.gz:\n\techo $<\n")
        assert result.errors == []

    def test_declaration_messages(self):
        """The messages about a .SUFFIXES line name it."""
        text = ".SUFFIXES: .c .o .c\n.SUFFIXES: a .cpp .o\n.SUFFIXES: . .tar.gz\n"
        result = _suffix(text)
        assert result.errors == [
            "1: Error: Duplicate suffix '.c' in .SUFFIXES declaration",
            "2: Error: Invalid suffix 'a' - suffixes must start with '.'",
        ]
        assert result.warnings == [
            "2: Warning: Suffix '.o' is already declared in previous .SUFFIXES "
            "statement",
            "3: Warning: Unusual suffix '.' - consider if this is intentional",
            "3: Warning: Complex suffix '.tar.gz' - ensure this is supported by "
            "your Make version",
        ]

    def test_redeclared_after_clear(self):
        """Once the list is empty (GNU 8529-8536), adding a suffix again is
        needed."""
        result = _suffix(".SUFFIXES: .x\n.SUFFIXES:\n.SUFFIXES: .x\n")
        assert result.warnings == []

    def test_traditional_error(self):
        """With gnu_error_format off, the 'Line N:' shape."""
        result = _suffix(".SUFFIXES:\n.c.o:\n", TRADITIONAL)
        assert result.errors == [
            "Line 2: Suffix rule '.c.o' uses undeclared suffix '.c'",
            "Line 2: Suffix rule '.c.o' uses undeclared suffix '.o'",
        ]

    def test_makeflags_no_builtin_rules(self):
        """'-r' empties the default list (GNU 8538-8539) for make 4.4.1, but
        make 3.81 keeps it where the makefile adds the flag to MAKEFLAGS, and
        runs '.c.o' (see the make-backed test)."""
        assert _suffix("MAKEFLAGS += -r\n.c.o:\n\tcc -c $<\n").errors == []

    RULES = (
        ".SUFFIXES: .c .o # .q comes from elsewhere\n"
        ".x.o: # c\n\tcp $< $@\n"
        "  .x.c:\n\tcp $< $@\n"
        ".x.q: \\\n\n\tcp $< $@\n"
        ".x.q:\n\tcp $< $@\n"
    )

    def test_comment_words_counted_before_still_count(self):
        """Only '.x.q:' alone on its line is checked. A comment declares
        nothing for make (GNU 730-737), but the rule counted '.q' of the
        comment before this change, so '.x.q' gets no error for '.q'."""
        assert _suffix(self.RULES).errors == [
            "9: Error: Suffix rule '.x.q' uses undeclared suffix '.x'"
        ]

    @pytest.mark.parametrize(
        "line",
        [
            "include more.mk",
            "-include more.mk",
            "sinclude more.mk",
            "load more.so",
            "$(eval X = 1)",
            "all:\n\t$(eval X = 1)",
            "$(SETUP)",
            "$(TARGETS): x.h",
            "X := $(call f,Y = 1)",
            "X := $(call \\\neval,Y = 1)",
            "all: $(guile #t)",
            "MAKEFILES = more.mk",
            "MAKEFLAGS += -f more.mk",
        ],
        ids=[
            "include",
            "-include",
            "sinclude",
            "load",
            "eval",
            "eval-in-recipe",
            "reference",
            "reference-target",
            "call",
            "call-continued",
            "guile",
            "makefiles",
            "makeflags-file",
        ],
    )
    def test_text_that_make_may_read_elsewhere(self, line):
        """Where make may read makefile text that the lines do not hold (GNU
        842-843, 938-942, 1221-1236, 6289-6295, 6383-6385, 7174-7175,
        8931-8936, 9128-9131), that text may add any suffix after an empty
        '.SUFFIXES:', so '.SUFFIXES:' does not empty the list here, while a
        suffix that the lines never name still gets its error."""
        text = f"{line}\n.SUFFIXES:\n.c.o:\n\tcp $< $@\n.x.o:\n\tcp $< $@\n"
        number = text.splitlines().index(".x.o:") + 1
        assert _suffix(text).errors == [
            f"{number}: Error: Suffix rule '.x.o' uses undeclared suffix '.x'"
        ]


class TestDefineBodies:
    """make reads a define body as makefile text wherever the makefile
    evaluates it (GNU 4790-4793), also through call with a computed name
    (6289-6295), which the lines need not show. So a suffix that a line of
    a body names after '.SUFFIXES' and a colon counts as declared, whether
    or not an evaluation is seen, and such a line never empties the list."""

    @pytest.mark.parametrize(
        "text",
        [
            "define X\n.SUFFIXES: .x\nendef\n.x.o:\n\tcp $< $@\n",
            "define X\n.SUFFIXES: \\\n  .x\nendef\n.x.o:\n\tcp $< $@\n",
            "define X\n  .SUFFIXES : .y .x # c\nendef\n.x.o:\n\tcp $< $@\n",
            "define X\n.SUFFIXES:\nendef\n.c.o:\n\tcp $< $@\n",
        ],
        ids=["named", "continued", "spaced", "empty"],
    )
    def test_body_suffixes_count(self, text):
        """A continued line of the body is one logical line (GNU 776-781)."""
        assert _suffix(text).errors == []

    def test_only_named_suffixes_count(self):
        text = "define X\n.SUFFIXES: .x\nendef\n.q.o:\n\tcp $< $@\n"
        assert _suffix(text).errors == [
            "4: Error: Suffix rule '.q.o' uses undeclared suffix '.q'"
        ]


class TestRulesForSuffixes:
    """A rule for .SUFFIXES is any rule whose targets include .SUFFIXES: a
    rule with several targets is one rule for each of them (GNU 2451-2453),
    and make removes './' from the start of a file name (9722-9723). A line
    that one GNU make reads as such a rule and the other does not counts
    too: with .RECIPEPREFIX set, make 4.x reads a line that starts with a TAB
    as makefile syntax (5158-5169), and 'undefine' is a directive only of a
    make that lists it in .FEATURES (5251-5252)."""

    @pytest.mark.parametrize(
        "declaration", list(_MORE_DECLARATIONS.values()), ids=list(_MORE_DECLARATIONS)
    )
    @pytest.mark.parametrize("rule", list(_RULE_FORMS.values()), ids=list(_RULE_FORMS))
    def test_suffix_added(self, declaration, rule):
        """'.x' is added, so '.x.o' gets no error in any form."""
        assert _suffix(f"{declaration}\n{rule}").errors == []

    @pytest.mark.parametrize(
        "line",
        [
            "export .SUFFIXES: .x",
            "unexport .SUFFIXES: .x",
            "vpath .SUFFIXES: .x",
            "x .SUFFIXES: X = .x",
            "x .SUFFIXES: .c # .x",
        ],
        ids=["export", "unexport", "vpath", "target-variable", "comment"],
    )
    def test_lines_that_add_nothing(self, line):
        """make reads these lines as directives (GNU 10847-10913), a
        target-specific variable (4938-4951), and a rule whose '.x' is in the
        comment (730-737), so '.x' is not added (see
        TestAgainstGnuMake.test_added_suffix_rule)."""
        assert _suffix(f"{line}\n.x.o:\n\tcp $< $@\n").errors == [
            "2: Error: Suffix rule '.x.o' uses undeclared suffix '.x'"
        ]

    @pytest.mark.parametrize(
        "text",
        [
            "x .SUFFIXES: w .c .c\n",
            "private .SUFFIXES: w .c .c\n",
            "./.SUFFIXES: w .c .c\n",
            ".RECIPEPREFIX = >\nall: ;\n\t.SUFFIXES: w .c .c\n.RECIPEPREFIX =\n",
        ],
        ids=["before", "private", "dot-slash", "recipe-prefix"],
    )
    def test_words_not_checked(self, text):
        """Only the words of a line that starts with '.SUFFIXES:' are checked
        (see TestDeclarationChecks)."""
        result = _suffix(text)
        assert (result.errors, result.warnings) == ([], [])

    @pytest.mark.parametrize(
        "text", ["./x.o:\n\tcp $< $@\n", "./config.status:\n\t./configure\n"]
    )
    def test_dot_slash_target_is_no_suffix_rule(self, text):
        """make removes './' from the start of a file name (GNU 9722-9723), so
        './x.o' is the file 'x.o' (see the make-backed test)."""
        assert _suffix(text).errors == []


class TestUnknownSuffixList:
    """Where a line that names .SUFFIXES has a shape that make may read
    otherwise than mbake can, the suffix list is not known, and no suffix
    rule gets an error: an escaped blank or ';' (GNU 730-737, 1499-1503),
    whitespace other than blanks, '|' (4.3), a byte order mark, another name
    for .SUFFIXES, a reference or a wildcard (4117-4121, 4.4), a second colon
    and a static pattern (4.12)."""

    @pytest.mark.parametrize(
        "declaration", list(_UNKNOWN_SHAPES.values()), ids=list(_UNKNOWN_SHAPES)
    )
    @pytest.mark.parametrize("rule", [".q.o", ".c.o", ".x.o"])
    def test_no_suffix_rule_error(self, declaration, rule):
        text = f"{declaration}\n{rule}:\n\t@echo SUFFIX-RULE\n"
        for check_only in (False, True):
            errors = _format_messages(text, True, check_only)[0]
            assert [e for e in errors if "undeclared suffix" in e] == []

    def test_last_line_ends_with_a_backslash(self):
        """Without a final newline, make reads the backslash as a
        prerequisite (GNU 757-758), and keeps the list (see
        TestAgainstGnuMake.test_last_line_ends_with_a_backslash)."""
        text = ".c.o:\n\t@echo SUFFIX-RULE\n.SUFFIXES: \\"
        for check_only in (False, True):
            assert _format_messages(text, True, check_only)[0] == []


class TestDeclarationChecks:
    """The checks of the words of a rule for .SUFFIXES read only lines and
    words that mbake 1.4.6 checked too: a line that starts with '.SUFFIXES:'
    and does not end with a backslash, and of its words those that make
    reads as prerequisites as they stand. GNU make 3.81 and 4.4.1 accept a suffix
    without a dot and a repeated one (see TestAgainstGnuMake), so those two
    errors stay only because tests/test_auto_phony_insertion.py expects
    them."""

    @pytest.mark.parametrize(
        ("line", "words"),
        [
            (".SUFFIXES: .c .o", [".c", ".o"]),
            ("  .SUFFIXES: a .b", ["a", ".b"]),
            (".SUFFIXES:", []),
            (".SUFFIXES: $(S) .c", ["$(S)", ".c"]),
            (".SUFFIXES: .c # .c x", [".c"]),
            (".SUFFIXES: .c .c#x", [".c"]),
            (".SUFFIXES: .c .c; @echo", [".c"]),
            (".SUFFIXES: a;", []),
            (".SUFFIXES:: .c .c", [".c", ".c"]),
            (".SUFFIXES::.c .c", [".c"]),
            (".SUFFIXES : .c .c", None),
            (".SUFFIXES\t: w", None),
            (".SUFFIXES: .c \\", None),
            (".SUFFIXES: .o\\", None),
            (".SUFFIXES: .c\\\\", None),
            (".SUFFIXES: w \\\\", None),
            (".SUFFIXES: .c\\ ", None),
            (".SUFFIXES: a\\\t", None),
        ],
    )
    def test_checked_words(self, line, words):
        """A comment (GNU 730-737), an inline recipe (1499-1503) and the
        second ':' of a double-colon rule (2721-2722) are no prerequisites,
        and a line that ends with an odd number of backslashes continues
        (762-769, 776-781). A line that ends with an even number, or with a
        backslash and blanks, is not checked either: mbake 1.4.6 checked it
        only after its continuation rule, which can rewrite its last
        word."""
        from mbake.core.rules.suffix_validation import checked_words

        assert checked_words(line) == words

    @pytest.mark.parametrize(
        "text",
        [
            ".SUFFIXES : .z .z w . .tar.gz\nall:\n\t@echo all\n",
            ".SUFFIXES\t: .c .c\nall:\n\t@echo all\n",
            ".SUFFIXES: .z\\\n.z\nall:\n\t@echo all\n",
            ".SUFFIXES: .x\\\ny\nall:\n\t@echo all\n",
            ".SUFFIXES: .c . \\\n  .c w .tar.gz\nall:\n\t@echo all\n",
            ".SUFFIXES: .c\n.SUFFIXES : .c\n.SUFFIXES: .c\\\n  .c\n"
            "all:\n\t@echo all\n",
            "include extra.mk\n.SUFFIXES : .c .o .c\nall:\n\t@echo all\n",
        ],
        ids=[
            "space",
            "tab",
            "continued",
            "continued-no-dot",
            "continued-blank",
            "not-already-declared",
            "include",
        ],
    )
    def test_lines_that_are_not_checked(self, text):
        """The lines get no message. mbake 1.4.6 did not check them either,
        except 'continued-blank', whose first line it checked, taking the
        backslash for a word. make reads such lines (see
        TestAgainstGnuMake.test_declarations_that_are_not_checked)."""
        assert _both(text) == ([], [])
        for check_only in (False, True):
            assert _format_messages(text, True, check_only) == ([], [])

    @pytest.mark.parametrize(
        ("text", "errors"),
        [
            (".SUFFIXES: .c .c#x\n", []),
            (".SUFFIXES: .c .c;\n", []),
            (".SUFFIXES: a;\n", []),
            (".SUFFIXES: .c # .c x\n", []),
            (".SUFFIXES::.c .c\n", []),
            (
                ".SUFFIXES:: .c .c\n",
                ["1: Error: Duplicate suffix '.c' in .SUFFIXES declaration"],
            ),
        ],
    )
    def test_words_cut_by_a_comment_or_a_recipe(self, text, errors):
        """Only words that make reads as prerequisites as they stand are
        checked (GNU 730-737, 1499-1503, 2721-2722)."""
        assert _suffix(text).errors == errors

    def test_already_declared_counts_checked_lines(self):
        """'already declared' names a suffix of a checked line above."""
        assert _suffix(".SUFFIXES : .c\n.SUFFIXES: .c .o\n").warnings == []
        assert _suffix(".SUFFIXES: .c\n.SUFFIXES: .c .o\n").warnings == [
            "2: Warning: Suffix '.c' is already declared in previous .SUFFIXES "
            "statement"
        ]


# Rules for .SUFFIXES and lines around a suffix rule, in shapes that the
# earlier rounds found, for TestErrorsOfBefore
_BEFORE_DECLARATIONS = [
    "",
    ".SUFFIXES:",
    ".SUFFIXES: .x",
    ".SUFFIXES: .x # .q",
    ".SUFFIXES : .x",
    ".SUFFIXES: \\\n  .x",
    "x .SUFFIXES:",
    "x .SUFFIXES: .x",
    "ifdef NOPE\n.SUFFIXES:\nendif",
    "define D\n.SUFFIXES: .x\nendef",
    "include more.mk\n.SUFFIXES:",
    "x\\ .SUFFIXES:",
    ".SUFFIXES:\xa0",
    ".SUFFIXES: .x|",
    ".SUFFIXES: .x\\;",
    ".SUFFIXES/: .x",
    "\ufeff.SUFFIXES: .x",
    ".SUFFIXES: w .c .c",
    "all:\n\tcp \\\njunk",
    "X = a \\\n  b\\\\",
    "X = 1 \\\\\n.SUFFIXES: a\\ ",
    "X = 1 \\\\\n.SUFFIXES: .c .c\\\t",
]
_BEFORE_RULES = [
    ".x.o:\n\tcp $< $@",
    ".c.o:\n\tcp $< $@",
    ".x.o: # c\n\tcp $< $@",
    "  .c.o:\n\tcp $< $@",
    ".x.o: \\\n\n\tcp $< $@",
    ".env.local: # copy\n\tcp .env.example $@",
]
_BEFORE_CASES = [
    f"{first}\n{rule}\n{second}\n".lstrip("\n")
    for first in _BEFORE_DECLARATIONS
    for rule in _BEFORE_RULES
    for second in ("", ".SUFFIXES:", ".SUFFIXES: .x")
]


class TestErrorsOfBefore:
    """The suffix check gives no error that it did not give before this
    change, when it ran at priority 15, after RecipeValidationRule and
    ContinuationRule: the errors are those of before, less the ones that the
    suffix list as make has it rules out."""

    @pytest.mark.parametrize("check_only", [False, True])
    @pytest.mark.parametrize("config", [{}, {"fix_missing_recipe_tabs": False}])
    def test_no_error_that_was_not_given_before(self, check_only, config):
        """Every error, without its line number, is one that the formatter
        gave before this change, as often as it gave it."""
        for text in _BEFORE_CASES:
            lines = split_makefile_lines(text)
            _, errors, _ = _formatter(**config).format_lines(lines, check_only, text)
            _, before, _ = _formatter_before(**config).format_lines(
                lines, check_only, text
            )
            assert not _error_texts(errors) - _error_texts(before), text

    @pytest.mark.parametrize(
        "text",
        [
            ".env.local: # copy the example\n\tcp .env.example $@\n",
            "all: .build.stamp\n  .build.stamp:\n\ttouch $@\n",
            ".cache.d: \\\n\n\tmkdir -p $@\n",
        ],
        ids=["comment", "indented", "continued"],
    )
    def test_dotted_file_targets(self, text):
        """make builds these files with their recipes (see
        TestAgainstGnuMake.test_dotted_file_targets); like before this
        change, they get no error."""
        for check_only in (False, True):
            assert _format_messages(text, True, check_only)[0] == []

    @pytest.mark.parametrize(
        "text",
        [
            "X = 1 \\\\\n.SUFFIXES: a\\ \nall:\n\t@echo all\n",
            "X = 1 \\\\\n.SUFFIXES: .c .c\\ \nall:\n\t@echo all\n",
        ],
        ids=["no-dot", "repeated"],
    )
    def test_declaration_that_continuation_rule_rewrites(self, text):
        """'X = 1' ends with two backslashes, and the '.SUFFIXES' line with a
        backslash and a blank. ContinuationRule took both for continued
        lines and rewrote the last word of the second: the rule then
        reported 'Invalid suffix 'a'' and 'Invalid suffix '\\''. It does not
        check such a line now, so it never reports a word that it did not
        read before, such as 'a\\' or '.c\\'."""
        for check_only in (False, True):
            assert _format_messages(text, True, check_only)[0] == []

    def test_line_that_continuation_rule_indents(self):
        """'  b' ends with two backslashes, so make does not continue it (GNU
        762-769; see TestAgainstGnuMake.test_rule_that_the_check_did_not_read),
        but ContinuationRule continues it and indents '.x.o:', which the
        rule then did not check. So '.x.o' gets no error."""
        text = "X = a \\\n  b\\\\\n.x.o:\n\tcp $< $@\n"
        for check_only in (False, True):
            assert _format_messages(text, True, check_only)[0] == []

    def test_line_left_out_in_check_mode(self):
        """In check mode, RecipeValidationRule leaves out 'junk', so
        ContinuationRule took '.x.o:' for the end of the recipe line and
        indented it, and the rule did not check it: no error in check mode.
        In format mode 'junk' gets a TAB, '.x.o:' stays where it is, and
        '.x' is undeclared."""
        text = "all:\n\t@echo a \\\n  b \\\njunk\n.x.o:\n\tcp $< $@\n"
        assert _format_messages(text, True, check_only=False)[0] == [
            "5: Error: Suffix rule '.x.o' uses undeclared suffix '.x'"
        ]
        assert _format_messages(text, True, check_only=True)[0] == []


class TestFormatterMessages:
    """Through the formatter: real line numbers, one 'Error', region files."""

    TEXT = "all:\n\t@echo ok\n.KEEP_STATE:\n.SUFFIXES: .c .o\n.x.o:\n\tcp $< $@\n"

    @pytest.mark.parametrize("check_only", [False, True])
    def test_gnu_format(self, check_only):
        errors, warnings = _format_messages(self.TEXT, True, check_only)
        assert errors == ["5: Error: Suffix rule '.x.o' uses undeclared suffix '.x'"]
        assert warnings == ["3: Warning: Unknown special target '.KEEP_STATE'"]

    @pytest.mark.parametrize("check_only", [False, True])
    def test_traditional_format(self, check_only):
        """The formatter leaves an already numbered message alone, so it
        never gets a second 'Error:' or a '(line 0)'."""
        errors, warnings = _format_messages(self.TEXT, False, check_only)
        assert errors == ["Line 5: Suffix rule '.x.o' uses undeclared suffix '.x'"]
        assert warnings == ["Line 3: Unknown special target '.KEEP_STATE'"]

    @pytest.mark.parametrize("gnu_error_format", [True, False])
    def test_region_lines_are_file_lines(self, gnu_error_format):
        """Lines that '# bake-format off' hides still count: line 4 of the
        file is line 3 of what the rules see."""
        text = (
            "# bake-format off\njunk   =   1\n# bake-format on\n.KEEP_STATE:\n"
            ".q.o:\n\tcp $< $@\n"
        )
        errors, warnings = _format_messages(text, gnu_error_format)
        if gnu_error_format:
            assert errors == [
                "5: Error: Suffix rule '.q.o' uses undeclared suffix '.q'"
            ]
            assert warnings == ["4: Warning: Unknown special target '.KEEP_STATE'"]
        else:
            assert errors == ["Line 5: Suffix rule '.q.o' uses undeclared suffix '.q'"]
            assert warnings == ["Line 4: Unknown special target '.KEEP_STATE'"]

    def test_hidden_declaration_counts(self):
        """make reads the lines of a '# bake-format off' region too."""
        text = "# bake-format off\n.SUFFIXES: .x\n# bake-format on\n.x.o:\n\tcp $< $@\n"
        assert _format_messages(text) == ([], [])

    def test_issue_example_has_no_error(self):
        """'.NOTINTERMEDIATE:', a default suffix rule and a repeated
        '.POSIX:' are all valid GNU make."""
        text = ".POSIX:\n.NOTINTERMEDIATE:\n.POSIX:\n.c.o:\n\t$(CC) -c $<\n"
        assert _format_messages(text) == ([], [])

    @pytest.mark.parametrize(
        "text",
        [TEXT, ".POSIX:\n.POSIX:\n.SUFFIXES:\n.c.o:\n\tcp $< $@\n.KEEP_STATE:\n"],
    )
    def test_idempotent(self, text):
        formatter = _formatter()
        once = formatter.format(text).content
        assert formatter.format(once).content == once

    @pytest.mark.parametrize(
        "text",
        [
            "build:\n\tgcc -o prog \\\nmain.c\n.SUFFIXES: .x .o\n.x.o:\n\tcp $< $@\n",
            ".SUFFIXES: .z\\\n.w\nall:\n\t@echo all\n",
            ".SUFFIXES: .x .y\nifdef FOO\n.SUFFIXES: .z\\\n.w\nendif\n.x.y:\n"
            "\tcp $< $@\n",
        ],
        ids=["recipe", "declaration", "conditional-declaration"],
    )
    @pytest.mark.parametrize("check_only", [False, True])
    def test_lines_that_continue_at_column_0(self, text, check_only):
        """A line that continues a recipe line or a rule belongs to it (GNU
        776-781, 2910-2920), also in check mode, where RecipeValidationRule
        reports such a line and leaves it out (see the make-backed tests)."""
        assert _format_messages(text, True, check_only) == ([], [])

    @pytest.mark.parametrize("check_only", [False, True])
    def test_check_mode_numbers_the_lines_of_the_file(self, check_only):
        """The messages name the same lines in check mode as in format mode."""
        text = (
            "build:\n\tgcc -o prog \\\nmain.c util.c\n.KEEP_STATE:\n.PHONY:\n"
            ".SUFFIXES:\n.c.o:\n\tcc -c $<\n"
        )
        assert _format_messages(text, True, check_only) == (
            [
                "7: Error: Suffix rule '.c.o' uses undeclared suffix '.c'",
                "7: Error: Suffix rule '.c.o' uses undeclared suffix '.o'",
            ],
            [
                "4: Warning: Unknown special target '.KEEP_STATE'",
                "5: Warning: Special target '.PHONY' typically requires prerequisites",
            ],
        )

    def test_hidden_clear_empties_the_declared_suffixes(self):
        """make empties the list at a '.SUFFIXES:' that '# bake-format off'
        hides (GNU 8529-8536), so '.x' is not declared a second time."""
        text = (
            ".SUFFIXES: .x\n# bake-format off\n.SUFFIXES:\n# bake-format on\n"
            ".SUFFIXES: .x\nall:\n\t@echo all\n"
        )
        assert _format_messages(text) == ([], [])


class TestAgainstGnuMake:
    """The messages agree with what GNU make does with the makefile."""

    def test_repeated_posix(self, gnu_make, tmp_path):
        """Both makes accept '.POSIX:' twice, without a message."""
        text = ".POSIX:\n.POSIX:\nall:\n\t@echo ok\n"
        proc = _make(gnu_make, tmp_path, text, "-n")
        assert (proc.returncode, proc.stdout, proc.stderr) == (0, "echo ok\n", "")
        assert _format_messages(text) == ([], [])

    def test_keep_state_is_an_ordinary_target(self, gnu_make, tmp_path):
        """'.KEEP_STATE' is not the default goal (GNU 1440-1447) and runs its
        recipe when asked for, like any target."""
        text = ".KEEP_STATE:\n\t@echo keep\nall:\n\t@echo all\n"
        assert _make(gnu_make, tmp_path, text, "-n").stdout == "echo all\n"
        asked = _make(gnu_make, tmp_path, text, "-n", ".KEEP_STATE")
        assert asked.stdout == "echo keep\n"
        errors, warnings = _format_messages(text)
        assert errors == []
        assert warnings == ["1: Warning: Unknown special target '.KEEP_STATE'"]

    def test_notintermediate(self, gnu_make, tmp_path):
        """With '.NOTINTERMEDIATE:', make 4.4 keeps the intermediate file
        x.b (GNU 2279-2287); older makes, such as 3.81, have no such target."""
        if gnu_make.version < (4, 4):
            pytest.skip(".NOTINTERMEDIATE is a target of make 4.4")
        chain = "%.b: %.a\n\tcp $< $@\n%.c: %.b\n\tcp $< $@\n"
        plain = _make(gnu_make, tmp_path, chain, "-n", "x.c", touch=["x.a"])
        if "rm x.b" not in plain.stdout:
            pytest.skip("this make does not delete intermediate files")
        text = ".NOTINTERMEDIATE:\n" + chain
        kept = _make(gnu_make, tmp_path, text, "-n", "x.c", touch=["x.a"])
        assert kept.returncode == 0
        assert "rm x.b" not in kept.stdout
        assert _format_messages(text) == ([], [])

    @pytest.mark.parametrize(
        ("text", "error"),
        [
            (".c.o:\n\t@echo SUFFIX-RULE\n", False),
            (".SUFFIXES:\n.c.o:\n\t@echo SUFFIX-RULE\n", True),
            (".SUFFIXES:\n.SUFFIXES: .c .o\n.c.o:\n\t@echo SUFFIX-RULE\n", False),
            (".c.o:\n\t@echo SUFFIX-RULE\n.SUFFIXES:\n", True),
            ("ifdef NOSUF\n.SUFFIXES:\nendif\n.c.o:\n\t@echo SUFFIX-RULE\n", False),
            ("define CLEAR\n.SUFFIXES:\nendef\n.c.o:\n\t@echo SUFFIX-RULE\n", False),
            (".SUFFIXES: .c .o\n.c.o:\n\t@echo SUFFIX-RULE\n.SUFFIXES:\n", False),
            ("x .SUFFIXES:\n.c.o:\n\t@echo SUFFIX-RULE\n", False),
            (".SUFFIXES :\n.c.o:\n\t@echo SUFFIX-RULE\n", False),
            (".c.o: # c\n\t@echo SUFFIX-RULE\n.SUFFIXES:\n", False),
        ],
        ids=[
            "default",
            "cleared",
            "cleared-added",
            "cleared-below",
            "conditional-clear",
            "define-body-clear",
            "declared-above-cleared-below",
            "several-targets-clear",
            "space-clear",
            "comment-rule-cleared",
        ],
    )
    def test_default_suffix_rule(self, gnu_make, tmp_path, text, error):
        """Where make runs the suffix rule '.c.o' (GNU 8485-8498, 8521-8536),
        it gets no error, and where it gets one, make does not run it. In the
        other cases make does not run it either, and it gets no error: before
        this change the rule did not check '.c.o: # c' and had '.c' and '.o'
        declared above the rule, so it gives no error there now; and only a
        line '.SUFFIXES:' alone empties the list here, not 'x .SUFFIXES:' or
        '.SUFFIXES :' (see
        TestSuffixRules.test_only_a_plain_clear_empties_the_list)."""
        proc = _make(gnu_make, tmp_path, text, "-n", "foo.o", touch=["foo.c"])
        errors = [e for e in _suffix(text).errors if "undeclared suffix" in e]
        assert (errors != []) is error
        if SUFFIX_RULE_RAN in proc.stdout:
            assert errors == []
        if error:
            assert SUFFIX_RULE_RAN not in proc.stdout

    @pytest.mark.parametrize(
        ("text", "error"),
        [
            (".x.o:\n\t@echo SUFFIX-RULE\n", True),
            (".SUFFIXES: .x\n.x.o:\n\t@echo SUFFIX-RULE\n", False),
            (".x.o:\n\t@echo SUFFIX-RULE\n.SUFFIXES: .x\n", False),
            ("L = .x\n.SUFFIXES: $(L)\n.x.o:\n\t@echo SUFFIX-RULE\n", False),
            (".SUFFIXES: \\\n  .x\n.x.o:\n\t@echo SUFFIX-RULE\n", False),
            (".SUFFIXES: .x # .y\n.x.o:\n\t@echo SUFFIX-RULE\n", False),
            (".SUFFIXES: .x ; @echo inline\n.x.o:\n\t@echo SUFFIX-RULE\n", False),
            (".SUFFIXES : .x\n.x.o:\n\t@echo SUFFIX-RULE\n", False),
            (".SUFFIXES := .x\n.x.o:\n\t@echo SUFFIX-RULE\n", True),
            (
                "# bake-format off\n.SUFFIXES: .x\n# bake-format on\n"
                ".x.o:\n\t@echo SUFFIX-RULE\n",
                False,
            ),
            ("all:\n\t@echo ok\n  .x.o:\n\t@echo SUFFIX-RULE\n", False),
            (".x.o: \\\n\n\t@echo SUFFIX-RULE\n", False),
            (".SUFFIXES: .c # .x\n.x.o:\n\t@echo SUFFIX-RULE\n", False),
            ("all:\n\t.SUFFIXES: .x\n.x.o:\n\t@echo SUFFIX-RULE\n", False),
            (".SUFFIXES: X = .x\n.x.o:\n\t@echo SUFFIX-RULE\n", False),
            ("-include more.mk\n.x.o:\n\t@echo SUFFIX-RULE\n", True),
            ("x .SUFFIXES: .x\n.x.o:\n\t@echo SUFFIX-RULE\n", False),
            (".SUFFIXES .PHONY: .x\n.x.o:\n\t@echo SUFFIX-RULE\n", False),
            ("x \\\n.SUFFIXES: .x\n.x.o:\n\t@echo SUFFIX-RULE\n", False),
            ("private .SUFFIXES: .x\n.x.o:\n\t@echo SUFFIX-RULE\n", False),
            ("./.SUFFIXES: .x\n.x.o:\n\t@echo SUFFIX-RULE\n", False),
            ("export .SUFFIXES: .x\n.x.o:\n\t@echo SUFFIX-RULE\n", True),
            ("x .SUFFIXES: X = .x\n.x.o:\n\t@echo SUFFIX-RULE\n", True),
            ("unexport .SUFFIXES: .x\n.x.o:\n\t@echo SUFFIX-RULE\n", True),
            ("vpath .SUFFIXES: .x\n.x.o:\n\t@echo SUFFIX-RULE\n", True),
        ],
        ids=[
            "undeclared",
            "added",
            "added-below",
            "variable",
            "continued",
            "comment",
            "inline-recipe",
            "space",
            "variable-assignment",
            "region",
            "indented-rule",
            "continued-rule",
            "comment-word",
            "recipe-line",
            "target-variable",
            "include-of-nothing",
            "several-targets",
            "several-targets-phony",
            "several-targets-continued",
            "private",
            "dot-slash",
            "export",
            "several-targets-variable",
            "unexport",
            "vpath",
        ],
    )
    def test_added_suffix_rule(self, gnu_make, tmp_path, text, error):
        """Where make runs the suffix rule '.x.o', it gets no error, and
        where it gets one, make does not run it. A rule with several targets
        is one rule for each (GNU 2451-2453), make removes './' from the
        start of a file name (9722-9723), and 'export', 'unexport' and
        'vpath' start directives (10847-10913). make does not run the rule
        in the indented-rule, continued-rule, comment-word, recipe-line and
        target-variable cases either, but before this change the rule did
        not check an indented or a continued rule, and it counted '.x' from
        any line that starts with '.SUFFIXES:', so it gives no error there
        now either."""
        proc = _make(gnu_make, tmp_path, text, "-n", "qux.o", touch=["qux.x"])
        errors, _ = _format_messages(text)
        assert (errors != []) is error
        if SUFFIX_RULE_RAN in proc.stdout:
            assert errors == []
        if error:
            assert SUFFIX_RULE_RAN not in proc.stdout

    @pytest.mark.parametrize(
        ("declaration", "runs_381", "runs_44"),
        [
            ("x\\ .SUFFIXES:", True, True),
            ("x\\\t.SUFFIXES:", True, True),
            (".SUFFIXES:\xa0", True, True),
            ("x\xa0.SUFFIXES:", True, True),
            (".SUFFIXES:\x1f", True, True),
            (".SUFFIXES:\u3000", True, True),
        ],
        ids=[
            "escaped-blank",
            "escaped-tab",
            "no-break-space",
            "no-break-space-target",
            "unit-separator",
            "ideographic-space",
        ],
    )
    @pytest.mark.parametrize("rule", [".c.o:", ".c.o: # c", "  .c.o:"])
    def test_list_kept_by_unknown_shapes(
        self, gnu_make, tmp_path, declaration, runs_381, runs_44, rule
    ):
        """make reads one target 'x .SUFFIXES' for an escaped blank (GNU
        730-737) and a prerequisite for whitespace other than blanks, so it
        keeps the default list and runs '.c.o'. Before this change the rule
        gave errors for '.c.o:' alone on its line; it gives none now."""
        text = f"{declaration}\n{rule}\n\t@echo SUFFIX-RULE\n"
        proc = _make(gnu_make, tmp_path, text, "-n", "qux.o", touch=["qux.c"])
        if gnu_make.version < (3, 82):
            assert (SUFFIX_RULE_RAN in proc.stdout) is runs_381
        elif gnu_make.version >= (4, 4):
            assert (SUFFIX_RULE_RAN in proc.stdout) is runs_44
        for check_only in (False, True):
            assert _format_messages(text, True, check_only)[0] == []

    @pytest.mark.parametrize(
        ("declaration", "runs_381", "runs_44"),
        [
            ("x .SUFFIXES:\x0b.q", True, True),
            (".SUFFIXES: .q|", True, True),
            ("x .SUFFIXES: |.q", True, True),
            (".SUFFIXES: .q\\;", True, True),
            (".SUFFIXES: .q\\;.x", True, True),
            (".SUFFIXES/: .q", True, False),
            ("\ufeff.SUFFIXES: .q", False, True),
        ],
        ids=[
            "vertical-tab",
            "bar-after",
            "bar-before",
            "escaped-semicolon",
            "escaped-semicolon-word",
            "slash",
            "byte-order-mark",
        ],
    )
    @pytest.mark.parametrize("rule", [".q.o:", ".q.o: # c"])
    def test_unknown_shapes(
        self, gnu_make, tmp_path, declaration, runs_381, runs_44, rule
    ):
        """make adds '.q' where mbake cannot tell: it skips a vertical tab
        after the colon, splits '|' off a word (4.3), reads ';' after one
        backslash as the start of the recipe on its second scan (730-737,
        1499-1503), reads '.SUFFIXES/' as .SUFFIXES (make 3.81), and removes
        a byte order mark (make 4.4.1). The rule gives no error for '.q.o'."""
        text = f"{declaration}\n{rule}\n\t@echo SUFFIX-RULE\n"
        proc = _make(gnu_make, tmp_path, text, "-n", "qux.o", touch=["qux.q"])
        if gnu_make.version < (3, 82):
            assert (SUFFIX_RULE_RAN in proc.stdout) is runs_381
        elif gnu_make.version >= (4, 4):
            assert (SUFFIX_RULE_RAN in proc.stdout) is runs_44
        for check_only in (False, True):
            assert _format_messages(text, True, check_only)[0] == []

    @pytest.mark.parametrize("rule", [".c.o:", ".c.o: # c"])
    def test_last_line_ends_with_a_backslash(self, gnu_make, tmp_path, rule):
        """Without a final newline, make reads the backslash as a
        prerequisite of .SUFFIXES (GNU 757-758), keeps the default list and
        runs '.c.o'."""
        text = f"{rule}\n\t@echo SUFFIX-RULE\nx .SUFFIXES: \\"
        proc = _make(gnu_make, tmp_path, text, "-n", "qux.o", touch=["qux.c"])
        assert SUFFIX_RULE_RAN in proc.stdout
        for check_only in (False, True):
            assert _format_messages(text, True, check_only)[0] == []

    def test_double_colon(self, gnu_make, tmp_path):
        """With '.SUFFIXES::', GNU make 4.4.1 adds the prerequisites and keeps
        the list, and runs '.c.o' and '.q.o'; make 3.81 runs no suffix rule
        at all. The rule gives no error (GNU 2721-2722)."""
        text = (
            ".SUFFIXES:: .q\n.c.o:\n\t@echo SUFFIX-RULE\n.q.o:\n\t@echo SUFFIX-RULE\n"
        )
        for touch in ("qux.c", "qux.q"):
            proc = _make(gnu_make, tmp_path, text, "-n", "qux.o", touch=[touch])
            if gnu_make.version < (3, 82):
                assert SUFFIX_RULE_RAN not in proc.stdout
            elif gnu_make.version >= (4, 4):
                assert SUFFIX_RULE_RAN in proc.stdout
            (tmp_path / touch).unlink()
        assert _format_messages(text) == ([], [])

    @pytest.mark.parametrize(
        ("text", "more"),
        [
            (".SUFFIXES:\ninclude more.mk\n.c.o:\n\t@echo SUFFIX-RULE\n", None),
            (
                ".SUFFIXES:\n$(eval .SUFFIXES: .c .o)\n.c.o:\n\t@echo SUFFIX-RULE\n",
                None,
            ),
            (
                "F = $(eval .SUFFIXES: .c .o)\n.SUFFIXES:\n$(call F)\n"
                ".c.o:\n\t@echo SUFFIX-RULE\n",
                None,
            ),
        ],
        ids=["include", "eval", "call"],
    )
    def test_clear_where_make_reads_more(self, gnu_make, tmp_path, text, more):
        """An included makefile (GNU 842-843) and the text of eval (6383-6385),
        also through call (6268-6295), add '.c' and '.o' again after the
        empty '.SUFFIXES:'. make runs '.c.o', and the rule, which gave errors
        before this change, gives none."""
        (tmp_path / "more.mk").write_text(".SUFFIXES: .c .o\n", encoding="utf-8")
        proc = _make(gnu_make, tmp_path, text, "-n", "qux.o", touch=["qux.c"])
        assert SUFFIX_RULE_RAN in proc.stdout
        for check_only in (False, True):
            assert _format_messages(text, True, check_only)[0] == []

    @pytest.mark.parametrize(
        ("text", "goal"),
        [
            (".env.local: # copy the example\n\t@echo built\n", ".env.local"),
            ("all: .build.stamp\n  .build.stamp:\n\t@echo built\n", ".build.stamp"),
            (".cache.d: \\\n\n\t@echo built\n", ".cache.d"),
        ],
        ids=["comment", "indented", "continued"],
    )
    def test_dotted_file_targets(self, gnu_make, tmp_path, text, goal):
        """make builds a file whose name has two dots with its recipe; no
        error, as before this change."""
        assert _make(gnu_make, tmp_path, text, "-n", goal).stdout == "echo built\n"
        for check_only in (False, True):
            assert _format_messages(text, True, check_only)[0] == []

    @pytest.mark.parametrize(
        ("text", "check_only", "error"),
        [
            ("X = a \\\n  b\\\\\n.x.o:\n\t@echo SUFFIX-RULE\n", False, False),
            ("X = a \\\n  b\\\\\n.x.o:\n\t@echo SUFFIX-RULE\n", True, False),
            (
                "all:\n\t@echo a \\\n  b \\\njunk\n.x.o:\n\t@echo SUFFIX-RULE\n",
                False,
                True,
            ),
            (
                "all:\n\t@echo a \\\n  b \\\njunk\n.x.o:\n\t@echo SUFFIX-RULE\n",
                True,
                False,
            ),
        ],
        ids=[
            "two-backslashes-format",
            "two-backslashes-check",
            "left-out-format",
            "left-out-check",
        ],
    )
    def test_rule_that_the_check_did_not_read(
        self, gnu_make, tmp_path, text, check_only, error
    ):
        """make reads '.x.o:' as a rule of its own, and with '.x' undeclared
        it is no suffix rule (GNU 8485-8489): make builds the file '.x.o'
        with the recipe, and 'qux.o' gets no suffix rule. Before this change
        the rule did not check the line where ContinuationRule had indented
        it: after a line that ends with two backslashes, and in check mode
        after a line that RecipeValidationRule leaves out. It gives no error
        there now either (see TestErrorsOfBefore)."""
        built = _make(gnu_make, tmp_path, text, "-n", ".x.o")
        assert built.stdout.endswith("echo SUFFIX-RULE\n")
        proc = _make(gnu_make, tmp_path, text, "-n", "qux.o", touch=["qux.x"])
        assert SUFFIX_RULE_RAN not in proc.stdout
        errors = _format_messages(text, True, check_only)[0]
        assert (errors != []) is error

    @pytest.mark.parametrize("declared", [True, False])
    def test_single_suffix_rule(self, gnu_make, tmp_path, declared):
        """'.FOO:' is a single-suffix rule once '.FOO' is a suffix, and an
        ordinary target otherwise (GNU 2431-2438, 8479-8489)."""
        text = ".FOO:\n\t@echo SUFFIX-RULE\n"
        if declared:
            text = ".SUFFIXES: .FOO\n" + text
        proc = _make(gnu_make, tmp_path, text, "-n", "bar", touch=["bar.FOO"])
        assert (SUFFIX_RULE_RAN in proc.stdout) is declared
        result = _special(text)
        assert result.errors == []
        assert (result.warnings == []) is declared

    def test_special_variable_assignments(self, gnu_make, tmp_path):
        """make reads '.NAME:=value' as an assignment (GNU 4577-4579), here
        of .DEFAULT_GOAL (5093-5131), .SHELLFLAGS and another name."""
        text = (
            ".DEFAULT_GOAL:=other\n.SHELLFLAGS:=-ec\n.MYVAR:=value\n"
            "all:\n\t@echo all\nother:\n\t@echo other\n"
        )
        assert _make(gnu_make, tmp_path, text, "-n").stdout == "echo other\n"
        (tmp_path / "probe.mk").write_text(
            "probe:\n\t@echo [$(.SHELLFLAGS)] [$(.MYVAR)]\n", encoding="utf-8"
        )
        proc = _make(gnu_make, tmp_path, text, "-n", "-f", "probe.mk", "probe")
        assert proc.stdout == "echo [-ec] [value]\n"
        assert _both(text) == ([], [])

    def test_recipeprefix_assignment(self, gnu_make, tmp_path):
        """'.RECIPEPREFIX:=>' sets the recipe prefix of make 4.x (GNU
        5158-5169); make 3.81 has no .RECIPEPREFIX."""
        if gnu_make.version < (4, 0):
            pytest.skip(".RECIPEPREFIX is a variable of make 4.x")
        text = ".RECIPEPREFIX:=>\nall:\n>@echo ok\n"
        assert _make(gnu_make, tmp_path, text, "-n").stdout == "echo ok\n"
        assert _both(text) == ([], [])

    def test_ignore_without_prerequisites(self, gnu_make, tmp_path):
        """'.IGNORE:' makes make go on after every failing recipe line (GNU
        2339-2344): with a shell that always fails, both lines run."""
        false = shutil.which("false")
        if false is None:
            pytest.skip("false is not installed")
        recipe = "all:\n\tfirst\n\tsecond\n"
        assert _make(gnu_make, tmp_path, recipe, shell=false).returncode != 0
        text = ".IGNORE:\n" + recipe
        proc = _make(gnu_make, tmp_path, text, shell=false)
        assert (proc.returncode, proc.stdout) == (0, "first\nsecond\n")
        assert _both(text) == ([], [])

    def test_silent_without_prerequisites(self, gnu_make, tmp_path):
        """'.SILENT:' stops make from printing any recipe line (GNU
        2383-2388)."""
        recipe = "all:\n\tfirst\n\tsecond\n"
        assert _make(gnu_make, tmp_path, recipe).stdout == "first\nsecond\n"
        text = ".SILENT:\n" + recipe
        assert _make(gnu_make, tmp_path, text).stdout == ""
        assert _both(text) == ([], [])

    def test_default_suffixes_of_make(self, gnu_make, tmp_path):
        """Every suffix of make's own default list is a default suffix here
        (GNU 7545-7549; GNU make 4.4.1 has '.yl')."""
        proc = subprocess.run(
            [gnu_make.path, "-p", "-f", os.devnull, f"SHELL={gnu_make.true}"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            timeout=60,
            env=_MAKE_ENV,
        )
        lines = [
            line for line in proc.stdout.splitlines() if line.startswith(".SUFFIXES:")
        ]
        assert lines, proc.stdout[-2000:]
        assert set(lines[0].split()[1:]) <= DEFAULT_SUFFIXES

    def test_recipe_line_continued_at_column_0(self, gnu_make, tmp_path):
        """make reads 'main.c' as the end of the recipe line above it (GNU
        2910-2920), so '.x.o' is a suffix rule: no error in check mode."""
        text = (
            "build:\n\tgcc -o prog \\\nmain.c\n.SUFFIXES: .x .o\n.x.o:\n"
            "\t@echo SUFFIX-RULE\n"
        )
        built = _make(gnu_make, tmp_path, text, "-n", "build")
        assert built.stdout == "gcc -o prog \\\nmain.c\n"
        proc = _make(gnu_make, tmp_path, text, "-n", "g.o", touch=["g.x"])
        assert SUFFIX_RULE_RAN in proc.stdout
        for check_only in (False, True):
            assert _format_messages(text, True, check_only) == ([], [])

    @pytest.mark.parametrize(
        ("text", "suffixes"),
        [
            (".SUFFIXES: .z\\\n.w\nall:\n\t@echo all\n", [".z", ".w"]),
            (
                ".SUFFIXES: .x .y\nifdef FOO\n.SUFFIXES: .z\\\n.w\nendif\n"
                "all:\n\t@echo all\n",
                [".x", ".y"],
            ),
        ],
        ids=["declaration", "conditional-declaration"],
    )
    def test_declaration_continued_at_column_0(
        self, gnu_make, tmp_path, text, suffixes
    ):
        """make joins the continued line to the declaration (GNU 776-781):
        no 'Invalid suffix' for the line below, in either mode."""
        assert _make_suffixes(gnu_make, tmp_path, text) == suffixes
        for check_only in (False, True):
            assert _format_messages(text, True, check_only) == ([], [])

    @pytest.mark.parametrize(
        ("text", "more"),
        [
            (
                "define SETUP\n.SUFFIXES: .x .o\nendef\n$(eval $(SETUP))\n"
                ".x.o:\n\t@echo SUFFIX-RULE\n",
                None,
            ),
            (
                ".SUFFIXES:\ndefine SETUP\n.SUFFIXES: .x .o\nendef\n"
                "$(eval $(SETUP))\n.x.o:\n\t@echo SUFFIX-RULE\n",
                None,
            ),
            (
                ".SUFFIXES: .x .o\n.x.o:\n\t@echo SUFFIX-RULE\n.SUFFIXES:\n"
                "$(eval .SUFFIXES: .x .o)\n",
                None,
            ),
            (
                ".SUFFIXES: .x .o\n.x.o:\n\t@echo SUFFIX-RULE\n.SUFFIXES:\n"
                "include more.mk\n",
                ".SUFFIXES: .x .o\n",
            ),
            (
                "define SETUP\n.SUFFIXES: .x\nendef\n$(SETUP)\n"
                ".x.o:\n\t@echo SUFFIX-RULE\n",
                None,
            ),
            (".x.o: # c\n\t@echo SUFFIX-RULE\n$(eval .SUFFIXES: .x)\n", None),
            ("-include more.mk\n  .x.o:\n\t@echo SUFFIX-RULE\n", ".SUFFIXES: .x\n"),
            (
                ".SUFFIXES: .c .o # .x comes from more.mk\ninclude more.mk\n"
                ".x.o:\n\t@echo SUFFIX-RULE\n",
                ".SUFFIXES: .x\n",
            ),
        ],
        ids=[
            "define-eval",
            "cleared-define-eval",
            "cleared-eval",
            "cleared-include",
            "reference",
            "comment-rule-eval",
            "indented-rule-include",
            "named-in-comment",
        ],
    )
    def test_suffixes_that_make_reads_elsewhere(self, gnu_make, tmp_path, text, more):
        """make reads makefile text from an included makefile (GNU 842-843),
        from $(eval ...) (6383-6385) and from a reference to a one-line value
        (1231-1236), here a define body (4792-4793). The suffix rule runs, so
        it gets no error, in either mode."""
        if more is not None:
            (tmp_path / "more.mk").write_text(more, encoding="utf-8")
        proc = _make(gnu_make, tmp_path, text, "-n", "qux.o", touch=["qux.x"])
        assert SUFFIX_RULE_RAN in proc.stdout
        for check_only in (False, True):
            assert _format_messages(text, True, check_only)[0] == []

    def test_makeflags_no_builtin_rules(self, gnu_make, tmp_path):
        """With -r added to MAKEFLAGS in the makefile, GNU make 4.4.1 has no
        default suffixes (GNU 8538-8539), but make 3.81 keeps them and runs
        '.c.o', so it gets no error."""
        text = "MAKEFLAGS += -r\n.c.o:\n\t@echo SUFFIX-RULE\n"
        proc = _make(gnu_make, tmp_path, text, "-n", "foo.o", touch=["foo.c"])
        if gnu_make.version < (4, 0):
            assert SUFFIX_RULE_RAN in proc.stdout
        elif gnu_make.version >= (4, 4):
            assert SUFFIX_RULE_RAN not in proc.stdout
        assert _format_messages(text) == ([], [])

    def test_hidden_clear(self, gnu_make, tmp_path):
        """make reads the '.SUFFIXES:' that '# bake-format off' hides, which
        empties the list (GNU 8529-8536)."""
        hidden = ".SUFFIXES: .x\n# bake-format off\n.SUFFIXES:\n# bake-format on\n"
        assert _make_suffixes(gnu_make, tmp_path, hidden) == []
        text = hidden + ".SUFFIXES: .x\nall:\n\t@echo all\n"
        assert _make_suffixes(gnu_make, tmp_path, text) == [".x"]
        assert _format_messages(text) == ([], [])

    @pytest.mark.parametrize(
        "text",
        [
            _SETUP + "X := $(call eval,$(SETUP))\n" + _SUFFIX_RULE,
            _SETUP + "all: $(call eval,$(SETUP))\n" + _SUFFIX_RULE,
            _SETUP + "F := eval\nX := $(call $(F),$(SETUP))\n" + _SUFFIX_RULE,
            _SETUP + "$(call eval,$(SETUP))\n" + _SUFFIX_RULE,
            _SETUP + "X := $(call call,eval,$(SETUP))\n" + _SUFFIX_RULE,
            "define SETUP\n.SUFFIXES: \\\n  .x\nendef\nX := $(call eval,$(SETUP))\n"
            + _SUFFIX_RULE,
            "X := $(call eval,.SUFFIXES: .x)\n  " + _SUFFIX_RULE,
            "X := $(call \\\neval,.SUFFIXES: .x)\n  " + _SUFFIX_RULE,
            "X := $(call\\\n eval,.SUFFIXES: .x)\n.x.o: # c\n\t@echo SUFFIX-RULE\n",
            "all: $(call \\\neval,.SUFFIXES: .x)\n.x.o: # c\n\t@echo SUFFIX-RULE\n",
            "F := eval\nX := $(call \\\n$(F),.SUFFIXES: .x)\n.x.o: # c\n"
            "\t@echo SUFFIX-RULE\n",
            "X := $(call eval,.SUFFIXES: .x)\n" + _SUFFIX_RULE,
        ],
        ids=[
            "assignment",
            "prerequisite",
            "computed-name",
            "line",
            "call-call",
            "continued-body",
            "text-indented-rule",
            "continued-call",
            "continued-call-blanks",
            "continued-call-prerequisite",
            "continued-computed-name",
            "text-column-0-rule",
        ],
    )
    def test_eval_through_call(self, gnu_make, tmp_path, text):
        """call runs eval where its first argument names it, also by a
        reference (GNU 6289-6295), also where a backslash/newline splits the
        call, which make joins with a space (776-781), and make adds the
        suffixes of the text (6383-6385): the suffix rule runs and gets no
        error, in either mode."""
        proc = _make(gnu_make, tmp_path, text, "-n", "qux.o", touch=["qux.x"])
        assert SUFFIX_RULE_RAN in proc.stdout
        for check_only in (False, True):
            assert _format_messages(text, True, check_only)[0] == []

    @pytest.mark.parametrize(
        ("text", "touch", "runs_381", "runs_44"),
        [
            (
                "override .SUFFIXES: .x\n.x.o:\n\t@echo SUFFIX-RULE\n",
                "qux.x",
                False,
                True,
            ),
            (
                "override .SUFFIXES:\n.c.o:\n\t@echo SUFFIX-RULE\n",
                "qux.c",
                True,
                False,
            ),
        ],
        ids=["adds", "empties"],
    )
    def test_override_before_suffixes(
        self, gnu_make, tmp_path, text, touch, runs_381, runs_44
    ):
        """GNU make 4.4.1 reads 'override .SUFFIXES: ...' as a rule for the
        targets 'override' and '.SUFFIXES' (GNU 2451-2453); make 3.81 rejects
        the line ('invalid override directive'). mbake counts the suffix that
        the line adds and does not let it empty the list, so the rule gets no
        error, in either mode."""
        proc = _make(gnu_make, tmp_path, text, "-n", "qux.o", touch=[touch])
        if gnu_make.version < (3, 82):
            assert (SUFFIX_RULE_RAN in proc.stdout) is runs_381
            assert "override" in proc.stderr
        elif gnu_make.version >= (4, 4):
            assert (SUFFIX_RULE_RAN in proc.stdout) is runs_44
        for check_only in (False, True):
            assert _format_messages(text, True, check_only)[0] == []

    @pytest.mark.parametrize(
        "text",
        [
            ".RECIPEPREFIX = >\nall: ;\n\t.SUFFIXES: .x .o\n.RECIPEPREFIX =\n"
            + _SUFFIX_RULE,
            ".RECIPEPREFIX = >\nall: ;\n\tx .SUFFIXES: .x\n.RECIPEPREFIX =\n"
            + _SUFFIX_RULE,
        ],
        ids=["column-0-rule", "several-targets"],
    )
    def test_recipe_prefix_declaration(self, gnu_make, tmp_path, text):
        """With '.RECIPEPREFIX = >', make 4.x reads a line that starts with a
        TAB as makefile syntax (GNU 5158-5169), here a rule for .SUFFIXES: the
        suffix rule runs and gets no error, in either mode. make 3.81 has no
        .RECIPEPREFIX."""
        if gnu_make.version < (4, 0):
            pytest.skip(".RECIPEPREFIX is a variable of make 4.x")
        proc = _make(gnu_make, tmp_path, text, "-n", "qux.o", touch=["qux.x"])
        assert SUFFIX_RULE_RAN in proc.stdout
        for check_only in (False, True):
            assert _format_messages(text, True, check_only)[0] == []

    def test_grouped_targets(self, gnu_make, tmp_path):
        """'.SUFFIXES x &: .x' groups the targets (GNU 2499-2502), and
        .SUFFIXES gets '.x': the suffix rule runs and gets no error."""
        if gnu_make.version < (4, 3):
            pytest.skip("grouped targets are syntax of make 4.3")
        text = ".SUFFIXES x &: .x ; @true\n.x.o:\n\t@echo SUFFIX-RULE\n"
        proc = _make(gnu_make, tmp_path, text, "-n", "qux.o", touch=["qux.x"])
        assert SUFFIX_RULE_RAN in proc.stdout
        assert _format_messages(text)[0] == []

    @pytest.mark.parametrize(
        ("text", "goal"),
        [
            ("./x.o:\n\t@echo built\n", "x.o"),
            ("./config.status:\n\t@echo built\n", "config.status"),
        ],
        ids=["x.o", "config.status"],
    )
    def test_dot_slash_target(self, gnu_make, tmp_path, text, goal):
        """make removes './' from the start of a file name (GNU 9722-9723):
        './x.o' is the file 'x.o', no suffix rule, so there is no error."""
        assert _make(gnu_make, tmp_path, text, "-n", goal).stdout == "echo built\n"
        assert _format_messages(text) == ([], [])

    def test_define_body_that_nothing_evaluates(self, gnu_make, tmp_path):
        """Without an evaluation, make does not add the suffixes of a define
        body (GNU 4795-4799), so '.x.o' is no suffix rule. mbake cannot see
        every evaluation, and the rule counted the body's '.SUFFIXES:' line
        before this change too, so it gives no error (see TestDefineBodies)."""
        text = "define X\n.SUFFIXES: .x\nendef\n" + _SUFFIX_RULE
        proc = _make(gnu_make, tmp_path, text, "-n", "qux.o", touch=["qux.x"])
        assert SUFFIX_RULE_RAN not in proc.stdout
        assert _format_messages(text) == ([], [])

    @pytest.mark.parametrize(
        ("text", "words", "error"),
        [
            (
                ".SUFFIXES: w\nall:\n\t@echo all\n",
                ["w"],
                "1: Error: Invalid suffix 'w' - suffixes must start with '.'",
            ),
            (
                ".SUFFIXES: .c .o .c\nall:\n\t@echo all\n",
                [".c", ".o", ".c"],
                "1: Error: Duplicate suffix '.c' in .SUFFIXES declaration",
            ),
        ],
        ids=["no-dot", "repeated"],
    )
    def test_declaration_errors_that_make_does_not_give(
        self, gnu_make, tmp_path, text, words, error
    ):
        """The known suffixes are the prerequisites of .SUFFIXES (GNU
        8521-8527): both makes run the makefile and list the words as they
        are. mbake keeps these two errors on such a line only because
        tests/test_auto_phony_insertion.py expects them."""
        proc = _make(gnu_make, tmp_path, text, "-n")
        assert (proc.returncode, proc.stdout, proc.stderr) == (0, "echo all\n", "")
        assert _make_suffixes(gnu_make, tmp_path, text) == words
        assert _format_messages(text)[0] == [error]

    @pytest.mark.parametrize(
        ("text", "words"),
        [
            (".SUFFIXES : .z .z\nall:\n\t@echo all\n", [".z", ".z"]),
            (".SUFFIXES : w\nall:\n\t@echo all\n", ["w"]),
            (".SUFFIXES\t: .c .c\nall:\n\t@echo all\n", [".c", ".c"]),
            (".SUFFIXES: .z\\\n.z\nall:\n\t@echo all\n", [".z", ".z"]),
            (".SUFFIXES: .x\\\ny\nall:\n\t@echo all\n", [".x", "y"]),
            (".SUFFIXES: .o\\\nq .c\nall:\n\t@echo all\n", [".o", "q", ".c"]),
            (".SUFFIXES: .x\\\n  .x\nall:\n\t@echo all\n", [".x", ".x"]),
            (".SUFFIXES: .o\\\n\t.o\nall:\n\t@echo all\n", [".o", ".o"]),
            (".SUFFIXES: .c \\\n  .c\nall:\n\t@echo all\n", [".c", ".c"]),
            (".SUFFIXES: .c .c#x\nall:\n\t@echo all\n", [".c", ".c"]),
            (".SUFFIXES: .c .c;\nall:\n\t@echo all\n", [".c", ".c"]),
            (".SUFFIXES: a;\nall:\n\t@echo all\n", ["a"]),
            (
                "-include extra.mk\n.SUFFIXES : .c .o .c\nall:\n\t@echo all\n",
                [".c", ".o", ".c"],
            ),
            (".SUFFIXES: w \\\\\nall:\n\t@echo all\n", ["w", "\\\\"]),
        ],
        ids=[
            "space-repeated",
            "space-no-dot",
            "tab-repeated",
            "continued-repeated",
            "continued-no-dot",
            "continued-no-dot-2",
            "continued-indented",
            "continued-tab",
            "continued-blank",
            "comment-cut",
            "recipe-cut",
            "recipe-cut-no-dot",
            "include",
            "two-backslashes",
        ],
    )
    def test_declarations_that_are_not_checked(self, gnu_make, tmp_path, text, words):
        """make joins a continued line (GNU 776-781) and cuts the comment
        (730-737) and the inline recipe (1499-1503); it runs the makefile.
        No error, in either mode. mbake 1.4.6 did not check these lines or
        words either, except a backslash apart from the words, 'a;', and the
        words of a line that ends with two backslashes, which it took for
        words without a dot."""
        proc = _make(gnu_make, tmp_path, text, "-n")
        assert (proc.returncode, proc.stdout) == (0, "echo all\n")
        assert _make_suffixes(gnu_make, tmp_path, text) == words
        for check_only in (False, True):
            assert _format_messages(text, True, check_only) == ([], [])


class TestCli:
    """'bake format' exits 0 and prints no error for valid GNU make."""

    TEXT = ".POSIX:\n.NOTINTERMEDIATE:\n.POSIX:\n\n.c.o:\n\t$(CC) -c $<\n"

    @pytest.mark.parametrize("check", [False, True])
    def test_no_error_for_gnu_special_targets(self, tmp_path, monkeypatch, check):
        (tmp_path / "Makefile").write_text(self.TEXT, encoding="utf-8")
        (tmp_path / "bake.toml").write_text("", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        args = ["format", "--config", "bake.toml", "Makefile"]
        if check:
            args.insert(1, "--check")
        result = _runner().invoke(app, args)
        assert result.exit_code == 0, result.stdout
        assert "Error" not in result.stdout
        assert "Error" not in result.stderr
        assert (tmp_path / "Makefile").read_text(encoding="utf-8") == self.TEXT

    @pytest.mark.parametrize(
        ("setting", "expected"),
        [
            ("", "Makefile:2: Error: Suffix rule '.x.o' uses undeclared suffix '.x'"),
            (
                "gnu_error_format = false\n",
                "Error: Line 2: Suffix rule '.x.o' uses undeclared suffix '.x'",
            ),
        ],
    )
    def test_error_is_printed_once(self, tmp_path, monkeypatch, setting, expected):
        """The CLI prints the error with its line and one 'Error'."""
        (tmp_path / "Makefile").write_text(
            ".SUFFIXES: .c .o\n.x.o:\n\tcp $< $@\n", encoding="utf-8"
        )
        (tmp_path / "bake.toml").write_text(setting, encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COLUMNS", "200")  # keep Rich from wrapping the line
        result = _runner().invoke(
            app, ["format", "--config", "bake.toml", "--check", "Makefile"]
        )
        assert result.exit_code == 2
        printed = [line for line in result.stdout.splitlines() if "Error" in line]
        assert printed == [expected]

    @pytest.mark.parametrize(
        "text",
        [
            ".SUFFIXES : .z .z\nall:\n\t@echo all\n",
            ".SUFFIXES: .o\\\n\t.o\nall:\n\t@echo all\n",
        ],
        ids=["space", "continued"],
    )
    def test_stdin_writes_unchecked_declarations(self, tmp_path, monkeypatch, text):
        """'format --stdin', which bake-format.el runs, writes the makefile
        only when there is no error. make accepts both makefiles (see
        TestAgainstGnuMake.test_declarations_that_are_not_checked)."""
        (tmp_path / "bake.toml").write_text("", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        result = _runner().invoke(
            app, ["format", "--config", "bake.toml", "--stdin"], input=text
        )
        assert result.exit_code == 0
        assert result.stdout == text
        assert "Error" not in result.stderr

    @pytest.mark.parametrize(
        "text",
        [
            "x .SUFFIXES: .x\n.x.o: # c\n\t@echo ok\n",
            "X := $(call \\\neval,.SUFFIXES: .x)\n  .x.o:\n\t@echo ok\n",
            ".RECIPEPREFIX = >\nall: ;\n\t.SUFFIXES: .x .o\n.RECIPEPREFIX =\n"
            ".x.o:\n\t@echo ok\n",
            ".env.local: # copy the example\n\tcp .env.example $@\n",
            "x\\ .SUFFIXES:\n.c.o: # c\n\t@echo ok\n",
            ".SUFFIXES: .q|\n.q.o:\n\t@echo ok\n",
            ".SUFFIXES:\ninclude more.mk\n.c.o:\n\t@echo ok\n",
        ],
        ids=[
            "several-targets",
            "continued-call",
            "recipe-prefix",
            "dotted-file",
            "escaped-blank",
            "bar",
            "include",
        ],
    )
    def test_stdin_writes_makefiles_whose_suffix_rules_run(
        self, tmp_path, monkeypatch, text
    ):
        """'format --stdin' writes these makefiles: make runs their suffix
        rules or builds the file, in the include case with a more.mk that
        declares '.c' and '.o' (see TestAgainstGnuMake)."""
        (tmp_path / "bake.toml").write_text("", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        result = _runner().invoke(
            app, ["format", "--config", "bake.toml", "--stdin"], input=text
        )
        assert result.exit_code == 0
        assert result.stdout == text
        assert "Error" not in result.stderr

    def test_warning_names_the_line(self, tmp_path, monkeypatch):
        (tmp_path / "Makefile").write_text(
            "all:\n\t@echo ok\n.KEEP_STATE:\n", encoding="utf-8"
        )
        (tmp_path / "bake.toml").write_text("", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("COLUMNS", "200")
        result = _runner().invoke(
            app, ["format", "--config", "bake.toml", "--check", "Makefile"]
        )
        assert "Makefile:3: Warning: Unknown special target '.KEEP_STATE'" in (
            result.stdout
        )
        assert "Error" not in result.stdout

    @pytest.mark.parametrize(
        ("setting", "expected"),
        [
            ("", "2: Error: Suffix rule '.x.o' uses undeclared suffix '.x'"),
            (
                "gnu_error_format = false\n",
                "Error: Line 2: Suffix rule '.x.o' uses undeclared suffix '.x'",
            ),
        ],
    )
    def test_stdin_error_is_printed_once(
        self, tmp_path, monkeypatch, setting, expected
    ):
        """'format --stdin', which bake-format.el runs, prints each error with
        its line and one 'Error'."""
        (tmp_path / "bake.toml").write_text(setting, encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        result = _runner().invoke(
            app,
            ["format", "--config", "bake.toml", "--stdin"],
            input=".SUFFIXES: .c .o\n.x.o:\n\tcp $< $@\n",
        )
        assert result.exit_code == 2
        assert result.stdout == ""
        assert result.stderr.splitlines() == [expected]
