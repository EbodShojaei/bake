"""Suffix rule validation and formatting rule for Makefiles.

Line numbers refer to the GNU make 4.4.1 manual. The known suffixes are the
prerequisites of the special target .SUFFIXES (10.7, lines 8521-8527). The
list starts as the default list (10.2, lines 7545-7549); a rule for .SUFFIXES
with prerequisites adds them, and one without prerequisites empties the list
(lines 8529-8536). A rule whose target is a known suffix, or two known
suffixes one after the other, is a suffix rule (lines 8485-8489). make finds
the suffix rules once it has read the whole makefile, so a rule '.x.o:' above
'.SUFFIXES: .x' is a suffix rule, and a rule '.c.o:' above an empty
'.SUFFIXES:' is not.

The rule reports no error that it did not report before it read the suffix
list as make does, when it ran after RecipeValidationRule and ContinuationRule
(priority 15). It only removes such errors:
- A suffix rule is checked only where the rule checked one before: a line
  that starts with the target and a colon, with nothing but blanks after the
  colon. An error is kept only for a suffix that the rule found undeclared
  there, from the suffixes that the lines above named after '.SUFFIXES:'
  (see _errors_before).
- make must read the line as a rule of its own: not a line that continues
  another one (3.1.1, lines 776-781), not a line of a define body (6.8, lines
  4795-4799), not a recipe line, and with one target and no prerequisite (a
  suffix rule with prerequisites is an ordinary target, lines 8500-8502).
- The suffix must be missing from every suffix list that make may have once
  it has read the makefile (see suffix_list). Where that list is not known
  here, no suffix rule gets an error.

The checks of the words of a rule for .SUFFIXES ('Invalid suffix',
'Duplicate suffix', 'already declared', 'Unusual suffix' and 'Complex
suffix') read only a line that starts with '.SUFFIXES:' and does not end
with a backslash, and of its words only those that make reads as
prerequisites as they stand (see checked_words): lines and words that the
rule checked before too. GNU make 3.81 and 4.4.1 accept a suffix without a
dot and a repeated suffix; the two errors stay only because existing tests
expect them.
"""

import re
from collections.abc import Collection, Mapping, Sequence
from typing import Any, NamedTuple, Optional

from ...constants.makefile_targets import DEFAULT_SUFFIXES
from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.line_utils import LineUtils
from ...utils.rule_context import (
    DIRECTIVE,
    FUNCTION_CALL,
    OTHER,
    RECIPE,
    RULE,
    LineState,
    scan_makefile,
)
from .continuation import ContinuationRule
from .recipe_validation import RecipeValidationRule

# The suffix rule line that the rule checked before, and its target: a line
# whose stripped text is a target with two dots, a colon and blanks only
_RULE_BEFORE = re.compile(r"^\.[^:]+\.\w+:\s*$")
_TARGET_BEFORE = re.compile(r"^(\.[^:]+\.\w+):")

# A suffix rule as make reads it: one target that starts with a dot and holds
# no character that make reads in a special way in a file name (a blank, a
# reference, a pattern, a wildcard, an escape), then the colon and nothing but
# blanks. make removes './' from the start of a file name (GNU make manual
# lines 9722-9723), so './x.o' is the file 'x.o', no suffix rule.
_SUFFIX_RULE = re.compile(r"\.(?!/)[^\s:$%*?\[\\]+\.\w+:[ \t]*\Z")

# A rule for .SUFFIXES that empties the list wherever make reads it: alone on
# its line, at its start, with one colon and only blanks after it
_PLAIN_CLEAR = re.compile(r"\.SUFFIXES:[ \t]*\Z")

# Characters on a line that names .SUFFIXES that make may read otherwise than
# this rule reads them, so that the suffixes that the line adds are not known
# here: a backslash, which escapes a blank or a ';' for make (3.1, lines
# 730-737; 4.2, lines 1499-1503), '|', which starts the order-only
# prerequisites (4.3) wherever it is in a word, a byte order mark, which
# make 4.4.1 removes at the start of a makefile, and whitespace other than
# blanks, which make reads as part of a word, or skips after a colon where
# it stands for a vertical tab, a form feed or a carriage return (see
# protect_line_breaks)
_UNKNOWN_SHAPE = re.compile(r"[\\|\ufeff\ufdd0-\ufdef]|[^\S \t]")

# Characters in a prerequisite of .SUFFIXES that make expands: a reference
# (6.1, lines 4117-4121) and wildcards (4.4)
_EXPANDED = re.compile(r"[$*?\[]")

# The directives with which make reads makefile text that the lines do not
# hold: other makefiles (GNU make manual 3.3, lines 842-843), and loaded
# objects, which may evaluate text (12.2.3, lines 9128-9131)
_READING_DIRECTIVES = frozenset({"include", "-include", "sinclude", "load", "-load"})

# The directives that GNU make 3.81 does not have, so that it reads a line
# that starts with one as a rule (see .FEATURES, GNU make manual lines
# 5215-5217 and 5251-5252)
_DIRECTIVES_SINCE_3_81 = frozenset({"undefine", "load", "-load"})

# Text with which make may read makefile text that the lines do not hold:
# eval (8.10, lines 6383-6385), call, which runs eval where its first
# argument names it (8.8, lines 6289-6295), guile, whose gmk-eval evaluates
# text (12.1, lines 8848-8852 and 8931-8936), and MAKEFILES, the makefiles
# that make reads first (3.4, lines 938-942)
_READS_MORE = re.compile(r"\$[({](?:eval|call|guile)\b|\bMAKEFILES\b")

# An option '-f', which names a makefile to read (9.8, lines 7174-7175), in
# the value of MAKEFLAGS
_FILE_OPTION = re.compile(r"(?:^|[\s=])-[A-Za-z]*f|--(?:make)?file\b")

# The kinds of lines that are only references, or no makefile syntax, which
# make may expand to a rule (GNU make manual 3.8, lines 1221-1236)
_MAY_EXPAND_TO_RULE = frozenset({FUNCTION_CALL, OTHER})

# The './' that make removes from the start of a file name, with the slashes
# after it (GNU make manual lines 9722-9723)
_DOT_SLASH = re.compile(r"\A(?:\./+)+")

# A rule for .SUFFIXES named in any text, and a word after it that starts
# with a dot, as eval or an included makefile may read it
_NAMED_RULE = re.compile(r"\.SUFFIXES[ \t]*&?::?")
_NAMED_WORD = re.compile(r"\.[^\s$(){},;:#|=\\'\"]+")

# A word, as str.split() finds them
_WORD = re.compile(r"\S+")


class RuleLine(NamedTuple):
    """A logical line that make reads as a rule."""

    # The index of its first line among the lines that the rules see, or None
    # for a line that '# bake-format off' hides
    line_index: Optional[int]
    # The logical line (GNU make manual 3.1.1, lines 776-781)
    text: str
    # True inside a conditional, where make may skip it (7.2)
    conditional: bool


class MakefileReading(NamedTuple):
    """How make reads a makefile, as far as the two validation rules need."""

    # The lines that the rules see, with the lines that '# bake-format off'
    # regions hide in their place
    merged: list[str]
    # For each of merged, its index among the lines that the rules see, or
    # None for a hidden line
    visible: list[Optional[int]]
    # scan_makefile of merged
    states: list[LineState]
    # The logical lines that make reads as rules, and only as rules, from the
    # top
    rules: list[RuleLine]


class _UnknownList(Exception):
    """The suffix list that make has cannot be known from the lines."""


def read_makefile(
    lines: Sequence[str], hidden: Mapping[int, Sequence[str]]
) -> MakefileReading:
    """
    Read the lines as make reads them.

    rule_context.scan_makefile classifies each logical line, so an
    assignment that LineUtils.parse_variable_assignment reads, such as
    '.DEFAULT_GOAL:=all', is no rule (GNU make manual 6.5, lines 4577-4579),
    nor is a target-specific variable (6.11, lines 4938-4951). The lines that
    '# bake-format off' regions hide are read in place, as make reads them.
    Recipe lines and define bodies are no rules: make passes a recipe line to
    the shell (3.1, lines 744-746) and keeps a define body as the value of a
    variable (6.8, lines 4795-4799).

    Args:
        lines: The lines that the rules see
        hidden: context['disabled_region_lines'], or {} without context

    Returns:
        The lines with the hidden ones in place, their scan, and the rules
    """
    merged: list[str] = []
    visible: list[Optional[int]] = []
    for index, line in enumerate(lines):
        merged.append(line)
        visible.append(index)
        for hidden_line in hidden.get(index, ()):
            merged.append(hidden_line)
            visible.append(None)
    states = scan_makefile(merged, {})
    rules = [
        RuleLine(visible[index], state.text, state.depth > 0)
        for index, state in enumerate(states)
        if _only_rule(state)
    ]
    return MakefileReading(merged, visible, states, rules)


def _only_rule(state: LineState) -> bool:
    """Check if make reads the first line of a logical line only as a rule."""
    return (
        not state.continuation
        and not state.may_be_define_body
        and state.kind == RULE
        and RECIPE not in state.readings
    )


def suffix_list(reading: MakefileReading) -> Optional[frozenset[str]]:
    """
    Return every suffix that may be on the suffix list once make has read it.

    The list starts as the default list (GNU make manual 10.2, lines
    7545-7549), and every line that GNU make 3.81 or 4.x may read as a rule
    for .SUFFIXES adds its prerequisites (10.7, lines 8521-8527): a logical
    line (3.1.1, lines 776-781) cut at its comment (3.1, lines 730-737) and
    at the ';' of an inline recipe (4.2, lines 1488 and 1499-1503), whose
    targets include .SUFFIXES, also with other targets (4.10, lines 2451-2453
    and 2499-2502), after './' (lines 9722-9723) or with '::' (4.13), and a
    line of a define body, which make reads wherever the makefile evaluates
    the body (6.8, lines 4790-4793). Where make may read makefile text that
    the lines do not hold (see _reads_more), so do the words after
    '.SUFFIXES' and a colon on any line, such as the text of eval.

    Only a line that is '.SUFFIXES:' and blanks (lines 8529-8536) empties the
    list, outside conditionals, define bodies and continued lines, in a
    makefile that reads no other makefile text: GNU make 3.81 and 4.4.1 both
    empty the list there. Every other rule for .SUFFIXES without
    prerequisites leaves the list as it is here, so that the list holds every
    suffix that make may know: make may skip a conditional (7.2), and with
    '.SUFFIXES::' GNU make 4.4.1 keeps the list, where make 3.81 uses no
    suffix rule at all.

    Args:
        reading: read_makefile of the lines

    Returns:
        The suffixes, or None where a line that names .SUFFIXES may add
        suffixes that are not known here: a prerequisite that make expands,
        such as a variable reference (6.1, lines 4117-4121), or a line whose
        shape make may read otherwise than this rule (see _UNKNOWN_SHAPE)
    """
    merged, states = reading.merged, reading.states
    if not any(".SUFFIXES" in line for line in merged):
        return frozenset(DEFAULT_SUFFIXES)
    try:
        reads_more = _reads_more(merged, states)
        suffixes = set(DEFAULT_SUFFIXES)
        named: set[str] = set()
        for index, state in enumerate(states):
            if state.continuation:
                continue
            text, end = _logical_line(merged, index, state)
            if text is None:
                continue
            code = _code(text)
            if ".SUFFIXES" not in code:
                continue
            if _UNKNOWN_SHAPE.search(code) or (
                end == len(merged) and merged[-1].endswith("\\")
            ):
                # A backslash on the last line of a makefile without a final
                # newline is a prerequisite for make (3.1.1, lines 757-758)
                raise _UnknownList
            if state.may_be_define_body:
                named.update(_prerequisites(code) or ())
                continue
            if not _may_be_rule(state):
                continue
            words = _prerequisites(code)
            if words:
                suffixes.update(words)
            elif (
                words is not None
                and not reads_more
                and _only_rule(state)
                and state.depth == 0
                and end == index + 1
                and _PLAIN_CLEAR.match(merged[index])
            ):
                suffixes.clear()
        if reads_more:
            for line in merged:
                named.update(_named_suffixes(line))
    except _UnknownList:
        return None
    return frozenset(suffixes | named)


def _logical_line(
    merged: Sequence[str], index: int, state: LineState
) -> tuple[Optional[str], int]:
    """
    Return the logical line that starts at merged[index] as makefile syntax.

    Args:
        merged: MakefileReading.merged
        index: The index of the first line of the logical line
        state: Its LineState

    Returns:
        The logical line and the index of the line after it; None for the
        line where make reads it only as a recipe line, which it passes to
        the shell (GNU make manual 3.1, lines 744-746)
    """
    end = index + 1
    while end < len(merged) and LineUtils.ends_with_continuation(merged[end - 1]):
        end += 1
    if state.kind == RECIPE and not state.readings - {RECIPE}:
        return None, end
    if state.kind == RECIPE:
        # A line that one GNU make reads as a recipe line and the other as
        # makefile syntax (see LineState.readings), joined as such
        return LineUtils.join_logical_line(merged, index)[0], end
    return state.text, end


def _may_be_rule(state: LineState) -> bool:
    """
    Check if GNU make 3.81 or 4.x may read a logical line as a rule.

    That is a line that one of them reads as a recipe line and the other as
    a rule (see LineState.readings), and a line that starts with a directive
    that make 3.81 does not have (see _DIRECTIVES_SINCE_3_81).

    Args:
        state: The LineState of the first line of the logical line
    """
    if state.kind == RULE or RULE in state.readings:
        return True
    return (
        state.kind == DIRECTIVE
        and LineUtils.directive_word(_code(state.text)) in _DIRECTIVES_SINCE_3_81
    )


def _prerequisites(code: str) -> Optional[list[str]]:
    """
    Read a logical line, cut at its comment, as a rule for .SUFFIXES.

    The targets are the words before the first ':' (GNU make manual 4.2,
    lines 1488-1497), or before the '&:' that groups them (4.10, lines
    2499-2502), with './' removed from their start (lines 9722-9723). The
    prerequisites end at the ';' that starts an inline recipe (lines
    1499-1503).

    Args:
        code: The logical line, cut at its comment

    Returns:
        The prerequisites, or None if the targets do not include .SUFFIXES

    Raises:
        _UnknownList: For a target that names .SUFFIXES otherwise, such as
            '.SUFFIXES/', which make 3.81 reads as .SUFFIXES; for a second
            colon after '::', or a '=' after the colon, which may make the
            line an assignment for one GNU make and a rule for the other; for
            a colon among the prerequisites, which makes a static pattern
            rule (4.12); and for a prerequisite that make expands
    """
    colon = LineUtils.find_unquoted_char(code, ":")
    if colon is None:
        return None
    head = code[:colon]
    if head.endswith("&"):
        head = head[:-1]
    targets = [_DOT_SLASH.sub("", word, count=1) for word in head.split()]
    if any(".SUFFIXES" in target and target != ".SUFFIXES" for target in targets):
        raise _UnknownList
    if ".SUFFIXES" not in targets:
        return None
    rest = code[colon + 1 :]
    if rest.startswith(":"):
        rest = rest[1:]
    if rest.startswith((":", "=")):
        raise _UnknownList
    semicolon = LineUtils.find_unquoted_char(rest, ";")
    if semicolon is not None:
        rest = rest[:semicolon]
    words = rest.split()
    if LineUtils.find_unquoted_char(rest, ":") is not None or any(
        _EXPANDED.search(word) for word in words
    ):
        raise _UnknownList
    return words


def _named_suffixes(line: str) -> list[str]:
    """
    Return the suffixes that a line names after '.SUFFIXES' and a colon.

    That is text that make may read as makefile syntax where the makefile
    reads more text, such as '$(eval .SUFFIXES: .x)' (GNU make manual 8.10,
    lines 6383-6385). Every word after the colon that starts with a dot
    counts, also in a comment.

    Raises:
        _UnknownList: For a reference after the colon, which may stand for
            any suffix (6.1, lines 4117-4121)
    """
    named: list[str] = []
    for match in _NAMED_RULE.finditer(line):
        rest = line[match.end() :]
        if "$" in rest:
            raise _UnknownList
        named.extend(_NAMED_WORD.findall(rest))
    return named


def _reads_more(merged: Sequence[str], states: Sequence[LineState]) -> bool:
    """
    Check if make may read makefile text that the lines do not hold.

    That is the text of the makefiles that an include, MAKEFILES or an option
    '-f' in MAKEFLAGS names (GNU make manual 3.3, lines 842-843; 3.4, lines
    938-942; 9.8, lines 7174-7175), the text of eval, also through call or
    guile (8.10, lines 6383-6385; 8.8, lines 6289-6295; 12.1, lines
    8931-8936), the text that a loaded object evaluates (12.2.3, lines
    9128-9131), and the rule that a reference expands to (3.8, lines
    1221-1236): on a line that is only references, or no makefile syntax, in
    the targets of a rule, and before '.SUFFIXES' on any line.

    Args:
        merged: MakefileReading.merged
        states: MakefileReading.states
    """
    for line in merged:
        if _READS_MORE.search(line):
            return True
        if "MAKEFLAGS" in line and _FILE_OPTION.search(line):
            return True
        reference = line.find("$")
        if reference != -1 and ".SUFFIXES" in line[reference:]:
            return True
    for state in states:
        if state.continuation:
            continue
        if _READS_MORE.search(state.text):
            # A call that a backslash/newline splits (3.1.1, lines 776-781)
            return True
        kinds = state.readings | {state.kind}
        if kinds & _MAY_EXPAND_TO_RULE:
            return True
        code = _code(state.text)
        if DIRECTIVE in kinds and LineUtils.directive_word(code) in _READING_DIRECTIVES:
            return True
        if RULE in kinds:
            colon = LineUtils.find_unquoted_char(code, ":")
            if colon is not None and "$" in code[:colon]:
                return True
    return False


def _code(text: str) -> str:
    """Return a logical makefile line cut at its comment (GNU 730-737)."""
    comment = LineUtils.find_comment_start(text)
    return text if comment is None else text[:comment]


def _plain_clear(reading: MakefileReading, index: int) -> bool:
    """
    Check if merged[index] is a rule for .SUFFIXES that empties the list.

    That is a line '.SUFFIXES:' and blanks that make reads only as a rule,
    outside conditionals (see suffix_list).
    """
    state = reading.states[index]
    return (
        _only_rule(state)
        and state.depth == 0
        and _PLAIN_CLEAR.match(reading.merged[index]) is not None
    )


def checked_words(line: str) -> Optional[list[str]]:
    """
    Return the words of a rule for .SUFFIXES that its checks read.

    The checks read only a line that starts with '.SUFFIXES:', so a line
    with a blank before the colon is not checked, and that does not end
    with a backslash, also before trailing whitespace: with an odd number
    of them and nothing after them the line continues (GNU make manual
    3.1.1, lines 762-769 and 776-781), and the rule read the other such
    lines only after ContinuationRule, which takes them for continued
    lines and rewrites their last word. They read the words after the
    colon that make reads as prerequisites as they stand: not a second ':'
    (4.13, lines 2721-2722), a word of the comment (3.1, lines 730-737) or
    of the inline recipe (4.2, lines 1499-1503), or a word that one of
    these cuts.

    Args:
        line: The physical line of a rule for .SUFFIXES

    Returns:
        The words, from the left, or None for a line that is not checked
    """
    if not line.strip().startswith(".SUFFIXES:") or line.rstrip().endswith("\\"):
        return None
    after_colon = line.index(":") + 1
    start = after_colon + 1 if line.startswith(":", after_colon) else after_colon
    end = LineUtils.find_comment_start(line)
    if end is None:
        end = len(line)
    semicolon = LineUtils.find_unquoted_char(line[:end], ";", start)
    if semicolon is not None:
        end = semicolon
    return [
        word.group()
        for word in _WORD.finditer(line, after_colon)
        if word.start() >= start and word.end() <= end
    ]


def is_suffix_rule_target(target: str, suffixes: Collection[str]) -> bool:
    """
    Check if a rule for target is a suffix rule.

    Its target is a known suffix, or two known suffixes one after the other
    (GNU make manual 10.7, lines 8485-8489).

    Args:
        target: The target of the rule
        suffixes: The known suffixes
    """
    return target in suffixes or any(
        target.startswith(suffix) and target[len(suffix) :] in suffixes
        for suffix in suffixes
        if len(suffix) < len(target)
    )


def _lines_read_before(
    lines: list[str],
    config: dict,
    check_mode: bool,
    hidden: Mapping[int, list[str]],
) -> tuple[list[str], list[int]]:
    """
    Return the lines as the rule read them before, at priority 15.

    It ran after RecipeValidationRule (priority 8), which adds a TAB to the
    lines that it reports in format mode and leaves them out in check mode,
    and after ContinuationRule (priority 9), which indents the lines that
    follow a line that ends with a backslash and puts a blank before such a
    backslash. TabsRule (priority 10) also ran before it, but it changes
    only lines that start with a blank, and only their leading blanks, which
    the rule stripped.

    Args:
        lines: The lines that the rule sees
        config: The rule's configuration
        check_mode: True in check mode
        hidden: context['disabled_region_lines'], or {}

    Returns:
        The lines, and for each of them its index among lines
    """
    if not any(line.rstrip().endswith("\\") for line in lines):
        # ContinuationRule changes nothing, and RecipeValidationRule only
        # changes or leaves out lines without a ':', which the rule never read
        return list(lines), list(range(len(lines)))
    recipe_rule = RecipeValidationRule()
    facts = recipe_rule.line_facts(lines, hidden)
    fix = config.get("fix_missing_recipe_tabs", True)
    read: list[str] = []
    indexes: list[int] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        # Only a line that starts with neither a TAB nor a space and holds
        # text without a ':' or a '=' may be reported (see
        # RecipeValidationRule.is_missing_recipe_tab)
        if (
            stripped
            and not stripped.startswith("#")
            and not line.startswith(("\t", " "))
            and ":" not in stripped
            and "=" not in stripped
            and recipe_rule.is_missing_recipe_tab(
                line,
                index,
                lines,
                LineUtils.get_active_recipe_prefix(lines, index),
                facts,
            )
        ):
            if check_mode:
                continue
            if fix:
                line = "\t" + line.lstrip(" \t")
        read.append(line)
        indexes.append(index)
    return ContinuationRule().format(read, config).lines, indexes


def _errors_before(
    read: list[str], indexes: list[int]
) -> list[tuple[int, str, list[str]]]:
    """
    Return the suffix rules that the rule reported before, with the suffixes.

    It checked a line whose stripped text is a target with two dots, a colon
    and blanks, if the line starts with the target, against the suffixes that
    the lines above named after '.SUFFIXES:' and that start with a dot.

    Args:
        read: The lines as _lines_read_before returns them
        indexes: Their indexes among the lines that the rule sees

    Returns:
        For each rule with an undeclared suffix, its index, its target and
        those suffixes
    """
    declared: set[str] = set()
    found: list[tuple[int, str, list[str]]] = []
    for position, line in enumerate(read):
        stripped = line.strip()
        if stripped.startswith(".SUFFIXES:"):
            content = line[line.find(":") + 1 :].strip()
            declared.update(word for word in content.split() if word.startswith("."))
        elif _RULE_BEFORE.match(stripped):
            match = _TARGET_BEFORE.match(line)
            if match is None:
                continue
            target = match.group(1)
            parts = target.split(".")
            if len(parts) != 3:
                continue
            missing = [
                suffix
                for suffix in ("." + parts[1], "." + parts[2])
                if suffix not in declared
            ]
            if missing:
                found.append((indexes[position], target, missing))
    return found


class SuffixValidationRule(FormatterPlugin):
    """Validates and formats suffix rules and .SUFFIXES declarations."""

    def __init__(self) -> None:
        # Before RecipeValidationRule (priority 8), which leaves out the
        # lines it reports in check mode: this rule reads the lines as make
        # reads them, by their own numbers, in both modes
        super().__init__("suffix_validation", priority=7)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Validate suffix rules and .SUFFIXES declarations."""
        errors: list[tuple[int, str]] = []
        warnings: list[tuple[int, str]] = []

        declares = any(line.strip().startswith(".SUFFIXES:") for line in lines)
        checks_rules = any(
            _TARGET_BEFORE.match(line) and _RULE_BEFORE.match(line.strip())
            for line in lines
        )
        if declares or checks_rules:
            hidden = context.get("disabled_region_lines") or {}
            found: list[tuple[int, str, list[str]]] = []
            if checks_rules:
                found = _errors_before(
                    *_lines_read_before(list(lines), config, check_mode, hidden)
                )
            if declares or found:
                reading = read_makefile(lines, hidden)
                if declares:
                    self._check_declarations(lines, reading, errors, warnings)
                if found:
                    errors.extend(self._suffix_rule_errors(lines, reading, found))

        # The messages of each line, from the top
        errors.sort(key=lambda message: message[0])
        warnings.sort(key=lambda message: message[0])
        return FormatResult(
            lines=list(lines),
            changed=False,
            errors=[
                LineUtils.format_error_message(error, index + 1, config)
                for index, error in errors
            ],
            warnings=[
                LineUtils.format_error_message(warning, index + 1, config, "Warning")
                for index, warning in warnings
            ],
            check_messages=[],
        )

    def _check_declarations(
        self,
        lines: list[str],
        reading: MakefileReading,
        errors: list[tuple[int, str]],
        warnings: list[tuple[int, str]],
    ) -> None:
        """
        Check the words of the rules for .SUFFIXES (see checked_words).

        'already declared' names a suffix of a checked line above, since the
        list was last emptied, also by a line that '# bake-format off' hides.
        """
        declared: set[str] = set()
        for index, line_index in enumerate(reading.visible):
            if _plain_clear(reading, index):
                declared.clear()
            if line_index is None or not _only_rule(reading.states[index]):
                continue
            words = checked_words(lines[line_index])
            if words is None:
                continue
            line_errors, line_warnings = self._validate_suffixes_declaration(
                words, declared
            )
            errors.extend((line_index, error) for error in line_errors)
            warnings.extend((line_index, warning) for warning in line_warnings)
            declared.update(
                word for word in words if word.startswith(".") and "$" not in word
            )

    def _suffix_rule_errors(
        self,
        lines: list[str],
        reading: MakefileReading,
        found: list[tuple[int, str, list[str]]],
    ) -> list[tuple[int, str]]:
        """
        Keep the errors of _errors_before that make's suffix list confirms.

        A rule keeps them where make reads its line as a suffix rule of its
        own (see _SUFFIX_RULE) and no suffix list that make may have holds
        the suffix (see suffix_list).
        """
        suffixes = suffix_list(reading)
        if suffixes is None:
            return []
        merged_index = {
            line_index: index
            for index, line_index in enumerate(reading.visible)
            if line_index is not None
        }
        errors: list[tuple[int, str]] = []
        for line_index, target, missing in found:
            state = reading.states[merged_index[line_index]]
            if (
                not _only_rule(state)
                or not _SUFFIX_RULE.match(lines[line_index])
                or is_suffix_rule_target(target, suffixes)
            ):
                continue
            errors.extend(
                (
                    line_index,
                    f"Suffix rule '{target}' uses undeclared suffix '{suffix}'",
                )
                for suffix in missing
                if suffix not in suffixes
            )
        return errors

    def _validate_suffixes_declaration(
        self, words: list[str], declared_suffixes: set[str]
    ) -> tuple[list[str], list[str]]:
        """Validate the suffixes of a .SUFFIXES declaration."""
        errors: list[str] = []
        warnings: list[str] = []
        new_suffixes: dict[str, None] = {}

        for suffix in words:
            # The suffixes that a variable reference stands for are not
            # known here (GNU make manual 6.1, lines 4117-4121)
            if "$" in suffix:
                continue

            # Validate suffix format
            if not suffix.startswith("."):
                errors.append(
                    f"Invalid suffix '{suffix}' - suffixes must start with '.'"
                )
                continue

            # Check for duplicate declarations
            if suffix in declared_suffixes:
                warnings.append(
                    f"Suffix '{suffix}' is already declared in previous .SUFFIXES statement"
                )

            # Check for duplicates within this declaration
            if suffix in new_suffixes:
                errors.append(f"Duplicate suffix '{suffix}' in .SUFFIXES declaration")

            new_suffixes[suffix] = None

        # Check for unusual suffix patterns, in the order of the declaration
        for suffix in new_suffixes:
            if len(suffix) < 2:  # Just "." or very short
                warnings.append(
                    f"Unusual suffix '{suffix}' - consider if this is intentional"
                )
            elif suffix.count(".") > 1:  # Multiple dots like ".tar.gz"
                warnings.append(
                    f"Complex suffix '{suffix}' - ensure this is supported by your Make version"
                )

        return errors, warnings
