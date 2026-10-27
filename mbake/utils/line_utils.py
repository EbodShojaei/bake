"""Utility functions for line processing in Makefile formatting."""

import re
from collections.abc import Collection, Container, Mapping, Sequence
from typing import Any, Callable, NamedTuple, Optional, Union

from ..constants.makefile_targets import ALL_SPECIAL_MAKE_TARGETS
from ..constants.shell_commands import (
    FILE_CREATING_COMMANDS,
    NON_FILE_CREATING_COMMANDS,
    SHELL_COMMAND_INDICATORS,
)

# The characters other than a newline at which str.splitlines() ends a line.
# GNU make ends a line only at a newline (GNU make manual 3.1.1, lines 757-758
# and 766-769) and reads all of them as part of the line. make 3.81 and 4.4.1
# read CR, VT and FF as whitespace only in some places, such as before a
# directive or an assignment; elsewhere they are data, such as in make 3.81's
# target names and at the end of a value or a recipe line. FS, GS, RS, NEL,
# LS and PS are never whitespace to make (they are not whitespace in the C
# locale, and NEL, LS and PS are bytes of UTF-8 sequences to make).
_WHITESPACE_BREAKS = "\r\x0b\x0c"
_DATA_BREAKS = "\x1c\x1d\x1e\x85\N{LINE SEPARATOR}\N{PARAGRAPH SEPARATOR}"
_SPLITLINES_BREAKS = _WHITESPACE_BREAKS + _DATA_BREAKS
_SPLITLINES_BREAK_PATTERN = re.compile(f"[{_SPLITLINES_BREAKS}]")
_WHITESPACE_BREAK_PATTERN = re.compile(f"[{_WHITESPACE_BREAKS}]")

# Stand-ins for those characters while the formatting rules run, one for each,
# in the same order. They are Unicode noncharacters, which Unicode reserves
# for a program's internal use, and str.isspace() is False for them.
_STAND_INS = "".join(chr(0xFDD0 + index) for index in range(len(_SPLITLINES_BREAKS)))
_TO_STAND_INS = str.maketrans(_SPLITLINES_BREAKS, _STAND_INS)
_FROM_STAND_INS = str.maketrans(_STAND_INS, _SPLITLINES_BREAKS)


def _holds_stand_in(text: str) -> bool:
    """Check if text holds one of the stand-ins of protect_line_breaks()."""
    return any(stand_in in text for stand_in in _STAND_INS)


def _physical_line_pieces(text: str) -> tuple[list[str], str]:
    """Split text at its line endings as GNU make does.

    Returns the lines that end with a line ending, without it, and the text
    after the last line ending. A carriage return right before a newline is
    part of the line ending: make 3.81 and 4.4.1 drop it. Text that has no
    newline but ends with a carriage return (classic Mac line endings) ends
    its lines at each carriage return.
    """
    if "\n" in text:
        pieces = text.split("\n")
        rest = pieces.pop()
        return [piece[:-1] if piece.endswith("\r") else piece for piece in pieces], rest
    if text.endswith("\r"):
        pieces = text.split("\r")
        rest = pieces.pop()
        return pieces, rest
    return [], text


def _is_edge_whitespace(char: str) -> bool:
    """Check if char is whitespace that may start or end a line's content.

    This is whitespace as str.isspace() sees it, as in the formatting rules,
    except FS, GS, RS, NEL, LS and PS, which are data for make everywhere.
    """
    return char.isspace() and char not in _DATA_BREAKS


def _whitespace_edges(line: str) -> tuple[int, int]:
    """Return where the content of line starts and ends.

    The content runs from the first to the last character that is not edge
    whitespace (see _is_edge_whitespace). For a line of whitespace only, both
    are the length of the line.
    """
    start = 0
    while start < len(line) and _is_edge_whitespace(line[start]):
        start += 1
    if start == len(line):
        return start, start
    end = len(line)
    while _is_edge_whitespace(line[end - 1]):
        end -= 1
    return start, end


def _split_line_edges(line: str, terminated: bool) -> list[str]:
    """Split one physical line at the CR, VT and FF in its edges.

    A CR, VT or FF in the content of the line (see _whitespace_edges) is data
    and stays. One in the leading or trailing whitespace, or in a line of
    whitespace only, still ends a line, as with str.splitlines(). terminated
    says whether a line ending followed the line in the text.
    """
    if not _WHITESPACE_BREAK_PATTERN.search(line):
        return [line]
    start, end = _whitespace_edges(line)
    if start == end:
        parts = _WHITESPACE_BREAK_PATTERN.split(line)
    else:
        head = _WHITESPACE_BREAK_PATTERN.split(line[:start])
        tail = _WHITESPACE_BREAK_PATTERN.split(line[end:])
        parts = head[:-1] + [head[-1] + line[start:end] + tail[0]] + tail[1:]
    if not terminated and len(parts) > 1 and not parts[-1]:
        # A break at the very end of the text adds no empty line
        parts.pop()
    return parts


def split_makefile_lines(text: str) -> list[str]:
    """Split makefile text into physical lines the way GNU make reads them.

    Only a newline ends a line: "the newline character is special and marks
    the end of a statement" (GNU make manual 3.1.1, lines 757-758), and a
    physical line is "a single line ending with a newline" (lines 766-769).
    make 3.81 and 4.4.1 drop the one carriage return right before a newline
    (CRLF line endings) and read every other character as part of the line.
    str.splitlines() also ends lines at CR, VT, FF, FS, GS, RS, NEL, LS and PS,
    which cut values, comments and recipe lines in two.

    FS, GS, RS, NEL, LS and PS now never end a line. CR, VT and FF stay in
    the content of a line, from its first to its last character that is not
    whitespace. Elsewhere they keep their str.splitlines() handling for now,
    so that the output stays as before there: in the leading or trailing
    whitespace of a line, in a line of whitespace only, and as the line
    endings of text that has no newline but ends with a carriage return
    (classic Mac line endings). A carriage return at the very end of the
    text therefore still ends the last line. make reads CR, VT and FF as
    whitespace only in some of these places, such as before a directive or
    an assignment; in others they are data, such as in make 3.81's target
    names and at the end of a value or a recipe line. protect_line_breaks()
    keeps the formatting rules from reading the characters that stay as
    whitespace.

    For text without CR, VT, FF, FS, GS, RS, NEL, LS and PS, other than the
    carriage returns of CRLF line endings, the result equals
    str.splitlines(): a final newline adds no empty line, and '' gives [].
    Text that holds one of the stand-ins of protect_line_breaks(), which no
    makefile needs, is split by str.splitlines(), as before.

    Args:
        text: The makefile text

    Returns:
        The physical lines, without their line endings
    """
    if _holds_stand_in(text):
        return text.splitlines()
    pieces, rest = _physical_line_pieces(text)
    lines: list[str] = []
    for piece in pieces:
        lines.extend(_split_line_edges(piece, terminated=True))
    if rest:
        lines.extend(_split_line_edges(rest, terminated=False))
    return lines


def normalize_newlines(text: str) -> str:
    """Return text with its line endings as newlines, as universal newlines read it.

    CRLF and a lone carriage return become a newline, as with Python's
    universal newlines, except for a carriage return that
    split_makefile_lines() keeps in a line: that one stays. Every other
    character stays too.

    Args:
        text: The makefile text

    Returns:
        The text with those line endings as newlines
    """
    if _holds_stand_in(text):
        return text.replace("\r\n", "\n").replace("\r", "\n")
    pieces, rest = _physical_line_pieces(text)
    normalized = []
    for piece in pieces + [rest]:
        if "\r" in piece:
            start, end = _whitespace_edges(piece)
            piece = (
                piece[:start].replace("\r", "\n")
                + piece[start:end]
                + piece[end:].replace("\r", "\n")
            )
        normalized.append(piece)
    return "\n".join(normalized)


def protect_line_breaks(lines: Sequence[str]) -> Optional[list[str]]:
    """Hide CR, VT, FF, FS, GS, RS, NEL, LS and PS in lines from the rules.

    The formatting rules read these characters as whitespace, so they would
    strip or collapse them, although make reads them as part of the line (see
    split_makefile_lines). They are replaced with stand-ins that are not
    whitespace, so the rules leave them where they are: FS, GS, RS, NEL, LS
    and PS everywhere, and CR, VT and FF in the content of a line, from its
    first to its last character that is not whitespace.
    restore_line_breaks() puts the characters back.

    Args:
        lines: The lines to format

    Returns:
        The lines with stand-ins, or None if a line already holds a stand-in
    """
    if any(_holds_stand_in(line) for line in lines):
        return None
    protected = []
    for line in lines:
        if _SPLITLINES_BREAK_PATTERN.search(line):
            # FS, GS, RS, NEL, LS and PS are never edge whitespace, so they
            # are all in the content
            start, end = _whitespace_edges(line)
            line = line[:start] + line[start:end].translate(_TO_STAND_INS) + line[end:]
        protected.append(line)
    return protected


def restore_line_breaks(text: str) -> str:
    """Put back the characters that protect_line_breaks() replaced in text."""
    return text.translate(_FROM_STAND_INS)


class VariableAssignment(NamedTuple):
    """A makefile variable assignment, split the way GNU make splits it.

    Attributes:
        modifiers: The 'export', 'unexport', 'override' and 'private' words
            before the name, in source order (GNU make manual 6.11, lines
            4942-4944; Appendix A, lines 10883-10902).
        name: The unexpanded variable name. It may contain variable references
            (GNU make manual 6.5, lines 4595-4597).
        operator: One of '=', ':=', '::=', ':::=', '+=', '?=' or '!=' (GNU make
            manual 6.5, lines 4577-4579 and 4612-4625; 6.6).
        value: The text after the operator, without its leading whitespace.
            Trailing whitespace is part of the value and is kept (GNU make
            manual 6.2.2, lines 4273-4288). It is source text: a comment is not
            removed (cut the text at LineUtils.find_comment_start first) and
            escapes such as '\\#' are kept.
    """

    modifiers: tuple[str, ...]
    name: str
    operator: str
    value: str


# Whitespace as GNU make classifies it: blanks (space, TAB) end a variable name
# and are condensed around a backslash/newline; any whitespace separates words.
_BLANKS = " \t"
_WHITESPACE = " \t\n\v\f\r"

# Words that may precede a variable assignment (GNU make manual 6.11, lines
# 4942-4944; Appendix A, lines 10883-10902).
_ASSIGNMENT_MODIFIERS = frozenset({"export", "unexport", "override", "private"})

# Assignment operators, longest first (GNU make manual 6.5, lines 4577-4579 and
# 4612-4625).
_ASSIGNMENT_OPERATORS = (":::=", "::=", ":=", "+=", "?=", "!=", "=")

# Functions whose result is always the empty string (GNU make manual 8.10,
# lines 6388-6390; 8.13, lines 6565-6601). Bare variable references and other
# calls, such as '$(MAKE)' or '$(call ...)', can expand to a command, which
# make rejects outside a recipe, so those lines are still repaired.
_EMPTY_RESULT_FUNCTIONS = frozenset({"eval", "info", "warning", "error"})

# Functions whose result is made of what some of their arguments expand to:
# '$(foreach VAR,LIST,TEXT)' joins the expansions of TEXT with spaces (GNU make
# manual 8.6, lines 6146-6159), and '$(if CONDITION,THEN-PART[,ELSE-PART])'
# gives one of its two parts (8.4, lines 6013-6030). {name: the indexes of
# those arguments}
_WRAPPER_FUNCTIONS = {"foreach": (2,), "if": (1, 2)}


def _skip_whitespace(text: str, index: int) -> int:
    """Return the index of the first non-whitespace character at or after index."""
    while index < len(text) and text[index] in _WHITESPACE:
        index += 1
    return index


def _end_of_word(text: str, index: int) -> int:
    """Return the index just past the whitespace-delimited word at index."""
    while index < len(text) and text[index] not in _WHITESPACE:
        index += 1
    return index


def _skip_variable_reference(text: str, index: int) -> int:
    """Return the index just past the variable reference whose '$' is at index.

    This is how GNU make steps over references while it looks for comments,
    separators and assignment operators:
    - '$(' and '${' run to the matching ')' or '}'. Only the same kind of
      bracket nests. An unterminated reference runs to the end of the text.
    - '$$' and single-character references such as '$@' are two characters.
    - A '$' at the end of the text ends there.
    """
    if index + 1 >= len(text):
        return len(text)
    opener = text[index + 1]
    if opener not in "({":
        return index + 2
    closer = ")" if opener == "(" else "}"
    depth = 1
    position = index + 2
    while position < len(text):
        char = text[position]
        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return position + 1
        position += 1
    return len(text)


def _reference_spans(text: str) -> Optional[list[tuple[int, int]]]:
    """Return the (start, end) of each $(...) and ${...} reference in text.

    Returns None if text holds anything but whitespace and such references.
    '$$' and single-character references such as '$@' count as other text.
    A reference ends as in _skip_variable_reference, so an unterminated one
    runs to the end of the text.
    """
    spans = []
    index = 0
    while index < len(text):
        char = text[index]
        if char in _WHITESPACE:
            index += 1
        elif char == "$" and text[index + 1 : index + 2] in ("(", "{"):
            end = _skip_variable_reference(text, index)
            spans.append((index, end))
            index = end
        else:
            return None
    return spans


def _backslashes_before(text: str, index: int) -> int:
    """Return the number of consecutive backslashes just before text[index]."""
    run_start = index
    while run_start > 0 and text[run_start - 1] == "\\":
        run_start -= 1
    return index - run_start


def _has_semicolon_on_second_scan(targets: str) -> bool:
    """Check if make finds a ';' when it scans a rule's target list again.

    make first looks for an unquoted ';' or '#' in the whole rule line and
    removes half of the backslashes before each escaped one. If it found no
    unquoted ';' there, it expands the target words and looks for ';' again,
    removing half of the remaining backslashes (see
    LineUtils.find_unquoted_char). A ';' after 1, 5, 9, ... backslashes is
    escaped on the first scan but not on the second, so it ends the target
    list before the colon: make 3.81 and 4.4.1 report "missing separator",
    or ignore the line when nothing comes before the ';'. A ';' after 3, 7,
    11, ... backslashes stays part of a target
    name. As on the first scan, text inside variable references is skipped;
    what references expand to is not modelled.

    Only call this when the line has no unquoted ';' outside references
    before its comment.
    """
    index = 0
    while index < len(targets):
        char = targets[index]
        if char == "$":
            index = _skip_variable_reference(targets, index)
            continue
        if char == ";" and _backslashes_before(targets, index) % 4 == 1:
            return True
        index += 1
    return False


def _define_or_undefine_word(text: str) -> Optional[str]:
    """Return 'define' or 'undefine' if text starts with it after any modifiers.

    GNU make reads 'export', 'unexport', 'override' and 'private' before
    'define' and 'undefine' as it does before a variable assignment, so
    'override define foo: X = 1' starts a define body and 'private undefine
    foo: X = 1' undefines a variable (GNU make manual 6.7, lines 4776-4781;
    6.8, lines 4801-4804 and 4844-4850; 6.9, lines 4878-4882). Only the exact
    words count: 'override define: X = 1' sets X for the targets 'override'
    and 'define'. An assignment to a variable with one of these names, such
    as 'override define = 1', also starts with them, so check
    parse_variable_assignment first.
    """
    position = 0
    while True:
        position = _skip_whitespace(text, position)
        word_end = _end_of_word(text, position)
        word = text[position:word_end]
        if word in ("define", "undefine"):
            return word
        if word not in _ASSIGNMENT_MODIFIERS:
            return None
        position = word_end


def _is_define_or_undefine(text: str) -> bool:
    """Check if text starts with 'define' or 'undefine' after any modifiers.

    See _define_or_undefine_word.
    """
    return _define_or_undefine_word(text) is not None


def _assignment_operator_at(text: str, index: int) -> Optional[str]:
    """Return the assignment operator that starts at index, if any."""
    for operator in _ASSIGNMENT_OPERATORS:
        if text.startswith(operator, index):
            return operator
    return None


def _parse_variable_definition(text: str, start: int) -> Optional[tuple[str, str, int]]:
    """Parse 'NAME OPERATOR' at text[start:] like GNU make 4.x.

    Returns (name, operator, index after the operator), or None if the text is
    not a variable definition. That is the case when, outside references:
    - a '#' (a comment) comes before any operator;
    - a ':' that does not start ':=', '::=' or ':::=' comes first, which makes
      the line a rule;
    - the name is followed by blanks and then by anything but an operator,
      because a name cannot contain whitespace (GNU make manual 6, lines
      4091-4092);
    - the name is empty.
    """
    position = _skip_whitespace(text, start)
    name_start = position
    while position < len(text):
        char = text[position]
        if char == "$":
            position = _skip_variable_reference(text, position)
            continue
        if char == "#":
            return None
        name_end = position
        if char in _BLANKS:
            position = _skip_whitespace(text, position)
        operator = _assignment_operator_at(text, position)
        if operator is not None:
            if name_end == name_start:
                return None
            return text[name_start:name_end], operator, position + len(operator)
        if char in _BLANKS or char == ":":
            return None
        position += 1
    return None


def _function_calls(text: str) -> Optional[list[tuple[str, str, str]]]:
    """
    Split text into the make function calls that it is made of.

    A call is '$(NAME ARGUMENTS)' or '${NAME ARGUMENTS}', where a blank
    separates the name from the arguments, and it ends where the brackets of
    its own kind balance (GNU make manual 8.1, lines 5588-5613).

    Returns:
        The name, the arguments and the opening bracket of each call, or None
        if text holds anything but such calls and whitespace, such as a
        variable reference or an unterminated call
    """
    calls: list[tuple[str, str, str]] = []
    index = 0
    while index < len(text):
        if text[index] in _WHITESPACE:
            index += 1
            continue
        opener = text[index + 1 : index + 2]
        if text[index] != "$" or opener not in ("(", "{"):
            return None
        closer = ")" if opener == "(" else "}"
        depth = 0
        end = index + 1
        while end < len(text):
            if text[end] == opener:
                depth += 1
            elif text[end] == closer:
                depth -= 1
                if depth == 0:
                    break
            end += 1
        if end == len(text):
            return None
        inside = text[index + 2 : end]
        name_end = 0
        while name_end < len(inside) and inside[name_end] not in _BLANKS:
            name_end += 1
        if name_end == len(inside):
            return None
        calls.append((inside[:name_end], inside[name_end:], opener))
        index = end + 1
    return calls


def _split_arguments(arguments: str, opener: str, count: int) -> list[str]:
    """
    Split the arguments of a function call at its commas, into at most count.

    Like make, only commas outside brackets of the call's own kind separate
    arguments (GNU make manual 8.1, lines 5603-5613), and the last argument
    takes the rest of the text.
    """
    closer = ")" if opener == "(" else "}"
    parts: list[str] = []
    depth = 0
    part_start = 0
    for index, char in enumerate(arguments):
        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
        elif char == "," and depth == 0 and len(parts) < count - 1:
            parts.append(arguments[part_start:index])
            part_start = index + 1
    parts.append(arguments[part_start:])
    return parts


class LineUtils:
    """Common line processing utilities used across formatting rules."""

    # Regex patterns for improved parsing
    DEFINE_START_PATTERN = re.compile(r"^\s*define\s+([^\s]+)")
    DEFINE_END_PATTERN = re.compile(r"^\s*endef\s*$")
    TARGET_PATTERN = re.compile(r"^([^:]+):\s*(.*)$")
    VARIABLE_ASSIGNMENT_PATTERN = re.compile(
        r"^(?:export\s+|override\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*([:+?!]?=)\s*(.*)$"
    )
    CONDITIONAL_START_PATTERN = re.compile(r"^(ifeq|ifneq|ifdef|ifndef)\s*\(")
    CONDITIONAL_MIDDLE_PATTERN = re.compile(r"^else(\s|$)")
    CONDITIONAL_END_PATTERN = re.compile(r"^endif\s*$")
    RECIPE_LIKE_PATTERN = re.compile(
        r"^\s*[^#\s].*"
    )  # Non-comment, non-empty, potentially recipe
    SHELL_COMMAND_PATTERN = re.compile(
        r"^\s*[\w\$@\-\+\(\)\[\]{}./\\]+"
    )  # Common shell command starters

    # Words that make a makefile line a directive rather than a rule when they
    # are its first whitespace-delimited word (GNU make manual Appendix A,
    # lines 10847-10913; 'load' and '-load', lines 9028-9034 and 9091).
    # 'endef' is a directive only where it ends a define body (lines
    # 4797-4799). 'override' and 'private' are not included because they are
    # modifiers. Before a variable assignment (see parse_variable_assignment)
    # or before 'define' or 'undefine' (6.7, lines 4776-4781; 6.9, lines
    # 4878-4882), the line is that assignment or directive. GNU make 4.4
    # parses any other line that starts with them as a rule. A line whose
    # first word is in this set can still be an assignment to a variable of
    # that name, such as 'export = 1', so check parse_variable_assignment
    # first.
    NON_RULE_DIRECTIVE_WORDS = frozenset(
        {
            "define",
            "endef",
            "undefine",
            "ifdef",
            "ifndef",
            "ifeq",
            "ifneq",
            "else",
            "endif",
            "include",
            "-include",
            "sinclude",
            "export",
            "unexport",
            "vpath",
            "load",
            "-load",
        }
    )

    @staticmethod
    def get_active_recipe_prefix(lines: list[str], line_index: int) -> str:
        """
        Get the active .RECIPEPREFIX character up to the given line index.

        Args:
            lines: List of all lines in the Makefile
            line_index: Index of the current line (0-based)

        Returns:
            The active recipe prefix character (default: "\t")
        """
        active_prefix = "\t"  # Default recipe prefix
        for i in range(line_index):
            line = lines[i]
            prefix_match = re.match(r"^\s*\.RECIPEPREFIX\s*(?::=|=)\s*(.)\s*$", line)
            if prefix_match:
                active_prefix = prefix_match.group(1)
        return active_prefix

    @staticmethod
    def is_recipe_line_with_prefix(line: str, active_prefix: str) -> bool:
        """
        Check if line is a recipe line using the active .RECIPEPREFIX character.

        Args:
            line: The line to check
            active_prefix: The active recipe prefix character

        Returns:
            True if the line starts with the active recipe prefix
        """
        # Handle cases: prefix directly (>) and prefix with tab (>\t)
        # Also handle the case where there might be a tab before the prefix
        return (
            line.startswith(active_prefix)
            or line.startswith(active_prefix + "\t")
            or line.startswith("\t" + active_prefix)
        )

    @staticmethod
    def should_skip_line(
        line: str,
        skip_recipe: bool = True,
        skip_comments: bool = True,
        skip_empty: bool = True,
    ) -> bool:
        """
        Check if a line should be skipped based on common criteria.

        Args:
            line: The line to check
            skip_recipe: Skip recipe lines (start with tab or spaces)
            skip_comments: Skip comment lines (start with #)
            skip_empty: Skip empty lines

        Returns:
            True if the line should be skipped
        """
        stripped = line.strip()

        if skip_empty and not stripped:
            return True

        if skip_comments and stripped.startswith("#"):
            return True

        return skip_recipe and line.startswith(("\t", " ")) and bool(stripped)

    @staticmethod
    def should_skip_makefile_line(line: str) -> bool:
        """
        Check if a line should be skipped when parsing Makefile structure.

        This is commonly used across phony rules to skip non-target lines.

        Args:
            line: The line to check

        Returns:
            True if the line should be skipped during Makefile parsing
        """
        stripped = line.strip()

        # Skip empty lines, comments, includes, conditionals
        return (
            not stripped
            or stripped.startswith("#")
            or stripped.startswith("include")
            or stripped.startswith("-include")
            or stripped.startswith("ifeq")
            or stripped.startswith("ifneq")
            or stripped.startswith("ifdef")
            or stripped.startswith("ifndef")
            or stripped.startswith("else")
            or stripped.startswith("endif")
        )

    @staticmethod
    def is_inside_define_block(line_index: int, all_lines: list[str]) -> bool:
        """
        Check if the current line is inside a define block.

        Args:
            line_index: Index of the current line
            all_lines: All lines in the file

        Returns:
            True if the line is inside a define block
        """
        define_stack = []
        for i in range(line_index):
            check_line = all_lines[i].strip()
            if LineUtils.DEFINE_START_PATTERN.match(check_line):
                define_stack.append(i)
            elif LineUtils.DEFINE_END_PATTERN.match(check_line) and define_stack:
                define_stack.pop()

        # If define_stack is not empty, we're inside a define block
        return bool(define_stack)

    @staticmethod
    def get_define_block_context(
        line_index: int, all_lines: list[str]
    ) -> Optional[dict]:
        """
        Get information about the define block context if the line is inside one.

        Args:
            line_index: Index of the current line
            all_lines: All lines in the file

        Returns:
            Dictionary with define block info or None if not in a define block
        """
        define_stack = []
        for i in range(line_index):
            check_line = all_lines[i].strip()
            match = LineUtils.DEFINE_START_PATTERN.match(check_line)
            if match:
                define_stack.append({"start_line": i, "name": match.group(1)})
            elif LineUtils.DEFINE_END_PATTERN.match(check_line) and define_stack:
                define_stack.pop()

        if define_stack:
            return define_stack[-1]  # Return the innermost define block
        return None

    @staticmethod
    def is_recipe_line_in_define_template(
        line: str, line_index: int, all_lines: list[str]
    ) -> bool:
        """
        Check if a line inside a define block is actually a recipe line for a target template.

        Args:
            line: The line to check
            line_index: Index of the line in the file
            all_lines: All lines in the file

        Returns:
            True if this is a recipe line within a target template in a define block
        """
        # Must be indented to be a recipe
        if not line.startswith(("\t", " ")) or not line.strip():
            return False

        define_context = LineUtils.get_define_block_context(line_index, all_lines)
        if not define_context:
            return False

        # Look backward within the define block to find a target line
        define_start = define_context["start_line"]

        for i in range(line_index - 1, define_start, -1):
            check_line = all_lines[i]
            stripped = check_line.strip()

            # Skip empty lines and comments
            if not stripped or stripped.startswith("#"):
                continue

            # If we hit another indented line, continue looking for the target
            if check_line.startswith(("\t", " ")):
                continue

            # Check if this is a target line
            if LineUtils.TARGET_PATTERN.match(stripped):
                return True

            # If we hit a variable assignment or other construct, this is not a recipe
            if LineUtils.VARIABLE_ASSIGNMENT_PATTERN.match(
                stripped
            ) or LineUtils.is_makefile_construct(stripped):
                return False

        return False

    @staticmethod
    def get_conditional_depth(line_index: int, all_lines: list[str]) -> int:
        """
        Get the current conditional block nesting depth at the given line.

        Args:
            line_index: Index of the current line
            all_lines: All lines in the file

        Returns:
            The nesting depth (0 = not in any conditional, 1+ = nested depth)
        """
        conditional_depth = 0
        for i in range(line_index):
            check_line = all_lines[i].strip()
            if LineUtils.CONDITIONAL_START_PATTERN.match(check_line):
                conditional_depth += 1
            elif LineUtils.CONDITIONAL_END_PATTERN.match(check_line):
                conditional_depth = max(0, conditional_depth - 1)

        return conditional_depth

    @staticmethod
    def is_makefile_construct(line: str) -> bool:
        """
        Check if a line is a special Makefile construct that should be excluded
        from recipe line detection.

        Args:
            line: The line to check

        Returns:
            True if the line is a special Makefile construct
        """
        stripped = line.strip()

        # Check for Make function calls that should be treated as constructs
        # Note: $(call ...) is context-dependent and handled in recipe detection
        if stripped.startswith("$(") and ")" in stripped:
            # Make function calls that should never be treated as recipe lines
            function_patterns = (
                "$(error",
                "$(warning",
                "$(info",
                "$(shell",
                "$(eval",
                "$(value",
                "$(origin",
                "$(flavor",
                "$(foreach",
                "$(if",
                "$(or",
                "$(and",
                "$(file",
            )
            if any(stripped.startswith(pattern) for pattern in function_patterns):
                return True

        # Special handling for export/unexport commands
        # If the line is indented (starts with tab or space), export/unexport are shell commands, not makefile constructs
        if stripped.startswith(("export", "unexport")):
            # If line is indented, it's a shell command in a recipe, not a makefile construct
            # If not indented, it's a makefile construct
            return not line.startswith(("\t", " "))

        return (
            stripped.startswith(
                (
                    "include",
                    "-include",
                    "ifeq",
                    "ifneq",
                    "ifdef",
                    "ifndef",
                    "define",
                    "endef",
                    "vpath",
                )
            )
            or stripped in ("else", "endif")
            or stripped in ALL_SPECIAL_MAKE_TARGETS
        )

    @staticmethod
    def is_conditional_start(line: str) -> bool:
        """Check if line starts a conditional block."""
        return bool(LineUtils.CONDITIONAL_START_PATTERN.match(line.strip()))

    @staticmethod
    def is_conditional_middle(line: str) -> bool:
        """Check if line is a conditional middle (else)."""
        return bool(LineUtils.CONDITIONAL_MIDDLE_PATTERN.match(line.strip()))

    @staticmethod
    def is_conditional_end(line: str) -> bool:
        """Check if line ends a conditional block."""
        return bool(LineUtils.CONDITIONAL_END_PATTERN.match(line.strip()))

    @staticmethod
    def detect_define_block_indentation(lines: list[str], define_start: int) -> str:
        """
        Detect the indentation pattern within a define block.

        Args:
            lines: All lines in the file
            define_start: Index of the 'define' line

        Returns:
            The indentation string to use for content (e.g., '    ', '\t', '')
        """
        # Find the matching endef
        define_end = None
        for i in range(define_start + 1, len(lines)):
            if lines[i].strip() == "endef":
                define_end = i
                break

        if define_end is None:
            # No matching endef found, default to no indentation
            return ""

        # Analyze indentation patterns in the define block content
        indentations = []
        non_indented_count = 0

        for i in range(define_start + 1, define_end):
            line = lines[i]
            stripped = line.strip()

            # Skip empty lines and comments
            if not stripped or stripped.startswith("#"):
                continue

            # Calculate indentation
            indent_len = len(line) - len(line.lstrip())
            if indent_len > 0:
                indentations.append(line[:indent_len])
            else:
                non_indented_count += 1

        # If there are no content lines, return no indentation
        total_content_lines = len(indentations) + non_indented_count
        if total_content_lines == 0:
            return ""

        # If all lines have no indentation, keep it that way
        if len(indentations) == 0:
            return ""

        # If most lines have no indentation, don't add indentation
        if non_indented_count > len(indentations):
            return ""

        # Find the most common indentation pattern among indented lines
        from collections import Counter

        indent_counts = Counter(indentations)

        if indent_counts:
            # Use the most common indentation
            most_common_indent = indent_counts.most_common(1)[0][0]
            return most_common_indent

        # Fallback to no indentation
        return ""

    @staticmethod
    def normalize_define_block_indentation(
        lines: list[str], define_start: int
    ) -> tuple[list[str], bool]:
        """
        Normalize indentation within a define block to be consistent.

        Args:
            lines: All lines in the file
            define_start: Index of the 'define' line

        Returns:
            Tuple of (modified_lines, changed_flag)
        """
        # Find the matching endef
        define_end = None
        for i in range(define_start + 1, len(lines)):
            if lines[i].strip() == "endef":
                define_end = i
                break

        if define_end is None:
            return lines, False

        # Detect the target indentation pattern
        target_indent = LineUtils.detect_define_block_indentation(lines, define_start)

        # Apply consistent indentation to all content lines
        modified_lines = lines.copy()
        changed = False

        for i in range(define_start + 1, define_end):
            line = lines[i]
            stripped = line.strip()

            # Skip empty lines and comments
            if not stripped or stripped.startswith("#"):
                continue

            # Apply target indentation
            new_line = target_indent + stripped
            if new_line != line:
                modified_lines[i] = new_line
                changed = True

        return modified_lines, changed

    @staticmethod
    def is_recipe_line(line: str, line_index: int, all_lines: list[str]) -> bool:
        """
        Check if a line is a recipe line (indented line that belongs to a target).

        Args:
            line: The line to check
            line_index: Index of the line in the file
            all_lines: All lines in the file

        Returns:
            True if this is a recipe line
        """
        # First check if it's already indented
        if line.startswith(("\t", " ")) and line.strip():
            return LineUtils._is_recipe_line_helper(line, line_index, all_lines, set())

        # If not indented, check if it should be based on context
        return LineUtils._should_be_recipe_line(line, line_index, all_lines)

    @staticmethod
    def _is_recipe_line_helper(
        line: str, line_index: int, all_lines: list[str], visited: set
    ) -> bool:
        """Helper method to avoid infinite recursion."""
        if not (line.startswith(("\t", " ")) and line.strip()):
            return False

        # Don't treat makefile constructs as recipe lines even if indented
        if LineUtils.is_makefile_construct(line):
            return False

        # Don't treat target lines as recipe lines even if indented (targets in conditional blocks)
        if LineUtils.is_target_line(line, line_index, all_lines):
            return False

        # Don't treat variable assignments inside conditional blocks as recipe lines
        stripped = line.strip()
        if (
            LineUtils.is_variable_assignment(stripped, line)
            and LineUtils.get_conditional_depth(line_index, all_lines) > 0
        ):
            # If we're inside a conditional block, this variable assignment
            # should not be treated as a recipe line
            return False

        # Check if this is inside a define block
        if LineUtils.is_inside_define_block(line_index, all_lines):
            # Allow recipe lines within target templates in define blocks
            # Allow recipe lines within target templates in define blocks
            return LineUtils.is_recipe_line_in_define_template(
                line, line_index, all_lines
            )

        # Don't treat variable assignment continuation lines as recipe lines
        if LineUtils._is_variable_assignment_continuation(line_index, all_lines):
            return False

        # Avoid infinite recursion
        if line_index in visited:
            return False
        visited.add(line_index)

        # Look backward to find what this indented line belongs to
        for i in range(line_index - 1, -1, -1):
            if i in visited:
                continue

            prev_line = all_lines[i]
            prev_stripped = prev_line.strip()

            # Skip empty lines and comments (comments should not break recipe context)
            if not prev_stripped or prev_stripped.startswith("#"):
                continue

            # If previous line is an indented line that ends with backslash,
            # this could be a recipe continuation line
            if prev_line.startswith(("\t", " ")) and prev_stripped.endswith("\\"):
                # Check if the previous line is a recipe line
                if LineUtils._is_recipe_line_helper(prev_line, i, all_lines, visited):
                    return True
                continue

            # If previous line is an indented recipe line, this is also a recipe line
            if prev_line.startswith(("\t", " ")):
                if LineUtils._is_recipe_line_helper(prev_line, i, all_lines, visited):
                    return True
                # If previous line is indented but not a recipe, check if it's a target line
                # This handles targets in conditional blocks
                if LineUtils.is_target_line(prev_stripped, i, all_lines):
                    return True
                continue

            # If previous line is detected as a recipe line by the new logic, this is also a recipe line
            if LineUtils._should_be_recipe_line(prev_line, i, all_lines):
                return True

            # Check if this is a target line (contains : but not an assignment)
            if ":" in prev_stripped and not prev_stripped.startswith("#"):
                # Exclude variable assignments that contain colons (e.g., CC := gcc)
                if "=" in prev_stripped and prev_stripped.find(
                    "="
                ) < prev_stripped.find(":"):
                    return False

                # If this is a conditional block or function definition, skip it and continue looking
                if prev_stripped.startswith(
                    ("ifeq", "ifneq", "ifdef", "ifndef", "define", "else", "endif")
                ):
                    continue

                # This is a target line (could be target:, target: prereq, or %.o: %.c)
                return True

            # If we find a variable assignment without colon, this is NOT a recipe
            # BUT only if it's at the top level (not indented)
            if (
                "=" in prev_stripped
                and not prev_stripped.startswith(("ifeq", "ifneq", "ifdef", "ifndef"))
                and not prev_line.startswith(("\t", " "))
            ):
                # This is a top-level variable assignment
                return False

            # If we reach a non-indented line, check if it's a conditional that we should skip
            if not prev_line.startswith(("\t", " ")):
                # Skip conditional constructs and continue looking
                if prev_stripped.startswith(
                    ("ifeq", "ifneq", "ifdef", "ifndef", "else", "endif")
                ):
                    continue

                break

        # Default to not a recipe if we can't determine context
        return False

    @staticmethod
    def _is_variable_assignment_continuation(
        line_index: int, all_lines: list[str]
    ) -> bool:
        """
        Check if this line is a continuation of a variable assignment.

        Args:
            line_index: Index of the current line
            all_lines: All lines in the file

        Returns:
            True if this line is part of a variable assignment continuation
        """
        # Look backward to find the start of the variable assignment
        for i in range(line_index - 1, -1, -1):
            prev_line = all_lines[i]
            prev_stripped = prev_line.strip()

            # Skip empty lines and comments (comments should not break variable assignment context)
            if not prev_stripped:
                break
            if prev_stripped.startswith("#"):
                continue

            # If we find another indented line that ends with backslash,
            # continue looking backward
            if prev_line.startswith((" ", "\t")) and prev_stripped.endswith("\\"):
                continue

            # If we find a non-indented line, check if it's a variable assignment
            if not prev_line.startswith((" ", "\t")):
                # Check if this is a variable assignment line that ends with backslash
                if (
                    "=" in prev_stripped
                    and prev_stripped.endswith("\\")
                    and not prev_stripped.startswith(
                        ("ifeq", "ifneq", "ifdef", "ifndef")
                    )
                ):
                    return True
                # If it's not a variable assignment, stop looking
                break

        return False

    @staticmethod
    def _should_be_recipe_line(
        line: str, line_index: int, all_lines: list[str]
    ) -> bool:
        """
        Check if a non-indented line should be a recipe line based on context.

        This handles cases where recipe lines are improperly formatted (not indented).
        This function is very conservative to avoid false positives.
        """
        # Skip empty lines and comments
        if not line.strip() or line.strip().startswith("#"):
            return False

        # Don't treat special makefile constructs as recipe lines
        if LineUtils.is_makefile_construct(line) or LineUtils.is_target_line(
            line, line_index, all_lines
        ):
            return False

        # If we're inside a define block, this is not a recipe line
        if LineUtils.is_inside_define_block(line_index, all_lines):
            return False

        # Check if we're inside a conditional block (but not followed by a target)
        conditional_depth = LineUtils.get_conditional_depth(line_index, all_lines)
        if conditional_depth > 0:
            # Find the last non-conditional line to see if it was a target
            last_non_conditional_line = None
            for i in range(line_index):
                check_line = all_lines[i].strip()
                if (
                    check_line
                    and not check_line.startswith(
                        ("ifeq", "ifneq", "ifdef", "ifndef", "else", "endif", "#")
                    )
                    and LineUtils.get_conditional_depth(i, all_lines) == 0
                ):
                    last_non_conditional_line = check_line

            # If we're inside a conditional block and the last non-conditional line
            # wasn't a target, then this is not a recipe
            if last_non_conditional_line is None or not LineUtils.is_target_line(
                last_non_conditional_line, line_index, all_lines
            ):
                return False

        # Look backward to find context - either direct target or through recipe lines
        target_line_found = False
        for i in range(line_index - 1, -1, -1):
            prev_line = all_lines[i]
            prev_stripped = prev_line.strip()

            # Skip empty lines and comments (comments should not break context)
            if not prev_stripped:
                break
            if prev_stripped.startswith("#"):
                continue

            # If we find a target line, this could be a recipe
            if LineUtils.is_target_line(prev_line, i, all_lines):
                target_line_found = True
                break

            # If we find another potential recipe line (with shell patterns), continue looking
            if any(
                pattern in prev_line for pattern in ["$(call ", "$@", "$<", "$^", "$$"]
            ):
                continue

            # If we find a non-target, non-recipe line, this is not a recipe
            if not prev_line.startswith(("\t", " ")):
                break

        # Only consider this a recipe line if:
        # 1. We found a target line in the context above
        # 2. AND this line looks like a shell command (not a typical makefile variable assignment)
        if target_line_found:
            # Additional heuristics to identify shell commands vs makefile variables:

            # If it contains shell-specific patterns, likely a shell command
            if any(pattern in line for pattern in ["$(call ", "$@", "$<", "$^", "$$"]):
                return True

            # If it's a simple variable assignment (no shell patterns),
            # it's likely a makefile variable, not a shell command
            if LineUtils.is_variable_assignment(line, line):
                # Check for shell variable patterns vs makefile variable patterns
                # Shell variables often have different naming conventions
                var_name = line.split("=")[0].strip()

                # Common makefile variable names (uppercase, with underscores)
                if var_name.isupper() and (
                    "_" in var_name
                    or var_name in ["CC", "CXX", "CFLAGS", "LDFLAGS", "AR", "AS"]
                ):
                    return False

                # Lowercase or mixed case more likely to be shell variables
                if not var_name.isupper():
                    return True

        return False

    @staticmethod
    def is_target_line(
        line: str,
        line_index: Optional[int] = None,
        all_lines: Optional[list[str]] = None,
    ) -> bool:
        """
        Check if a line defines a target.

        Args:
            line: The line to check
            line_index: Index of the line in the file (optional, for context)
            all_lines: All lines in the file (optional, for context)
        """
        stripped = line.strip()

        # Skip comments and empty lines
        if not stripped or stripped.startswith("#"):
            return False

        # If line is indented, it's very unlikely to be a target
        # BUT: if we're inside a conditional block, indented target lines are valid
        if line.startswith(("\t", " ")):
            # If we have context, check if we're inside a conditional block
            if line_index is not None and all_lines is not None:
                conditional_depth = LineUtils.get_conditional_depth(
                    line_index, all_lines
                )
                # Inside a conditional block, indented target lines are valid
                # Check if this looks like a target line
                if (
                    conditional_depth > 0
                    and LineUtils.colon_is_target_separator(stripped)
                    and not LineUtils.VARIABLE_ASSIGNMENT_PATTERN.match(stripped)
                ):
                    return True
            # Outside conditional blocks, indented lines are not targets
            return False

        # Use regex to match target pattern first
        target_match = LineUtils.TARGET_PATTERN.match(stripped)
        if not target_match:
            return False

        # Only use built-in shell commands for direct match
        first_word = stripped.split()[0] if stripped.split() else ""
        if first_word in SHELL_COMMAND_INDICATORS:
            return False

        # Special handling for $ - only reject if it doesn't look like a target with variable reference
        if stripped.startswith("$"):
            if stripped.startswith("$(") and ")" in stripped and ":" in stripped:
                paren_close = stripped.find(")")
                if paren_close != -1:
                    after_paren = stripped[paren_close + 1 :].strip()
                    if (
                        after_paren
                        and " " in after_paren
                        and (
                            "$(" in after_paren
                            or "${" in after_paren
                            or any(
                                char in after_paren
                                for char in ["&&", "||", ";", "|", ">", "<", "`"]
                            )
                            or after_paren.startswith(
                                ("if ", "for ", "while ", "case ", "until ")
                            )
                        )
                    ):
                        return False
            else:
                return False
            if stripped.startswith("$(") and " " in stripped:
                paren_close = stripped.find(")")
                if paren_close == -1:
                    return False
                func_part = stripped[2:paren_close]
                if " " in func_part:
                    return False

        # Check if this is actually a variable assignment with colon (e.g., VAR:=value)
        if LineUtils.VARIABLE_ASSIGNMENT_PATTERN.match(stripped):
            return False

        # Exclude conditional constructs and define blocks
        if (
            LineUtils.CONDITIONAL_START_PATTERN.match(stripped)
            or LineUtils.DEFINE_START_PATTERN.match(stripped)
            or LineUtils.DEFINE_END_PATTERN.match(stripped)
        ):
            return False

        # Additional validation: check if the colon is inside quotes
        colon_pos = stripped.find(":")
        if colon_pos != -1:
            before_colon = stripped[:colon_pos]
            single_quotes = before_colon.count("'")
            double_quotes = before_colon.count('"')
            if single_quotes % 2 == 1 or double_quotes % 2 == 1:
                return False

        return True

    @staticmethod
    def is_variable_assignment(line: str, context_line: Optional[str] = None) -> bool:
        """
        Check if a line is a variable assignment.

        Args:
            line: The line to check
            context_line: The original line with indentation (optional, for context)

        Returns:
            True if this is a variable assignment
        """
        stripped = line.strip()

        # Skip comments and empty lines
        if not stripped or stripped.startswith("#"):
            return False

        # Exclude conditional blocks
        if LineUtils.CONDITIONAL_START_PATTERN.match(stripped):
            return False

        # Check if this looks like a variable assignment
        if not LineUtils.VARIABLE_ASSIGNMENT_PATTERN.match(stripped):
            return False

            # If this is an export/unexport command in a recipe context (indented),
        # it's a shell command, not a makefile variable assignment
        return not (
            stripped.startswith(("export ", "unexport "))
            and context_line
            and context_line.startswith(("\t", " "))
        )

    @staticmethod
    def is_variable_assignment_with_colon(line: str) -> bool:
        """
        Check if a line is a variable assignment that contains a colon.

        This is used to distinguish between variable assignments like 'CC := gcc'
        and target definitions like 'target: dependencies'.

        Args:
            line: The line to check

        Returns:
            True if this is a variable assignment with := or = that contains a colon
        """
        stripped = line.strip()

        # Check for variable assignment patterns
        return bool(
            ":=" in stripped or "=" in stripped and ":" not in stripped.split("=")[0]
        )

    @staticmethod
    def is_continuation_line(line: str) -> bool:
        """
        Check if a line ends with a backslash (continuation).

        Same as ends_with_continuation: only an unescaped backslash at the
        very end of the line continues it, and a backslash followed by
        whitespace does not (GNU make manual 3.1, lines 730-733; 3.1.1).

        Args:
            line: The line to check

        Returns:
            True if this is a continuation line
        """
        return LineUtils.ends_with_continuation(line)

    @staticmethod
    def normalize_whitespace(line: str, remove_trailing: bool = True) -> str:
        """
        Normalize whitespace in a line.

        Args:
            line: The line to normalize
            remove_trailing: Whether to remove trailing whitespace

        Returns:
            The normalized line
        """
        if remove_trailing:
            return line.rstrip()
        return line

    @staticmethod
    def format_error_message(
        message: str, line_num: int, config: dict, severity: str = "Error"
    ) -> str:
        """
        Format an error message according to GNU error format setting.

        Args:
            message: The error message content
            line_num: Line number where error occurred
            config: Configuration dictionary
            severity: 'Error', or 'Warning' for a warning, in the GNU format

        Returns:
            Formatted error message string
        """
        gnu_error_format = config.get("_global", {}).get("gnu_error_format", False)

        if gnu_error_format:
            return f"{line_num}: {severity}: {message}"
        else:
            return f"Line {line_num}: {message}"

    @staticmethod
    def create_define_block_processor() -> Callable[[str], bool]:
        """
        Create a define block processor for tracking define/endef blocks.

        Returns:
            A function that can be used to process lines and track define blocks
        """
        inside_define = False

        def process_line(line: str) -> bool:
            """
            Process a line and return whether we're inside a define block.

            Args:
                line: The line to process

            Returns:
                True if inside a define block after processing this line
            """
            nonlocal inside_define

            stripped = line.strip()

            if LineUtils.DEFINE_START_PATTERN.match(stripped):
                inside_define = True
            elif LineUtils.DEFINE_END_PATTERN.match(stripped):
                inside_define = False

            return inside_define

        return process_line

    @staticmethod
    def process_lines_with_standard_skipping(
        lines: list[str],
        line_processor: Callable[[str, int], tuple[str, bool]],
        skip_recipe: bool = True,
        skip_comments: bool = True,
        skip_empty: bool = True,
        skip_define_blocks: bool = False,
    ) -> tuple[list[str], bool]:
        """
        Process lines with standard skipping logic used across multiple rules.

        Args:
            lines: Lines to process
            line_processor: Function that takes (line, line_index) and returns (new_line, changed)
            skip_recipe: Whether to skip recipe lines
            skip_comments: Whether to skip comment lines
            skip_empty: Whether to skip empty lines
            skip_define_blocks: Whether to skip content inside define blocks

        Returns:
            Tuple of (processed_lines, changed_flag)
        """
        formatted_lines = []
        changed = False

        # Optional define block processor
        define_processor = (
            LineUtils.create_define_block_processor() if skip_define_blocks else None
        )

        for i, line in enumerate(lines):
            # Check if we should skip this line
            should_skip = LineUtils.should_skip_line(
                line,
                skip_recipe=skip_recipe,
                skip_comments=skip_comments,
                skip_empty=skip_empty,
            )

            # Check define block status if needed
            if define_processor and not should_skip:
                inside_define = define_processor(line)
                if inside_define and skip_define_blocks:
                    should_skip = True

            if should_skip:
                formatted_lines.append(line)
                continue

            # Process the line
            new_line, line_changed = line_processor(line, i)
            if line_changed:
                changed = True
            formatted_lines.append(new_line)

        return formatted_lines, changed

    @staticmethod
    def is_template_placeholder_target(target_name: str) -> bool:
        """
        Returns True if the target is a template placeholder like $(1), $(2), $(VAR), ${1}, ${VAR}, etc.
        This includes both numeric and named variable references in either $() or ${} format.
        """
        # Match $(number), $(NAME), ${number}, ${NAME}
        return bool(re.fullmatch(r"\$[({][^})]+[})]", target_name))

    @staticmethod
    def colon_is_target_separator(line: str) -> bool:
        """
        Returns True if the colon in the line is likely a target separator,
        not part of a variable reference or inside quotes.
        """
        in_single = in_double = False
        i = 0
        while i < len(line):
            c = line[i]
            if c == '"' and not in_single:
                in_double = not in_double
            elif c == "'" and not in_double:
                in_single = not in_single
            elif c == ":" and not in_single and not in_double:
                # Check if colon is part of a variable reference like $@
                if i > 0 and line[i - 1] == "$":
                    pass  # skip, part of variable
                else:
                    return True
            i += 1
        return False

    # GNU make parsing helpers. They model how GNU make 4.x reads makefile
    # syntax (GNU make manual 3.1, 3.1.1, 3.8, 6.5 and 6.11). Pass them makefile
    # lines only: recipe lines go to the shell as they are (GNU make manual
    # 3.1, lines 744-746; 5.1) and define bodies are kept verbatim (lines
    # 748-752; 6.8). They are static: variable values, $(eval) text,
    # .RECIPEPREFIX, .POSIX and DOS drive letters are not modelled.

    @staticmethod
    def find_unquoted_char(line: str, chars: str, start: int = 0) -> Optional[int]:
        """
        Find the first character from chars that make does not treat as quoted.

        Like GNU make:
        - a character preceded by an odd number of backslashes is escaped;
          an even number of backslashes escape each other (GNU make manual
          3.1, lines 730-737);
        - characters inside $(...) and ${...} are skipped, as are '$$' and
          single-character references such as '$@' (lines 739-742);
        - quotes are not special.

        GNU make removes the escaping backslashes as it scans, and it scans a
        rule's targets and prerequisites for ';' again after that. So
        'foo: a\\;b' still gets the inline recipe 'b', although this function
        reports the ';' as escaped. is_target_specific_variable models the
        second scan of the targets.

        Args:
            line: The text to search
            chars: The characters to look for. A '$' always starts a variable
                reference, so it is never found.
            start: The index to start searching from

        Returns:
            The index of the first unquoted character from chars, or None
        """
        index = max(start, 0)
        while index < len(line):
            char = line[index]
            if char == "$":
                index = _skip_variable_reference(line, index)
                continue
            if char in chars and _backslashes_before(line, index) % 2 == 0:
                return index
            index += 1
        return None

    @staticmethod
    def find_comment_start(line: str) -> Optional[int]:
        """
        Find where the make comment on a makefile line starts.

        '#' starts a comment unless it is escaped as '\\#' or appears inside a
        variable reference or function call (GNU make manual 3.1, lines
        730-742). make 3.81 does not follow lines 739-742: it treats a '#'
        inside $(...) as a comment.

        Only use this on makefile syntax, never on recipe lines (lines
        744-746) or define bodies (lines 748-752). For a line continued with a
        backslash, search the logical line from join_logical_line.

        Args:
            line: The line to search

        Returns:
            The index of the '#' that starts the comment, or None
        """
        return LineUtils.find_unquoted_char(line, "#")

    @staticmethod
    def has_semicolon_on_second_scan(text: str) -> bool:
        """
        Check if make finds a ';' in part of a rule line when it scans it again.

        make looks for the first unquoted ';' or '#' of a rule line (see
        find_unquoted_char) and removes half of the backslashes before each
        escaped one. If it found no unquoted ';' before the comment, it
        expands the targets and the prerequisites and looks for ';' in them
        once more. A ';' after 1, 5, 9, ... backslashes is escaped on the
        first scan but not on the second: in the targets it ends the target
        list, and in the prerequisites it starts an inline recipe, so
        'foo: a\\;b' has the prerequisite 'a' and the recipe 'b' (GNU make
        manual 3.1, lines 730-737; 4.2, lines 1499-1503). A ';' after 3, 7,
        11, ... backslashes stays text. Text inside variable references is
        skipped; what references expand to is not modelled.

        Only call this when the rule line has no unquoted ';' outside
        references before its comment.

        Args:
            text: The targets or the prerequisites of a rule line, cut at its
                comment

        Returns:
            True if make finds a ';' in the text on that second scan
        """
        return _has_semicolon_on_second_scan(text)

    @staticmethod
    def parse_variable_assignment(text: str) -> Optional[VariableAssignment]:
        """
        Parse a variable assignment the way GNU make 4.x does.

        The name is followed by '=', ':=', '::=', ':::=', '+=', '?=' or '!='
        (GNU make manual 6.5, lines 4577-4579 and 4612-4625). It may contain
        variable references, and letters of any case, but no whitespace, ':'
        or '#' (lines 4091-4092). Any number of the modifiers 'export',
        'unexport', 'override' and 'private' may come first (6.11, lines
        4942-4944; Appendix A, lines 10883-10902). A word that is both a
        directive and a variable name, as in 'export = 1', is a variable.

        These are not assignments: rule lines, 'define' and 'undefine'
        directives, 'export NAME' without an operator, and an empty name.

        The value keeps its trailing whitespace (lines 4273-4288). It is
        source text: a comment is not removed, so cut the text at
        find_comment_start first, and escapes such as '\\#' are kept. Pass the
        logical line from join_logical_line when the assignment continues
        over several lines.

        Args:
            text: A makefile line, without the recipe prefix

        Returns:
            The parsed assignment, or None if the text is not an assignment
        """
        modifiers: list[str] = []
        position = 0
        while True:
            position = _skip_whitespace(text, position)
            if position >= len(text):
                return None
            definition = _parse_variable_definition(text, position)
            if definition is not None:
                name, operator, value_start = definition
                value = text[_skip_whitespace(text, value_start) :]
                return VariableAssignment(tuple(modifiers), name, operator, value)
            word_end = _end_of_word(text, position)
            word = text[position:word_end]
            if word not in _ASSIGNMENT_MODIFIERS:
                return None
            modifiers.append(word)
            position = word_end

    @staticmethod
    def is_target_specific_variable(line: str) -> bool:
        """
        Check if a makefile line sets a target- or pattern-specific variable.

        The form is 'TARGETS : VARIABLE-ASSIGNMENT' or 'TARGETS :: ...' (GNU
        make manual 6.11, lines 4938-4951; 6.12, lines 4994-4999). As in GNU
        make 4.x:
        - the assignment can use any operator and modifier, and a name in any
          case (see parse_variable_assignment);
        - the line is cut at its first unquoted ';' or '#' before the test,
          so 'foo: ;X=1' is an inline recipe (4.2, lines 1488 and 1499-1503)
          and 'foo: # X = 1' is a plain rule (3.1, lines 730-737). A ';' after
          the assignment belongs to the value: 'foo: X = a;b' sets 'a;b';
        - the target list ends at the first ':' outside references that is
          not escaped with a backslash. If the line has no unquoted ';', make
          scans the target list for ';' once more (see find_unquoted_char),
          and a ';' after 1, 5, 9, ... backslashes ends it there. So make
          stops with "missing separator" on 'a\\;b foo: X = 1', which is not
          target-specific, but 'a\\;b foo: X = 1;2' sets X to '1;2';
        - plain assignments, such as 'CC := a:b', and directive lines, such
          as 'export foo: X = 1' or 'override define foo: X = 1', are not
          target-specific (6.7, lines 4776-4781; 6.9, lines 4878-4882).

        Known limit: make 4.4 reads a '::' followed directly by an escaped ';'
        and '=' ('foo::\\;=1') as an inline recipe; this check reports it as
        target-specific.

        A line that starts with the recipe prefix in a rule context is a
        recipe line; do not pass it. For a continued line, pass the logical
        line from join_logical_line.

        Args:
            line: The makefile line to check

        Returns:
            True if the line sets a target- or pattern-specific variable
        """
        text = line.strip(_WHITESPACE)
        if not text or text.startswith("#"):
            return False
        first_word = text[: _end_of_word(text, 0)]
        # 'endef' only ends a define body (GNU make manual 6.8, lines
        # 4797-4799). Elsewhere GNU make 4.4 reads it as an ordinary word, so
        # 'endef foo: X = 1' is target-specific; only the other words count.
        if first_word in LineUtils.NON_RULE_DIRECTIVE_WORDS and first_word != "endef":
            return False
        if LineUtils.parse_variable_assignment(text) is not None:
            return False
        if _is_define_or_undefine(text):
            return False
        cut = LineUtils.find_unquoted_char(text, ";#")
        head = text if cut is None else text[:cut]
        colon = LineUtils.find_unquoted_char(head, ":")
        # A bare '&' is only the grouped-target separator, so '&: X = 1' has
        # no targets and make 4.x ignores it (GNU make manual 4.10, lines
        # 2501-2502).
        if colon is None or head[:colon].strip(_WHITESPACE) in ("", "&"):
            return False
        rescans_targets = cut is None or text[cut] == "#"
        if rescans_targets and _has_semicolon_on_second_scan(head[:colon]):
            return False
        rest = head[colon + 1 :]
        if rest.startswith(":"):
            # A double-colon rule's target list (4.13).
            rest = rest[1:]
        return LineUtils.parse_variable_assignment(rest) is not None

    @staticmethod
    def is_reference_only(text: str) -> bool:
        """
        Check if a logical line is only variable references or function calls.

        The text, cut at its make comment, must contain at least one $(...)
        or ${...} and nothing else but whitespace, as in '$(info ...)',
        '$(eval $(call T,x))' or '${VAR}'. Unless it starts with the recipe
        prefix in a rule context, make expands such a line and reads the
        result as makefile syntax, which also ends any rule context (GNU make
        manual 3.8, lines 1209-1229). '$(eval ...)', '$(info ...)' and other
        calls that expand to nothing are harmless there (8.10, lines
        6381-6390); a reference that expands to a command, such as '$(MAKE)',
        makes make fail with "missing separator". This check only classifies
        the text; it does not decide what the author meant. '$$' and
        single-character references such as '$@' count as other text. An
        unterminated reference runs to the end of the text.

        Pass the logical line from join_logical_line: a physical line that
        ends with a continuation backslash has text after its references.

        Args:
            text: The logical line to check

        Returns:
            True if the line holds only references, whitespace and a comment
        """
        comment = LineUtils.find_comment_start(text)
        if comment is not None:
            text = text[:comment]
        return bool(_reference_spans(text))

    @staticmethod
    def is_function_call_only(text: str, functions: Collection[str]) -> bool:
        """
        Check if a logical line is only calls to the given make functions.

        Like is_reference_only, but every reference must be a call
        '$(NAME ARGUMENTS)' or '${NAME ARGUMENTS}' with NAME in functions:
        the name follows the bracket directly, and a blank separates it from
        the arguments (GNU make manual 8.1, lines 5588-5605). So '$(info)' is
        a reference to the variable 'info', not a call. An unterminated call
        does not count. With functions such as 'eval' and 'info', whose result
        is the empty string (8.10, lines 6388-6390; 8.13, lines 6595-6601),
        this finds lines that make reads as makefile syntax without error.

        Pass the logical line from join_logical_line.

        Args:
            text: The logical line to check
            functions: The names of the functions that may be called

        Returns:
            True if the line holds at least one call, only calls to these
            functions, whitespace and a comment
        """
        comment = LineUtils.find_comment_start(text)
        if comment is not None:
            text = text[:comment]
        spans = _reference_spans(text)
        if not spans:
            return False
        for start, end in spans:
            opener = text[start + 1]
            closer = ")" if opener == "(" else "}"
            # The reference ends where its brackets balance, or at the end of
            # the text when they never do.
            if text.count(opener, start + 1, end) != text.count(closer, start + 1, end):
                return False
            name_end = start + 2
            while name_end < end and text[name_end] not in _BLANKS:
                name_end += 1
            if name_end == end or text[start + 2 : name_end] not in functions:
                return False
        return True

    @staticmethod
    def expands_to_blanks(text: str) -> bool:
        """
        Check if a makefile line only calls functions whose result is empty.

        Calls to 'eval', 'info', 'warning' and 'error' count (see
        _EMPTY_RESULT_FUNCTIONS), and so do '$(foreach ...)' and '$(if ...)'
        calls whose TEXT, THEN-PART and ELSE-PART are blank or such calls, as in
        the manual's '$(foreach prog,$(PROGRAMS),$(eval $(call
        PROGRAM_template,$(prog))))' (GNU make manual 8.10, line 6427). make reads
        such a line as makefile syntax and ignores the blanks that it expands to.

        Args:
            text: The logical line, cut at its comment

        Returns:
            True if the line holds at least one call, and only such calls and
            whitespace
        """
        if LineUtils.is_function_call_only(text, _EMPTY_RESULT_FUNCTIONS):
            return True
        calls = _function_calls(text)
        if not calls or not any(name in _WRAPPER_FUNCTIONS for name, _, _ in calls):
            return False
        for name, arguments, opener in calls:
            if name in _EMPTY_RESULT_FUNCTIONS:
                continue
            indexes = _WRAPPER_FUNCTIONS.get(name)
            if indexes is None:
                return False
            parts = _split_arguments(arguments, opener, 3)
            if len(parts) < (3 if name == "foreach" else 2):
                return False
            for index in indexes:
                if (
                    index < len(parts)
                    and parts[index].strip(_WHITESPACE)
                    and not LineUtils.expands_to_blanks(parts[index])
                ):
                    return False
        return True

    @staticmethod
    def directive_word(text: str) -> Optional[str]:
        """
        Return the directive that a makefile line starts with, or None.

        Like GNU make 4.x, which looks for assignments before directives:
        - an assignment is not a directive, even to a variable named like
          one, as in 'export = 1' (see parse_variable_assignment);
        - 'define' and 'undefine' may follow the modifiers 'export',
          'unexport', 'override' and 'private' (GNU make manual 6.7, lines
          4776-4781; 6.9, lines 4878-4882), so 'override define X' gives
          'define';
        - every other directive is the first word, from
          NON_RULE_DIRECTIVE_WORDS (Appendix A, lines 10847-10913). A
          modifier before it is not allowed: make rejects
          'override vpath %.c src'.

        'endef' is returned wherever it is the first word, although it only
        ends a define body inside one (6.8, lines 4797-4799). make 3.81 does
        not know 'undefine', 'load', or modifiers other than 'override'
        before 'define'.

        Pass a makefile line, cut at find_comment_start, or such a logical
        line from join_logical_line; never a recipe line.

        Args:
            text: The makefile line to check

        Returns:
            The directive word, or None if the line does not start with one
        """
        if LineUtils.parse_variable_assignment(text) is not None:
            return None
        word = _define_or_undefine_word(text)
        if word is not None:
            return word
        start = _skip_whitespace(text, 0)
        first_word = text[start : _end_of_word(text, start)]
        if first_word in LineUtils.NON_RULE_DIRECTIVE_WORDS:
            return first_word
        return None

    @staticmethod
    def define_body_directive(text: str) -> Optional[str]:
        """
        Return 'define' or 'endef' if make reads a define body line as one.

        Inside a define body make reads logical lines and only looks at the first
        word of a line that does not start with the recipe prefix: 'define' nests
        another body and 'endef' ends the innermost one, each when a blank or the
        end of the line follows the word (GNU make manual 6.8, lines 4797-4799
        and 4823-4827). So 'endef # comment' ends a body and 'endef#comment'
        does not.

        Args:
            text: The logical line from LineUtils.join_logical_line, with its
                comment

        Returns:
            'define', 'endef' or None
        """
        start = len(text) - len(text.lstrip(_WHITESPACE))
        for word in ("define", "endef"):
            end = start + len(word)
            if text.startswith(word, start) and (
                end == len(text) or text[end] in _BLANKS
            ):
                return word
        return None

    @staticmethod
    def count_trailing_backslashes(text: str) -> int:
        """
        Count the backslashes at the very end of text.

        Args:
            text: The text to check

        Returns:
            The number of consecutive backslashes that end the text
        """
        return len(text) - len(text.rstrip("\\"))

    @staticmethod
    def ends_with_continuation(line: str) -> bool:
        """
        Check if a line continues on the next physical line.

        Only a backslash that is the last character of the line and is not
        escaped by another backslash continues it, so the line must end with
        an odd number of backslashes (GNU make manual 3.1, lines 730-733;
        3.1.1, lines 762-769; 5.1.1, lines 2910-2915). Trailing whitespace is
        not stripped first: a backslash followed by a space does not continue
        the line.

        Args:
            line: The physical line to check

        Returns:
            True if the line ends with an unescaped backslash
        """
        return LineUtils.count_trailing_backslashes(line) % 2 == 1

    @staticmethod
    def has_dangling_backslash(line: str) -> bool:
        """
        Check if a line ends with an unescaped backslash and then whitespace.

        make does not continue such a line, because the backslash is not the
        last character (see ends_with_continuation). Removing the trailing
        whitespace would make the line continue.

        Args:
            line: The physical line to check

        Returns:
            True if the line ends with an unescaped backslash and then only
            whitespace
        """
        stripped = line.rstrip()
        return stripped != line and LineUtils.ends_with_continuation(stripped)

    @staticmethod
    def names_target(
        lines: Sequence[str],
        target: str,
        hidden: Optional[Mapping[int, Sequence[str]]] = None,
    ) -> bool:
        """
        Check if target is a target of a rule anywhere in the lines.

        See first_target_line for the lines that count.

        Args:
            lines: The physical lines of the makefile
            target: The target name
            hidden: The lines that '# bake-format off' hides, as for
                rule_context.scan_makefile

        Returns:
            True if target is a target in the lines
        """
        return LineUtils.first_target_line(lines, target, hidden) is not None

    @staticmethod
    def first_target_line(
        lines: Sequence[str],
        target: str,
        hidden: Optional[Mapping[int, Sequence[str]]] = None,
    ) -> Optional[int]:
        """
        Find the first line that may name target as the target of a rule.

        A special target such as .ONESHELL or .POSIX takes effect when it is
        mentioned as a target (GNU make manual 4.9, lines 2410-2423). The
        lines count as make reads them (see rule_context.logical_lines_read):
        a logical line that make may read as a rule names target when target
        is one of the words before its first ':' (4.2, lines 1480-1493), or
        is in a reference there, which may expand to it. A recipe line, a
        variable assignment, a target-specific variable, a comment and a
        function call such as '$(info .POSIX: ...)' name no target (5.1,
        lines 2897-2900; 6.11, lines 4938-4951). The text of '$(eval ...)'
        is read as makefile syntax (8.10, lines 6381-6386), and so is a
        define body that it may be given: such text counts where target is
        followed by ':' or '::' that starts no assignment operator, outside a
        variable assignment or a target-specific variable.

        Args:
            lines: The physical lines of the makefile
            target: The target name
            hidden: The lines that '# bake-format off' hides, as for
                rule_context.scan_makefile

        Returns:
            The index in lines of the first line that may name target, or of
            the '# bake-format off' line that hides it; None if no line does
        """
        regions = [line for region in (hidden or {}).values() for line in region]
        if not any(target in line for line in (*lines, *regions)):
            return None
        # rule_context imports this module, so it is imported here.
        from . import rule_context

        evaluates = any("eval" in line for line in (*lines, *regions))
        pattern = re.compile(r"(?:^|[\s(,])" + re.escape(target) + r"[ \t]*::?(?![:=])")
        for index, text, kinds in rule_context.logical_lines_read(lines, hidden):
            if target not in text:
                continue
            code = text
            comment = LineUtils.find_comment_start(code)
            if comment is not None:
                code = code[:comment]
            colon = LineUtils.find_unquoted_char(code, ":")
            if rule_context.RULE in kinds and colon is not None:
                targets = code[:colon].rstrip(_WHITESPACE).removesuffix("&")
                if target in targets.split() or ("$" in targets and target in targets):
                    return index
            if "eval" in text or (rule_context.DEFINE_BODY in kinds and evaluates):
                stripped = code.strip(_WHITESPACE)
                if (
                    pattern.search(stripped)
                    and LineUtils.parse_variable_assignment(stripped) is None
                    and not LineUtils.is_target_specific_variable(stripped)
                ):
                    return index
        return None

    @staticmethod
    def join_logical_line(lines: Sequence[str], start: int) -> tuple[str, int]:
        """
        Join the physical lines of the logical line that starts at lines[start].

        This is how GNU make reads makefile syntax that is not a recipe (GNU
        make manual 3.1.1, lines 776-781). Each backslash/newline becomes a
        single space together with all the whitespace around it: the blanks
        before the backslash, the blanks at the start of the next line, and
        any backslash/newlines that follow. All other whitespace is kept,
        including the leading whitespace of the first line and the trailing
        whitespace of the last one, which can be part of a variable value
        (6.2.2, lines 4273-4288). Like make, the escaped backslashes before a
        backslash/newline are halved: 'a\\\\\\' then 'b' gives 'a\\ b'.
        A comment continues the same way (3.1, lines 730-733).

        A continuation on the last line ends the logical line, read as if the
        file ended with a newline: ['X = a \\'] gives 'X = a '. .POSIX mode
        (lines 783-786) is not modelled.
        Recipe lines keep their backslash/newlines (5.1.1, lines 2917-2920),
        so do not join them with this.

        Args:
            lines: The physical lines
            start: The index of the first physical line of the logical line

        Returns:
            The logical line and the index of the first line after it

        Raises:
            IndexError: If start is not a valid index into lines
        """
        if not 0 <= start < len(lines):
            raise IndexError(f"line index {start} out of range")
        text = ""
        index = start
        while True:
            piece = lines[index]
            if index > start:
                piece = piece.lstrip(_BLANKS)
            index += 1
            backslashes = LineUtils.count_trailing_backslashes(piece)
            if backslashes % 2 == 0:
                return text + piece, index
            text += piece[: len(piece) - backslashes] + "\\" * (backslashes // 2)
            text = text.rstrip(_BLANKS) + " "
            if index >= len(lines):
                return text, index


# The blanks at which a shell splits words (its default IFS, without the
# newline, which a logical recipe line only holds after a backslash)
_SHELL_BLANKS = (" ", "\t")

# The shell operators that end a word, so that blanks next to them are not
# needed ('exit 1;fi' runs as 'exit 1; fi'), and the characters that can be
# part of one operator with them, such as '&&', ';;', '>&' or '>|'
_SHELL_OPERATORS = ";&|"
_SHELL_OPERATOR_PARTS = ";&|<>"

# What make removes from the start of a command before it runs the shell: the
# recipe prefix comes off first, then blanks and the '@', '-' and '+'
# characters (GNU make manual 5.2, lines 3037-3038; 5.5, lines 3507-3509;
# 5.3.1, lines 3107-3108)
_COMMAND_FLAGS = " \t@-+"

# The programs that read a recipe line as a POSIX shell does: a backslash/
# newline continues the line outside quotes and inside double quotes, it stays
# inside single quotes (GNU make manual 5.1.1, lines 2946-2969), and blanks
# only separate words
_POSIX_SHELLS = frozenset({"sh", "bash", "dash", "ash", "ksh", "zsh"})

# A define of SHELL, with any modifiers and operator (GNU make manual 6.8,
# lines 4795-4799 and 4816-4821)
_DEFINE_SHELL = re.compile(
    r"(?:(?:export|unexport|override|private)[ \t]+)*define[ \t]+SHELL(?![^ \t:+?!=])"
)

# An assignment or a define of SHELL anywhere in a text, such as the text of
# '$(eval ...)' (GNU make manual 6.5, lines 4577-4579; 6.8, lines 4795-4799)
_ASSIGNS_SHELL = re.compile(
    r"(?<![\w.$-])SHELL[ \t]*(?:[+?!]|:{1,3})?=|define[ \t]+SHELL(?![^ \t:+?!=])"
)


def _names_posix_shell(operator: str, value: str) -> bool:
    """Check if an assignment leaves SHELL a program of _POSIX_SHELLS.

    make runs the first word of SHELL's value as the shell program, and
    gives it the words after it, such as '-o pipefail', as arguments (GNU
    make manual 5.3.2, lines 3170-3174), so only the first word counts: with
    or without a directory and with or without '.exe'. A first word with a
    '$' is expanded by make, and the output of a '!=' command is not known
    (6.5, lines 4624-4630). '+=' adds words after the program, which stays
    the one that the other assignments set, or '/bin/sh' (6.6, lines
    4652-4660; 5.3.2, lines 3170-3171).
    """
    if operator == "+=":
        return True
    words = value.split()
    if operator == "!=" or not words or "$" in words[0]:
        return False
    name = words[0].replace("\\", "/").rsplit("/", 1)[-1]
    if name.lower().endswith(".exe"):
        name = name[: -len(".exe")]
    return name in _POSIX_SHELLS


def _sets_other_shell(code: str) -> bool:
    """Check if a logical line, cut at its comment, may set SHELL to a program
    other than a POSIX shell: a plain, target- or pattern-specific assignment
    with any operator and modifiers, or a define of SHELL (GNU make manual
    6.11, lines 4938-4951)."""
    if "SHELL" not in code:
        return False
    text = code.strip(_WHITESPACE)
    if _DEFINE_SHELL.match(text):
        return True
    assignment = LineUtils.parse_variable_assignment(text)
    if assignment is None and LineUtils.is_target_specific_variable(text):
        colon = LineUtils.find_unquoted_char(text, ":")
        if colon is not None:
            rest = text[colon + 1 :]
            if rest.startswith(":"):
                rest = rest[1:]
            assignment = LineUtils.parse_variable_assignment(rest)
    if assignment is None or assignment.name != "SHELL":
        return False
    return not _names_posix_shell(assignment.operator, assignment.value)


def _recipe_shell_pieces(
    block: Sequence[str], prefix: str, command_start: bool = True
) -> list[str]:
    """Return the text that make passes to the shell from each line of a
    logical recipe line: without the recipe prefix that starts a line (GNU
    make manual 5.1.1, lines 2917-2925), and on the first line, with
    command_start, also without the blanks and the '@', '-' and '+' before
    the command (_COMMAND_FLAGS). With .ONESHELL make checks those only on
    the first line of a recipe (5.3.1, lines 3107-3110), so command_start is
    False where that is not known. The backslashes that continue the lines
    stay."""
    pieces = []
    for index, line in enumerate(block):
        if prefix and line.startswith(prefix):
            line = line[len(prefix) :]
        if index == 0 and command_start:
            line = line.lstrip(_COMMAND_FLAGS)
        pieces.append(line)
    return pieces


# Where a line break of recipe text stands for the shell (see
# _line_break_states): outside quotes, inside quotes or a here-document, or
# at the end of a shell comment
_PLAIN = "plain"
_QUOTED = "quoted"
_COMMENT = "comment"

# The characters after which a '#' starts a shell comment: the start of the
# text, a blank, the newline that ends a comment, and the operator characters.
# Inside a word, as in 'a#b' or '$$#', a '#' is text.
_COMMENT_AFTER = frozenset({"", " ", "\t", "\n", ";", "&", "|", "(", ")", "<", ">"})


def _opens_ansi_c_quote(text: str, index: int) -> bool:
    """
    Check if the "'" at text[index] starts a $'...' string for the shell.

    make passes each '$$' of a recipe to the shell as one '$' (GNU make
    manual 5.1.2, lines 3005-3006), so the shell gets "$'" where two '$' come
    before the quote, or six. Four give the shell '$$' and a plain quote. An
    odd number ends in a make reference, "$'", which counts as a plain quote,
    as before. bash, ksh and zsh read $'...' as quoted text in which a
    backslash escapes the next character, so "\\'" does not end it.
    """
    run = 0
    while index - run > 0 and text[index - run - 1] == "$":
        run += 1
    return run % 4 == 2


def _line_break_states(pieces: Sequence[str]) -> list[str]:
    """
    Return where each line break of the recipe text stands for the shell.

    Each line break follows the backslash that continues a line (see
    _recipe_shell_pieces). It is _QUOTED inside single or double quotes,
    inside $'...' (see _opens_ansi_c_quote), or after '<<', which starts a
    here-document: there the blanks around it are text, not word separators
    (GNU make manual 5.1.1, lines 2946-2969). It is _COMMENT where the
    backslash is part of a shell comment: make passes comments in a recipe
    to the shell (3.1, lines 744-746), and a '#' that starts a word starts a
    comment that ends at the newline, so the backslash before it is comment
    text that continues nothing, and quotes in the comment are text too
    (sh, bash, dash, ksh and zsh all run 'echo b' after 'echo a # c \\' and
    a newline). Elsewhere it is _PLAIN.
    """
    text = "\n".join(pieces)
    states: list[str] = []
    quote = ""
    comment = False
    heredoc = False
    # The character before the current one as the shell reads it, outside
    # comments, so that a '#' at the start of a word is found
    previous = ""
    index = 0
    while index < len(text):
        char = text[index]
        if comment:
            if char == "\n":
                states.append(_QUOTED if heredoc else _COMMENT)
                comment = False
                previous = char
            index += 1
            continue
        if quote == "'":
            if char == "'":
                quote = ""
            elif char == "\n":
                states.append(_QUOTED)
            previous = char
            index += 1
            continue
        if char == "\\":
            if text.startswith("\n", index + 1):
                states.append(_QUOTED if quote or heredoc else _PLAIN)
            else:
                # The backslash quotes the next character.
                previous = text[index + 1 : index + 2]
            index += 2
            continue
        if char == "\n":
            states.append(_QUOTED if quote or heredoc else _PLAIN)
        elif quote:
            if char == quote[-1]:
                quote = ""
        elif char == "'":
            quote = "$'" if _opens_ansi_c_quote(text, index) else "'"
        elif char == '"':
            quote = char
        elif char == "#" and previous in _COMMENT_AFTER:
            comment = True
        elif text.startswith("<<", index):
            heredoc = True
        previous = char
        index += 1
    return states


def _quoted_line_breaks(pieces: Sequence[str]) -> list[bool]:
    """Return, for each line break of the recipe text, whether it is inside
    quotes or a here-document (see _line_break_states)."""
    return [state == _QUOTED for state in _line_break_states(pieces)]


def _leading_blanks(line: str) -> str:
    """Return the blanks that start a line."""
    return line[: len(line) - len(line.lstrip(" \t"))]


def _blank_is_optional(before: tuple[str, str], after: tuple[str, str]) -> bool:
    """
    Check if blanks between two characters outside quotes change nothing.

    A POSIX shell ends a word at an operator, so a blank next to ';', '&' or
    '|' is not needed to end the word on its other side: 'exit 1;fi' runs as
    'exit 1; fi', and 'a|b' as 'a | b'. The same holds next to the newline
    that ends a shell comment, which ends the command. That does not hold
    where the other side is part of an operator too, which the blank may
    split, as in '&&', ';;', '>&' or '>|'. An escaped or quoted ';', '&' or
    '|' is part of a word, as in '\\;'.

    Args:
        before: The character before the blanks, as a (kind, character)
            pair of _shell_text
        after: The character after them, as such a pair

    Returns:
        True if the shell reads the same with and without the blanks
    """
    if before == ("op", "\n") or after == ("op", "\n"):
        return True
    if before[0] == "op" and before[1] in _SHELL_OPERATORS:
        return after[0] != "op"
    if after[0] == "op" and after[1] in _SHELL_OPERATORS:
        return before[0] != "op"
    return False


def _shell_text(pieces: Sequence[str]) -> tuple[tuple[str, str], ...]:
    """
    Return what a POSIX shell reads in the text of a recipe line.

    pieces is the text that make passes on from each line (see
    _recipe_shell_pieces). The shell removes each backslash/newline outside
    single quotes, and a backslash quotes the next character outside single
    quotes (GNU make manual 5.1.1, lines 2946-2969). Outside quotes a run of
    blanks only separates words, so it counts as one blank, and blanks that
    only stand next to an operator count for nothing (see
    _blank_is_optional). Quoted text, $'...' text (see _opens_ansi_c_quote)
    and all text from '<<', which starts a here-document, count as written.
    A shell comment counts for nothing: it runs from a '#' that starts a
    word to the newline, which ends the command (see _line_break_states).

    Returns:
        The text as (kind, character) pairs: kind 'blank' for a run of blanks
        that separates two words, 'op' for an operator character (';&|<>')
        outside quotes that no backslash escapes and for the newline after a
        comment, and 'text' for every other character
    """
    text = "\n".join(pieces)
    units: list[tuple[str, str]] = []
    quote = ""
    comment = False
    previous = ""
    index = 0
    while index < len(text):
        char = text[index]
        if comment:
            if char == "\n":
                units.append(("op", char))
                comment = False
                previous = char
            index += 1
            continue
        if quote == "'":
            units.append(("text", char))
            if char == "'":
                quote = ""
        elif char == "\\":
            if quote == "$'" or not text.startswith("\n", index + 1):
                units.append(("text", char))
                units.extend(
                    ("text", escaped) for escaped in text[index + 1 : index + 2]
                )
                previous = text[index + 1 : index + 2]
            # Outside single quotes and $'...', a backslash/newline is a line
            # continuation, which the shell removes.
            index += 2
            continue
        elif quote:
            units.append(("text", char))
            if char == quote[-1]:
                quote = ""
        elif char in "'\"":
            quote = "$'" if char == "'" and _opens_ansi_c_quote(text, index) else char
            units.append(("text", char))
        elif char == "#" and previous in _COMMENT_AFTER:
            comment = True
        elif text.startswith("<<", index):
            units.extend(("text", rest) for rest in text[index:])
            break
        elif char in _SHELL_BLANKS:
            if units and units[-1][0] != "blank":
                units.append(("blank", " "))
        else:
            units.append(("op" if char in _SHELL_OPERATOR_PARTS else "text", char))
        previous = char
        index += 1
    while units and units[-1][0] == "blank":
        units.pop()
    return tuple(
        unit
        for position, unit in enumerate(units)
        if unit[0] != "blank"
        or not _blank_is_optional(units[position - 1], units[position + 1])
    )


class ShellUtils:
    """Utilities for processing shell commands within Makefile recipes."""

    # Keywords for shell control structures
    START_KEYWORDS = ("if", "for", "while", "case", "until")
    CONTINUATION_KEYWORDS = ("elif", "else")
    END_KEYWORDS = ("fi", "done", "esac")
    END_KEYWORDS_WITH_SEMICOLON = ("fi;", "done;", "esac;")

    # All keywords combined, for comprehensive checks
    ALL_KEYWORDS = (
        START_KEYWORDS
        + CONTINUATION_KEYWORDS
        + END_KEYWORDS
        + END_KEYWORDS_WITH_SEMICOLON
    )

    # Simple keywords for checking if a line contains any shell control structures
    SIMPLE_KEYWORDS = START_KEYWORDS + CONTINUATION_KEYWORDS + ("do", "then")

    # Common shell operators
    OPERATORS = ("&&", "||", ";", "|", ">", "<", ">>", "<<", "$(", "`")

    @staticmethod
    def is_shell_control_start(line: str) -> bool:
        """Check if a line starts a shell control structure."""
        # Strip make command prefixes (@, -, +)
        stripped = line.lstrip("@-+ ")

        # More precise matching than just startswith, to avoid matching substrings
        control_patterns = [
            r"^if\s+\[",
            r"^for\s+",
            r"^while\s+",
            r"^case\s+",
            r"^until\s+",
            r"^{\s*$",
        ]
        return any(re.match(pattern, stripped) for pattern in control_patterns)

    @staticmethod
    def is_shell_control_end(line: str) -> bool:
        """Check if a line ends a shell control structure."""
        stripped = line.lstrip("@-+ \t").rstrip()
        return any(stripped.startswith(kw) for kw in ShellUtils.END_KEYWORDS) or any(
            stripped.endswith(kw) for kw in ShellUtils.END_KEYWORDS_WITH_SEMICOLON
        )

    @staticmethod
    def contains_shell_operators(line: str) -> bool:
        """Check if content contains shell operators that suggest deliberate structure."""
        return any(op in line for op in ShellUtils.OPERATORS)

    @staticmethod
    def uses_oneshell(
        lines: Sequence[str], hidden: Optional[Mapping[int, Sequence[str]]] = None
    ) -> bool:
        """
        Check if a makefile names .ONESHELL as a target.

        make then gives all recipe lines of a target to one shell, newlines
        included, wherever the target appears in the makefile (GNU make
        manual 4.9, lines 2410-2415; 5.3.1, lines 3094-3097), so the
        whitespace of any recipe line may be part of a script. See
        LineUtils.first_target_line for the lines that count.

        Args:
            lines: The physical lines of the makefile
            hidden: The lines that '# bake-format off' hides, as for
                rule_context.scan_makefile

        Returns:
            True if .ONESHELL is a target in the lines
        """
        return LineUtils.names_target(lines, ".ONESHELL", hidden)

    @staticmethod
    def recipes_are_shell_opaque(
        lines: Sequence[str], hidden: Optional[Mapping[int, Sequence[str]]] = None
    ) -> bool:
        """
        Check if the formatter cannot know which whitespace of a recipe matters.

        That is so when .ONESHELL is a target (see uses_oneshell), and when
        SHELL is set anywhere in the makefile to anything but sh, bash, dash,
        ash, ksh or zsh, with or without a directory and with or without
        '.exe', for example to a value with a '$', which make expands, or to
        the output of a command: another program reads backslash/newlines
        and blanks in its own way (GNU make manual 5.1.1, lines 2965-2969;
        5.3.2, lines 3170-3174). An assignment to SHELL counts wherever make
        may read the line as makefile syntax (see
        rule_context.logical_lines_read), with any operator and modifiers,
        target- and pattern-specific ones and a define of SHELL included
        (6.11, lines 4938-4951). A recipe line such as 'SHELL=/bin/sh ./run'
        sets no make variable (5.1, lines 2897-2900). The text of
        '$(eval ...)', and a define body that it may be given, count where
        they assign SHELL at all. .SHELLFLAGS alone does not count.

        Args:
            lines: The physical lines of the makefile
            hidden: The lines that '# bake-format off' hides, as for
                rule_context.scan_makefile

        Returns:
            True if every recipe of the makefile is to be left as written
        """
        if ShellUtils.uses_oneshell(lines, hidden):
            return True
        regions = [line for region in (hidden or {}).values() for line in region]
        if not any("SHELL" in line for line in (*lines, *regions)):
            return False
        # rule_context imports this module, so it is imported here.
        from . import rule_context

        evaluates = any("eval" in line for line in (*lines, *regions))
        for _index, text, kinds in rule_context.logical_lines_read(lines, hidden):
            if "SHELL" not in text:
                continue
            if kinds - {rule_context.RECIPE, rule_context.DEFINE_BODY}:
                comment = LineUtils.find_comment_start(text)
                if _sets_other_shell(text if comment is None else text[:comment]):
                    return True
            if (
                "eval" in text or (rule_context.DEFINE_BODY in kinds and evaluates)
            ) and _ASSIGNS_SHELL.search(text):
                return True
        return False

    @staticmethod
    def recipe_block_is_whitespace_sensitive(
        block: Sequence[str], prefix: str = "\t"
    ) -> bool:
        """
        Check if new blanks in a recipe line could change what the shell runs.

        block holds the physical lines of one logical recipe line (GNU make
        manual 5.1.1, lines 2910-2915). make passes its backslash/newlines to
        the shell with the whitespace around them, and removes only the one
        recipe prefix character that starts the line after each one; it never
        adds whitespace (lines 2917-2925). The block is sensitive when:
        - a backslash with no blank before it is followed by a line whose
          text, without its recipe prefix, starts with no blank: the shell
          joins the two words, so '@echo no\\' and 'space' print 'nospace'
          (lines 2927-2944). That is not so where one side is ';', '&' or '|',
          which ends a word anyway, as in 'exit 1;\\' and 'fi', unless the
          other side can be part of the same operator (see
          _blank_is_optional);
        - a backslash/newline is inside single or double quotes, inside
          $'...', or after '<<', which starts a here-document: there the
          blanks are text (lines 2946-2969).
        Elsewhere blanks only separate words, so new ones change nothing. That
        holds for a continuation line without the recipe prefix too, whose
        whitespace all goes to the shell: its leading blanks separate words
        where no word is joined to the line above it ('@echo no\\' and
        'space' are joined above), and a rewrite that makes a backslash join
        two words fails recipe_rewrite_preserves_shell_text. A backslash in
        a shell comment joins nothing: the comment ends at the newline (see
        _line_break_states).

        The quotes and comments are tracked from the start of the command,
        as a POSIX shell tracks them, with bash's $'...' (see
        _opens_ansi_c_quote). What a variable reference expands to is not
        known: a quote character that make puts in by expansion is not seen.

        Args:
            block: The physical lines of the recipe line; for a recipe after
                the ';' of a rule line, the text after the ';' comes first
            prefix: The recipe prefix (GNU make manual, lines 5158-5169)

        Returns:
            True if the block is sensitive; False for a block without
            continuation lines
        """
        if len(block) < 2:
            return False
        pieces = _recipe_shell_pieces(block, prefix)
        states = _line_break_states(pieces)
        for index in range(len(pieces) - 1):
            piece = pieces[index]
            if not LineUtils.ends_with_continuation(piece) or (
                index < len(states) and states[index] == _COMMENT
            ):
                continue
            body = piece[:-1]
            before = body[-1:]
            after = pieces[index + 1][:1]
            if before in _SHELL_BLANKS or not after or after in _SHELL_BLANKS:
                continue
            escaped = bool(before) and _backslashes_before(body, len(body) - 1) % 2 == 1
            before_kind = (
                "op"
                if before and before in _SHELL_OPERATOR_PARTS and not escaped
                else "text"
            )
            after_kind = "op" if after in _SHELL_OPERATOR_PARTS else "text"
            if not _blank_is_optional((before_kind, before), (after_kind, after)):
                return True
        return _QUOTED in states

    @staticmethod
    def last_line_starts_in_quotes(block: Sequence[str], prefix: str = "\t") -> bool:
        """
        Check if the last line of a recipe line starts inside quoted text.

        That is so where the backslash/newline before it is inside single or
        double quotes, inside $'...', or after '<<', which starts a
        here-document (see _line_break_states): the blanks at the start of
        the line are then text that the shell gets (GNU make manual 5.1.1,
        lines 2946-2969).

        Args:
            block: The physical lines of the recipe line, up to the line to
                check; for a recipe after the ';' of a rule line, the text
                after the ';' comes first
            prefix: The recipe prefix (GNU make manual, lines 5158-5169)

        Returns:
            True if the last line starts inside quotes or a here-document
        """
        if len(block) < 2:
            return False
        breaks = _quoted_line_breaks(_recipe_shell_pieces(block, prefix))
        return bool(breaks) and breaks[-1]

    @staticmethod
    def recipe_rewrite_preserves_shell_text(
        old: Sequence[str], new: Sequence[str], prefix: str = "\t"
    ) -> bool:
        """
        Check if a rewrite of a recipe line gives the shell the same words.

        Both versions are read as make passes them to the shell: without the
        one recipe prefix character after each backslash/newline, which is
        all that make removes (GNU make manual 5.1.1, lines 2917-2925), and
        without the blanks and the '@', '-' and '+' that start the command.
        A rewrite holds if that text is the same, or if a POSIX shell reads
        the same words and operators in it (see _shell_text), and the number
        of lines is the same.

        Args:
            old: The physical lines of the recipe line before the rewrite
            new: The lines after it
            prefix: The recipe prefix (GNU make manual, lines 5158-5169)

        Returns:
            True if the shell gets the same words
        """
        if len(old) != len(new):
            return False
        old_pieces = _recipe_shell_pieces(old, prefix)
        new_pieces = _recipe_shell_pieces(new, prefix)
        return old_pieces == new_pieces or _shell_text(old_pieces) == _shell_text(
            new_pieces
        )

    @staticmethod
    def keep_shell_text(
        old: Sequence[str],
        new: Sequence[str],
        prefix: str = "\t",
        opaque: bool = False,
        fallbacks: Sequence[Sequence[str]] = (),
    ) -> list[str]:
        """
        Return a rewrite of a recipe line without the line changes that change a command.

        The lines are taken from the top, each with the lines above it as
        they are by then. A line keeps its rewrite where the shell still gets
        the same words and operators from the whole recipe line, quoted text,
        here-documents and words that a backslash joins included (see
        recipe_rewrite_preserves_shell_text); otherwise it stays as it was in
        old. A change that leaves the line's text as make passes it to the
        shell always holds: make removes one recipe prefix character after a
        backslash/newline, so giving the prefix to a line without it, or
        taking it from a line, changes nothing that the shell gets (GNU make
        manual 5.1.1, lines 2917-2925), whatever the shell and the quotes.
        The one exception is the start of a line that begins inside quotes or
        a here-document (see last_line_starts_in_quotes): make 3.81 removes a
        TAB there before it runs the shell, but prints it, as part of the
        quoted text, in the command that it echoes, so the blanks that start
        such a line stay as they are.

        Args:
            old: The physical lines of the recipe line
            new: The lines of the rewrite, as many as in old
            prefix: The recipe prefix (GNU make manual, lines 5158-5169)
            opaque: The makefile is one where the shell is not known (see
                recipes_are_shell_opaque): only the changes that leave the
                text as it is hold, and the blanks at the start of the first
                line count too, which make passes on with .ONESHELL (5.3.1,
                lines 3107-3110)
            fallbacks: Other rewrites, each as many lines as old, whose line
                is tried, in order, where the line of new does not hold

        Returns:
            The lines, each from new, from a fallback or from old
        """
        result = list(old)
        old_pieces = _recipe_shell_pieces(old, prefix, not opaque)
        old_text: Optional[tuple[tuple[str, str], ...]] = None
        # Whether each line starts inside quotes or a here-document
        quoted = [False, *_quoted_line_breaks(old_pieces)]
        for index in range(len(old)):
            for rewrite in (new, *fallbacks):
                line = rewrite[index]
                if line == old[index]:
                    break
                if quoted[index] and _leading_blanks(line) != _leading_blanks(
                    old[index]
                ):
                    continue
                candidate = [*result[:index], line, *result[index + 1 :]]
                pieces = _recipe_shell_pieces(candidate, prefix, not opaque)
                if pieces[index] == old_pieces[index]:
                    # The shell gets this line's text as before.
                    result = candidate
                    break
                if opaque:
                    continue
                if old_text is None:
                    old_text = _shell_text(old_pieces)
                if _shell_text(pieces) == old_text:
                    result = candidate
                    break
        return result


class MakefileParser:
    """Utilities for parsing Makefile structure and extracting targets."""

    @staticmethod
    def parse_targets_and_recipes(lines: list[str]) -> list[tuple[str, list[str]]]:
        """
        Parse all targets and their recipe lines from the Makefile.

        This is commonly used across phony rules to extract target information.

        Args:
            lines: List of lines from the Makefile

        Returns:
            List of tuples containing (target_name, recipe_lines)
        """
        targets: list[tuple[str, list[str]]] = []
        current_target: Union[str, None] = None
        current_recipe: list[str] = []

        for line in lines:
            stripped = line.strip()

            # Skip lines that don't contribute to target structure
            if LineUtils.should_skip_makefile_line(line):
                continue

            # Check if this is a target line (has colon and is not indented)
            if ":" in stripped and not line.startswith("\t"):
                # Save previous target if exists
                if current_target:
                    targets.append((current_target, current_recipe.copy()))

                # Check if this is a variable assignment
                if LineUtils.is_variable_assignment_with_colon(line):
                    current_target = None
                    current_recipe = []
                    continue

                # Parse target name (everything before first colon)
                target_part = stripped.split(":")[0].strip()

                # Skip pattern rules, special targets, and complex targets
                if MakefileParser._should_skip_target(target_part):
                    current_target = None
                    current_recipe = []
                    continue

                current_target = target_part
                current_recipe = []

            # Check if this is a recipe line
            elif line.startswith("\t") and current_target:
                current_recipe.append(line.strip())

        # Don't forget the last target
        if current_target:
            targets.append((current_target, current_recipe.copy()))

        return targets

    @staticmethod
    def _should_skip_target(target_part: str) -> bool:
        """
        Check if a target should be skipped during parsing.

        Args:
            target_part: The target name part of the line

        Returns:
            True if this target should be skipped
        """
        return (
            target_part in ALL_SPECIAL_MAKE_TARGETS
            or target_part.startswith(".")
            or "%" in target_part
            or "$" in target_part
            or " " in target_part  # Multiple targets
            or not target_part  # Empty target
        )

    @staticmethod
    def extract_phony_targets(lines: list[str]) -> set[str]:
        """
        Extract targets from existing .PHONY declarations.

        Args:
            lines: List of lines from the Makefile

        Returns:
            Set of target names found in .PHONY declarations
        """
        phony_targets = set()

        for line in lines:
            stripped = line.strip()
            if stripped.startswith(".PHONY:"):
                # Remove .PHONY: prefix and any line continuation
                content = stripped[7:].strip()  # Remove '.PHONY:'

                # Handle continuation character
                if content.endswith("\\"):
                    content = content[:-1].strip()

                targets = [t.strip() for t in content.split() if t.strip()]
                phony_targets.update(targets)

        return phony_targets

    @staticmethod
    def has_phony_declarations(lines: list[str]) -> bool:
        """
        Check if the Makefile has any .PHONY declarations.

        Args:
            lines: List of lines from the Makefile

        Returns:
            True if .PHONY declarations exist
        """
        return any(line.strip().startswith(".PHONY:") for line in lines)

    @staticmethod
    def find_phony_insertion_point(lines: list[str]) -> int:
        """
        Find the best place to insert .PHONY declarations at the top.

        Uses enhanced logic that respects comment blocks and variable continuations:
        - Treats contiguous comments as file header
        - Inserts .PHONY after first blank line following header comments
        - Preserves section comments that come after variables/blank lines
        - Never inserts between a line that continues on the next one, such
          as a header comment (GNU make manual 3.1, lines 730-733), and a
          line with text that it continues over: the '.PHONY:' line and the
          blank line after it would end the logical line there, and make
          would read that text on its own. A line continues only where an odd
          number of backslashes ends it, so a backslash that whitespace
          follows continues none (3.1.1, lines 762-769). Before a blank line
          that ends such a line, the declaration becomes part of it, which
          changes nothing that make reads
        - Properly handles multiline variable assignments: a line at column 1
          that no backslash above continues, such as a rule, also one that
          continues itself, starts a new statement, so the line never lands
          between a rule and its recipe. An indented line after a line that
          ends with a backslash stays with that line, as before: '.PHONY:'
          right above it would give it a rule context (5.1, lines 2878-2884),
          in which TabsRule gives a space-led line a TAB on the next run, and
          make reads a TAB-led one as a recipe line

        Args:
            lines: List of lines from the Makefile

        Returns:
            Index where .PHONY should be inserted
        """
        in_header_comments = True
        last_comment_index = -1
        in_variable_block = False

        for i, line in enumerate(lines):
            stripped = line.strip()

            if stripped and i > 0 and LineUtils.ends_with_continuation(lines[i - 1]):
                # Text that the logical line above it continues over
                continue

            if not stripped:  # Empty line
                if in_header_comments and last_comment_index >= 0:
                    # Found blank line after header comments - insert here
                    return i
                # If we were in a variable block, this marks the end
                in_variable_block = False
                # Continue looking (empty line in middle of file)
                continue

            elif stripped.startswith("#"):  # Comment
                if not in_header_comments:
                    # This is a section comment after variables/rules, skip it
                    continue
                last_comment_index = i
                continue

            elif (
                "=" in stripped
                or stripped.startswith("include")
                or stripped.startswith("-include")
            ):
                # Variable assignment or include - part of declarations
                in_header_comments = False
                in_variable_block = True
                continue

            elif (
                in_variable_block
                and line[:1] in (" ", "\t")
                and LineUtils.ends_with_continuation(line)
            ):
                # An indented line that continues stays with the block, as
                # before; a line at column 1 starts a new statement, such as a
                # continued rule, whose recipe a '.PHONY:' line above it
                # would take over (GNU make manual 5.1, lines 2878-2884)
                continue

            elif (
                in_variable_block
                and i > 0
                and line[:1] in (" ", "\t")
                and lines[i - 1].rstrip().endswith("\\")
            ):
                # An indented line after a backslash that continues nothing
                continue

            else:
                # First rule/target found or end of variable block
                return i

        # If we get here, insert at the end
        return len(lines)


class ConditionalTracker:
    """Utility for tracking conditional contexts in Makefiles."""

    def __init__(self) -> None:
        """Initialize the conditional tracker."""
        self.conditional_stack: list[dict[str, Any]] = []
        self.conditional_branch_id: int = 0

    def process_line(self, line: str, line_index: int) -> tuple:
        """Process a line and return the conditional context the line is IN.

        Args:
            line: The line to process
            line_index: Index of the line (for debugging)

        Returns:
            Tuple representing the conditional context the line is IN
        """
        stripped = line.strip()

        # Get current context BEFORE processing conditional directives
        # This way we return the context the line is IN, not the context after processing it
        current_context = tuple(block["branch_id"] for block in self.conditional_stack)

        # Track conditional blocks (update state after getting current context)
        if stripped.startswith(("ifeq", "ifneq", "ifdef", "ifndef")):
            self.conditional_stack.append(
                {
                    "type": "if",
                    "line": line_index,
                    "branch_id": self.conditional_branch_id,
                }
            )
            self.conditional_branch_id += 1
        elif stripped.startswith("else"):
            if self.conditional_stack and self.conditional_stack[-1]["type"] == "if":
                self.conditional_stack[-1]["type"] = "else"
                self.conditional_stack[-1]["branch_id"] = self.conditional_branch_id
                self.conditional_branch_id += 1
        elif stripped.startswith("endif"):
            if self.conditional_stack:
                self.conditional_stack.pop()

        # Return the context the line was IN (before processing)
        return current_context

    def reset(self) -> None:
        """Reset the tracker state."""
        self.conditional_stack = []
        self.conditional_branch_id = 0

    @staticmethod
    def are_mutually_exclusive(context1: tuple, context2: tuple) -> bool:
        """Check if two conditional contexts are mutually exclusive.

        Two contexts are mutually exclusive if they differ at any conditional level,
        which means they're in different branches of some conditional block.

        Args:
            context1: First conditional context
            context2: Second conditional context

        Returns:
            True if contexts are mutually exclusive
        """
        # If contexts are identical, not mutually exclusive
        if context1 == context2:
            return False

        # If one context is empty and the other not, not mutually exclusive
        # in the sense that one is unconditional and the other is conditional
        if not context1 or not context2:
            return False

        # Compare contexts level by level
        min_len = min(len(context1), len(context2))

        # If contexts differ at any level, mutually exclusive
        return any(context1[i] != context2[i] for i in range(min_len))


class PhonyAnalyzer:
    """Utilities for analyzing whether targets are phony."""

    @staticmethod
    def is_target_phony(
        target_name: str, recipe_lines: list[str], all_lines: Optional[list[str]] = None
    ) -> bool:
        """
        Determine if a target is phony by analyzing its recipe.

        Args:
            target_name: Name of the target
            recipe_lines: List of recipe command lines
            all_lines: All lines in the Makefile for context analysis

        Returns:
            True if the target is likely phony
        """
        if not recipe_lines:
            # No recipe could mean:
            # 1. Phony target (like .PHONY: help)
            # 2. Dependency-only rule (like header.h: source.c)
            #
            # File targets (especially .h, .o, .c, .cpp, etc.) with no recipe
            # are typically dependency-only rules, not phony targets
            # Otherwise assume it's phony (like help, clean, etc.)
            return not PhonyAnalyzer._looks_like_file_target(target_name, all_lines)

        # Analyze recipe commands to determine if they create a file with target_name
        creates_target_file = False

        for recipe_line in recipe_lines:
            # Remove variable expansions and quotes for analysis
            clean_line = PhonyAnalyzer._clean_command_for_analysis(recipe_line)

            # Check for file creation patterns that create target file
            if PhonyAnalyzer._command_creates_target_file(clean_line, target_name):
                creates_target_file = True
                break

        # Target is phony if it doesn't create a file with its own name
        return not creates_target_file

    @staticmethod
    def _looks_like_file_target(
        target_name: str, all_lines: Optional[list[str]] = None
    ) -> bool:
        """
        Check if a target name looks like a file target using dynamic analysis.

        Args:
            target_name: Name of the target
            all_lines: All lines in the Makefile for context analysis

        Returns:
            True if the target name looks like a file target
        """
        # If we have context, use dynamic analysis
        if all_lines:
            return PhonyAnalyzer._analyze_file_patterns_dynamically(
                target_name, all_lines
            )

        # Fallback to basic heuristics if no context available
        return PhonyAnalyzer._basic_file_target_heuristics(target_name)

    @staticmethod
    def _analyze_file_patterns_dynamically(
        target_name: str, all_lines: list[str]
    ) -> bool:
        """
        Dynamically analyze the Makefile to determine if target looks like a file.

        Args:
            target_name: Name of the target to analyze
            all_lines: All lines in the Makefile

        Returns:
            True if target appears to be a file based on Makefile patterns
        """
        # First check if it looks like an action target by name
        if PhonyAnalyzer._looks_like_action_target(target_name):
            return False

        # Extract all extensions used in the Makefile
        discovered_extensions = PhonyAnalyzer._discover_file_extensions(all_lines)

        # Check if target has an extension that appears elsewhere in the Makefile
        if "." in target_name:
            ext = "." + target_name.split(".")[-1].lower()
            if ext in discovered_extensions:
                return True

        # Check if target appears in file-related contexts
        if PhonyAnalyzer._appears_in_file_contexts(target_name, all_lines):
            return True

        # Check if target follows naming patterns of other file targets
        if PhonyAnalyzer._matches_file_naming_patterns(target_name, all_lines):
            return True

        # Check if target's recipe suggests it's a file target
        return PhonyAnalyzer._recipe_suggests_file_target(target_name, all_lines)

    @staticmethod
    def _recipe_suggests_file_target(target_name: str, all_lines: list[str]) -> bool:
        """
        Analyze target's recipe to determine if it creates a file.
        Uses structural analysis, not semantic command knowledge.

        Args:
            target_name: Name of the target
            all_lines: All lines in the Makefile

        Returns:
            True if recipe suggests target creates a file
        """
        # Find the target definition and its recipe
        target_pattern = re.compile(rf"^{re.escape(target_name)}:")

        for i, line in enumerate(all_lines):
            if target_pattern.match(line.strip()):
                # Get recipe lines for this target
                recipe_lines = []
                for j in range(i + 1, len(all_lines)):
                    recipe_line = all_lines[j]
                    if recipe_line.startswith("\t"):
                        recipe_lines.append(recipe_line.strip())
                    elif recipe_line.strip():  # Non-empty, non-recipe line
                        break

                # If no recipe, check if target has file-like characteristics
                if not recipe_lines:
                    # Targets with extensions are likely files even without recipes
                    if "." in target_name and not target_name.startswith("."):
                        return True
                    # Targets with paths are likely files
                    return "/" in target_name or "\\" in target_name

                # Analyze recipe for file creation patterns
                for recipe in recipe_lines:
                    cleaned_recipe = PhonyAnalyzer._clean_command_for_analysis(recipe)

                    # Check if command creates target file using structural patterns
                    if PhonyAnalyzer._command_creates_target_file(
                        cleaned_recipe, target_name
                    ):
                        return True

                    # Output redirection patterns (structural, not command-specific)
                    if any(op in recipe for op in [" > ", " >> ", " 2> "]):
                        return True

                    # Structural indicators of file creation (not semantic)
                    # Look for patterns that suggest file output
                    if any(
                        pattern in recipe
                        for pattern in [
                            "$@",  # Make automatic variable for target
                            "$< $@",  # Common Make pattern: input to output
                        ]
                    ):
                        return True

                break

        return False

    @staticmethod
    def _discover_file_extensions(all_lines: list[str]) -> set[str]:
        """
        Discover file extensions used throughout the Makefile.
        Completely dynamic - no hardcoded exclusions.

        Args:
            all_lines: All lines in the Makefile

        Returns:
            Set of discovered file extensions
        """
        extensions = set()

        for line in all_lines:
            # Skip comments and empty lines
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Find all words that look like filenames (contain dots)
            import re

            # Match words with extensions (word.ext pattern)
            filename_pattern = r"\b\w+\.\w+\b"
            matches = re.findall(filename_pattern, stripped)

            for match in matches:
                # Extract extension
                if "." in match:
                    ext = "." + match.split(".")[-1].lower()
                    # No hardcoded exclusions - include all discovered extensions
                    extensions.add(ext)

        return extensions

    @staticmethod
    def _appears_in_file_contexts(target_name: str, all_lines: list[str]) -> bool:
        """
        Check if target appears in file-related contexts in the Makefile.
        Completely dynamic - no hardcoded command patterns.

        Args:
            target_name: Name of the target
            all_lines: All lines in the Makefile

        Returns:
            True if target appears in file contexts
        """
        # Only structural patterns, no hardcoded commands
        file_context_patterns = [
            r"\$\(wildcard.*" + re.escape(target_name),  # $(wildcard *.ext)
            r"include\s+.*" + re.escape(target_name),  # include target
            r"-o\s+" + re.escape(target_name),  # -o target
            r">\s*" + re.escape(target_name),  # > target
            r"rm\s+.*" + re.escape(target_name),  # rm target (file being removed)
            r"rm\s+-[rf]*\s+.*" + re.escape(target_name),  # rm -f target
        ]

        for line in all_lines:
            for pattern in file_context_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    return True

        return False

    @staticmethod
    def _matches_file_naming_patterns(target_name: str, all_targets: list[str]) -> bool:
        """
        Check if target follows naming patterns of other file targets.

        Args:
            target_name: Name of the target
            all_targets: List of all targets in the Makefile

        Returns:
            True if target follows file naming patterns
        """
        # Analyze naming patterns
        return PhonyAnalyzer._has_similar_naming_pattern(target_name, all_targets)

    @staticmethod
    def _has_similar_naming_pattern(target_name: str, all_targets: list[str]) -> bool:
        """
        Check if target has similar naming pattern to other targets.
        Completely dynamic - no hardcoded patterns.

        Args:
            target_name: Name of the target to check
            all_targets: List of all targets in the Makefile

        Returns:
            True if target has similar pattern to file targets
        """
        # If target has extension, check if other targets have same extension
        if "." in target_name:
            target_ext = "." + target_name.split(".")[-1].lower()
            similar_targets = [t for t in all_targets if t.endswith(target_ext)]

            # If we find multiple targets with same extension, likely file targets
            if len(similar_targets) > 1:
                return True

        # Check for path-like patterns (contains slashes)
        return "/" in target_name or "\\" in target_name

    @staticmethod
    def _basic_file_target_heuristics(target_name: str) -> bool:
        """
        Basic heuristics for file target detection when no context is available.
        Conservative approach using only structural indicators.

        Args:
            target_name: Name of the target

        Returns:
            True if target looks like a file based on basic heuristics
        """
        # If it looks like an action target, it's not a file target
        if PhonyAnalyzer._looks_like_action_target(target_name):
            return False

        # Has file extension (most reliable indicator)
        if "." in target_name and not target_name.startswith("."):
            return True

        # Has path separators (likely a file path)
        return "/" in target_name or "\\" in target_name

    @staticmethod
    def _looks_like_action_target(target_name: str) -> bool:
        """
        Check if target looks like an action target.
        Completely dynamic - no hardcoded patterns at all.

        Args:
            target_name: Name of the target

        Returns:
            Always False - let recipe analysis determine everything
        """
        # No hardcoded patterns whatsoever
        # All phony detection is now based purely on recipe analysis
        return False

    @staticmethod
    def detect_phony_targets_excluding_conditionals(
        lines: list[str],
        disabled_line_indices: Optional[set[int]] = None,
        block_start_index: int = 0,
        recipe_text: Container[int] = (),
    ) -> set[str]:
        """Detect phony targets excluding those inside conditional blocks and format-disabled regions.

        recipe_text holds the indexes of continuation lines whose text make
        passes to the shell (see rule_context.recipe_text_lines), where a
        word before a ':', as in 'docker run -p 8080:80', is no target (GNU
        make manual 5.1.1, lines 2917-2925); it may hold the continuation
        lines of define bodies too, which are part of a variable's value
        (6.8, lines 4795-4799).
        """
        target_pattern = re.compile(r"^([^:=]+):(:?)\s*(.*)$")
        conditional_tracker = ConditionalTracker()
        phony_targets = set()

        if disabled_line_indices is None:
            disabled_line_indices = set()

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Skip empty lines, comments, and lines that start with tab (recipes)
            if not stripped or stripped.startswith("#") or line.startswith("\t"):
                continue
            # A conditional directive or a rule in shell text is neither
            if (
                ":" in stripped
                or stripped.startswith(
                    ("ifeq", "ifneq", "ifdef", "ifndef", "else", "endif")
                )
            ) and i in recipe_text:
                continue

            # Skip lines in format-disabled regions
            absolute_line_index = block_start_index + i
            if absolute_line_index in disabled_line_indices:
                continue

            # Track conditional context
            current_context = conditional_tracker.process_line(line, i)

            # Skip targets inside conditional blocks
            if current_context:
                continue

            # Skip variable assignments (=, :=, +=, ?=)
            if "=" in stripped and (
                ":" not in stripped
                or ":=" in stripped
                or "+=" in stripped
                or "?=" in stripped
            ):
                continue

            # Skip export variable assignments (e.g., "export VAR:=value")
            if stripped.startswith("export ") and "=" in stripped:
                continue

            # Skip $(info) function calls and other function calls
            if stripped.startswith("$(") and stripped.endswith(")"):
                continue

            # Skip lines that are clearly not target definitions
            # (e.g., lines that start with @ or contain function calls)
            if stripped.startswith("@") or "$(" in stripped:
                continue

            # Check for target definitions
            match = target_pattern.match(stripped)
            if match:
                target_list = match.group(1).strip()
                is_double_colon = match.group(2) == ":"
                target_body = match.group(3).strip()

                # Handle multiple targets on one line
                target_names = [t.strip() for t in target_list.split() if t.strip()]

                # Double-colon rules are allowed to have multiple definitions
                if is_double_colon:
                    continue

                # Check if this is a static pattern rule (contains %)
                if any("%" in name for name in target_names):
                    continue

                # Check if this is a target-specific variable assignment, of
                # any form (GNU make manual 6.11, lines 4938-4951). The
                # upper-case pattern also skips lines such as
                # 'endif # clean: OPT = -O0'.
                if re.match(
                    r"^\s*[A-Z_][A-Z0-9_]*\s*[+:?]?=", target_body
                ) or LineUtils.is_target_specific_variable(stripped):
                    continue

                # Get recipe lines for this target
                recipe_lines = PhonyAnalyzer._get_target_recipe_lines(lines, i)

                # Process each target name
                for target_name in target_names:
                    if target_name in ALL_SPECIAL_MAKE_TARGETS:
                        continue

                    # Skip targets that contain quotes or special characters that shouldn't be in target names
                    if (
                        '"' in target_name
                        or "'" in target_name
                        or "@" in target_name
                        or "$" in target_name
                        or "(" in target_name
                        or ")" in target_name
                    ):
                        continue

                    # Skip targets whose names hold CR, VT, FF, FS, GS, RS,
                    # NEL, LS or PS (the stand-ins of protect_line_breaks()):
                    # make 3.81 keeps a CR, VT or FF at the end of a target
                    # name and make 4.4.1 drops it, and a '.PHONY' line cannot
                    # end with one, so such targets are not declared
                    if _holds_stand_in(target_name):
                        continue

                    # Analyze if target is phony
                    if PhonyAnalyzer.is_target_phony(target_name, recipe_lines, lines):
                        phony_targets.add(target_name)

        return phony_targets

    @staticmethod
    def _get_target_recipe_lines(lines: list[str], target_index: int) -> list[str]:
        """Get the recipe lines for a target starting at target_index."""
        recipe_lines = []

        # Start from the line after the target
        for i in range(target_index + 1, len(lines)):
            line = lines[i]

            # Stop at empty line or next target/directive
            if not line.strip():
                continue

            # Recipe lines start with tab
            if line.startswith("\t"):
                recipe_lines.append(line.strip())
            else:
                # Hit a non-recipe line, stop collecting
                break

        return recipe_lines

    @staticmethod
    def _clean_command_for_analysis(command: str) -> str:
        """
        Clean command line for analysis by removing variables and quotes.

        Args:
            command: Raw command line

        Returns:
            Cleaned command line suitable for analysis
        """
        # Remove common variable patterns
        clean = re.sub(r"\$\([^)]+\)", "", command)
        clean = re.sub(r"\$\{[^}]+\}", "", clean)
        clean = re.sub(r"\$[A-Za-z_][A-Za-z0-9_]*", "", clean)

        # Remove quotes
        clean = clean.replace('"', "").replace("'", "")

        return clean.strip()

    @staticmethod
    def _command_creates_target_file(command: str, target_name: str) -> bool:
        """
        Check if command creates a file with the target name.
        Uses structural patterns, not semantic command knowledge.

        Args:
            command: Cleaned command line
            target_name: Name of the target

        Returns:
            True if the command creates a file with the target name
        """
        # Check for -o flag patterns (structural, not command-specific)
        output_flag_patterns = [
            rf"-o\s+{re.escape(target_name)}\b",  # -o target
            rf"-o\s*{re.escape(target_name)}\b",  # -otarget
        ]

        for pattern in output_flag_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return True

        # Check for Make automatic variables that represent the target
        # $@ is the target name in Make
        if "-o $@" in command or "-o$@" in command:
            return True

        # Direct file creation with redirection to target name (exact match)
        redirect_patterns = [
            rf">\s*{re.escape(target_name)}\s*$",  # > target_name at end
            rf">\s*{re.escape(target_name)}\s+",  # > target_name with space after
        ]

        for pattern in redirect_patterns:
            if re.search(pattern, command):
                return True

        # Make automatic variable patterns - very common in Makefiles
        # Pattern: command $< $@ (input to output)
        if "$< $@" in command:
            return True

        # Pattern: command $^ $@ (all prerequisites to output)
        if "$^ $@" in command:
            return True

        # Pattern: command ... $@ (any command ending with target)
        if command.strip().endswith(" $@"):
            return True

        # Structural patterns for common file creation (not semantic)
        # These are based on command structure, not specific command names

        # Pattern: any command that outputs to the target name
        if f" {target_name}" in command and any(
            indicator in command for indicator in ["-o", ">", ">"]
        ):
            return True

        # Pattern: commands that explicitly mention creating the target
        if target_name in command and any(
            word in command.lower() for word in ["create", "generate", "build", "make"]
        ):
            return True

        # Structural pattern: compilation to object files
        # If target is .o file and command has -c flag, it's likely compilation
        if target_name.endswith(".o") and "-c" in command:
            # Check if source file with same base name is mentioned
            base_name = target_name[:-2]  # Remove .o
            # Look for any file with the same base name (structural pattern)
            if base_name in command and "." in command:
                return True

        # Structural pattern: general file transformation
        # If target has extension and command mentions a file with same base name
        if "." in target_name and not target_name.startswith("."):
            base_name = target_name.rsplit(".", 1)[0]  # Remove extension
            if base_name in command and base_name != target_name:
                return True

        # Pattern: target name as last argument
        # Only return True if we have STRONG structural indicators of file creation
        # Don't assume file creation just because target is last argument
        command_parts = command.strip().split()
        if command_parts and command_parts[-1] == target_name:
            # Check for explicit file creation indicators (structural patterns only)
            # 1. Output redirection (strongest indicator)
            if f">{target_name}" in command or f"> {target_name}" in command:
                return True
            if f">>{target_name}" in command or f">> {target_name}" in command:
                return True

            # 2. -o flag (output flag) - structural pattern for compilers/linkers
            if f"-o{target_name}" in command or f"-o {target_name}" in command:
                return True

            # 3. Make automatic variables (structural pattern)
            if "$@" in command or "$< $@" in command or "$^ $@" in command:
                return True

            # 4. Multiple arguments with file extensions - suggests file transformation
            # Pattern: command source.ext target.ext (structural: file to file)
            if len(command_parts) >= 3:
                # Check if there are file-like arguments (contain dots/extensions)
                has_file_args = any(
                    "." in part and not part.startswith(".")
                    for part in command_parts[:-1]
                )
                target_has_extension = (
                    "." in target_name and not target_name.startswith(".")
                )
                if has_file_args and target_has_extension:
                    return True

            # 5. If target has extension and command has file-like patterns
            # This catches: command input.txt output.txt (structural pattern)
            if "." in target_name and not target_name.startswith("."):
                # Check if there are other file-like words in the command
                file_like_pattern = re.compile(r"\b\w+\.\w+\b")
                if file_like_pattern.search(command):
                    return True

            # 6. Single-argument commands (command + target only) - use command semantics
            # Pattern: "command target" where target is the only argument
            # Use constants for POSIX-standard commands only
            # For language runtimes (npm, python, rust, etc.), use structural heuristics
            if len(command_parts) == 2:
                first_word = command_parts[0].lower()
                # Known POSIX commands that never create files (echo, printf, etc.)
                if first_word in NON_FILE_CREATING_COMMANDS:
                    return False
                # Known POSIX commands that always create files (touch, cp, mv, etc.)
                if first_word in FILE_CREATING_COMMANDS:
                    return True
                # For unknown commands (language runtimes, custom scripts, etc.):
                # Use structural heuristics - if target looks like a file, assume file creation
                # Otherwise, assume it's just an argument (conservative - likely phony)
                # Default: assume it's just an argument (like npm test, python script, rust run)
                # This is conservative but avoids false positives
                return "." in target_name or "/" in target_name or "\\" in target_name

            # 7. Multiple arguments (3+) where target is last - likely file creation
            # Pattern: command arg1 arg2 ... target (structural: target is destination)
            if len(command_parts) >= 3:
                # If any previous argument looks file-like, target is likely output file
                file_like_pattern = re.compile(r"\b\w+\.\w+\b")
                if file_like_pattern.search(" ".join(command_parts[:-1])):
                    return True
                # If target has extension and there are multiple args, likely file creation
                if "." in target_name and not target_name.startswith("."):
                    return True

            # Default: if target is last arg but no strong structural indicators,
            # assume NOT file creation (most commands just pass target as argument)
            return False
        return False
