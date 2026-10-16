"""Conditional block formatting rule for Makefiles."""

import re
from collections.abc import Mapping, Sequence
from typing import Any, Callable, Optional

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.line_utils import LineUtils
from ...utils.rule_context import (
    RECIPE,
    LineState,
    significant_whitespace_lines,
)
from .tabs import MakeReading, TabsRule

# The directives that read other makefiles (GNU make manual 3.3, lines
# 851-854).
_INCLUDE_WORDS = frozenset({"include", "-include", "sinclude"})

# The conditional directives (GNU make manual 7.2, lines 5386-5421)
_CONDITIONAL_WORDS = frozenset({"ifeq", "ifneq", "ifdef", "ifndef", "else", "endif"})

# A value that configure puts in place of '@NAME@' before make reads the file
_SUBSTITUTION = re.compile(r"@[A-Za-z_][A-Za-z0-9_]*@")


class _RecipeReading:
    """
    The reading that decides which lines make may read as recipe lines.

    That is TabsRule.read_lines with past_errors: it goes on past the lines
    where make stops with an error, as the next run reads the lines once
    other rules turn such a line into a recipe line. Every rule context
    counts, those of .PHONY rules included: PhonyRule does not always move
    a .PHONY line (it keeps lines in conditionals, '.PHONY :' lines, single
    declarations when ungrouping, and lines that own recipe lines), and a
    recipe line that keeps its TAB reads the same in every case. The lines
    are read on first use.

    The lines are read as TabsRule leaves them: it runs after this rule and
    turns some lines with leading spaces into recipe lines, which changes
    the rule contexts and the define bodies of the lines below. Reading the
    lines as they come out of the same run makes the next run choose the
    same.
    """

    def __init__(
        self,
        lines: list[str],
        hidden: Mapping[int, Sequence[str]],
        strip_dangling: bool,
        converted: "Callable[[], set[int]]",
    ) -> None:
        self._lines = lines
        self._hidden = hidden
        self._strip_dangling = strip_dangling
        self._converted = converted
        self._read: Optional[Sequence[LineState]] = None

    def __getitem__(self, index: int) -> LineState:
        if self._read is None:
            lines = self._lines
            converted = self._converted()
            if converted:
                lines = list(lines)
                for line_index in converted:
                    lines[line_index] = "\t" + lines[line_index].lstrip(" ")
            self._read = TabsRule.read_lines(
                lines, self._hidden, self._strip_dangling, past_errors=True
            )
        return self._read[index]


class ConditionalRule(FormatterPlugin):
    """Handles proper indentation of conditional blocks (ifeq, ifneq, etc.)."""

    def __init__(self) -> None:
        # Run before tabs rule to handle conditional formatting first
        super().__init__("conditionals", priority=5)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Format conditional blocks according to GNU Make syntax.

        According to GNU Make syntax:
        - Top-level conditional directives (ifeq, else, endif) start at column 1
        - Nested conditional directives are indented with spaces (if enabled in config)
        - Content inside conditionals should be indented with spaces (if enabled in config)
        - Recipe lines inside conditionals should use tabs

        Two kinds of lines keep their indentation, because new indentation
        would change what make reads:
        - the lines of a define body, which are the value of a variable (GNU
          make manual 6.8, lines 4795-4799);
        - a line that starts with the recipe prefix where make may read it
          as a recipe line, in a rule context (3.8, lines 1217-1219; 5.1,
          lines 2878-2884). make passes it to the shell, also when it looks
          like a conditional directive, an include or a variable assignment
          (lines 2897-2905; 3.3, lines 851-854; 7.2, lines 5511-5513), so it
          keeps its TAB and is reported. A conditional directive there still
          counts for the nesting of the lines after it, as before. The rule
          contexts of .PHONY rules count like any other. Where make's recipe
          prefix differs from the one that the rules read line by line, the
          rules keep their old reading (see TabsRule.reads_prefix_as_make).
          See _keeps_prefixed_line.
        - a continuation line of a line that make may read as a recipe line:
          make passes it to the shell with its leading whitespace (5.1.1,
          lines 2918-2925), so new indentation would change the command.
        Only spaces are ever added. With remove_trailing_whitespace off, the
        whitespace after a final backslash stays, also on directive lines,
        without which the backslash would continue the line (3.1.1, lines
        762-769).
        """
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        # Check if conditional indentation is enabled
        indent_conditionals = config.get("indent_nested_conditionals", False)
        tab_width = config.get("tab_width", 4)

        # If conditional indentation is disabled, return lines unchanged
        if not indent_conditionals:
            return FormatResult(
                lines=lines,
                changed=False,
                errors=errors,
                warnings=warnings,
                check_messages=[],
            )

        # Track conditional nesting depth and context
        conditional_stack: list[dict[str, Any]] = []  # Stack to track nesting levels

        # Trailing whitespace can be part of a variable value (GNU make manual
        # 6.2.2, lines 4273-4288). WhitespaceRule judges it when it removes
        # trailing whitespace; otherwise only whitespace that make reads is
        # kept here. Each line is read as makefile syntax, since TabsRule may
        # move a re-indented line into a rule context.
        remove_trailing_whitespace = config.get("remove_trailing_whitespace", True)
        value_lines: Optional[set[int]] = None

        # How make reads the lines, as TabsRule reads them
        hidden = context.get("disabled_region_lines") or {}
        states = TabsRule.read_lines(lines, hidden, remove_trailing_whitespace)
        keep_recipe_lines = TabsRule.reads_prefix_as_make(lines, states)
        tabs = TabsRule()
        tabs_reading: Optional[MakeReading] = None
        if keep_recipe_lines:
            # The reading that TabsRule makes its choices on (see
            # TabsRule.make_reading)
            others = TabsRule.read_lines_without_phony(
                lines, hidden, remove_trailing_whitespace, states
            )
            tabs_reading = MakeReading(states, [s.rule_context for s in others])

        def converted() -> set[int]:
            # The lines with leading spaces that TabsRule turns into recipe
            # lines in this run (see TabsRule.format)
            leave = TabsRule._lines_to_leave(lines, hidden, remove_trailing_whitespace)
            return {
                index
                for index, line in enumerate(lines)
                if line.startswith(" ")
                and index not in leave
                and tabs.converts_to_recipe(
                    line,
                    index,
                    lines,
                    states[index].recipe_prefix,
                    reading=tabs_reading,
                )
            }

        recipe_reading = _RecipeReading(
            lines, hidden, remove_trailing_whitespace, converted
        )
        # The define bodies are judged on the reading past errors, as the next
        # run reads the lines once a missing-TAB line above is repaired; files
        # without the word 'define' have none.
        has_define = any("define" in line for line in lines) or any(
            "define" in line for region in hidden.values() for line in region
        )

        for line_num, line in enumerate(lines, 1):
            original_line = line
            stripped = line.strip()
            line_index = line_num - 1  # Convert to 0-based index
            state = states[line_index]

            # Skip empty lines and comments
            if not stripped or stripped.startswith("#"):
                formatted_lines.append(line)
                continue

            # A define body is the value of a variable (GNU make manual 6.8,
            # lines 4795-4799): its lines stay as written, and make does not
            # read them as conditional directives.
            if has_define and recipe_reading[line_index].may_be_define_body:
                formatted_lines.append(line)
                continue

            # A continuation line of a line that make may read as a recipe
            # line is passed to the shell with its leading whitespace (GNU
            # make manual 5.1.1, lines 2918-2925): it stays as written, as
            # long as the line it continues stays a recipe line, as written.
            start = state.logical_start
            if (
                state.continuation
                and RECIPE in state.readings
                and 0 <= start < line_index
                and formatted_lines[start] == lines[start]
                and lines[start].startswith(state.recipe_prefix)
            ):
                formatted_lines.append(line)
                continue

            # Check if this is a target definition (ends with :)
            if (
                ":" in stripped
                and not stripped.startswith("\t")
                and not line.startswith(" ")
            ):
                # This looks like a target definition
                formatted_lines.append(line)
                continue

            # Check if this is a conditional directive
            if self._is_conditional_directive(stripped):
                formatted_line = self._format_conditional_directive(
                    line,
                    stripped,
                    conditional_stack,
                    line_num,
                    tab_width,
                    keep_trailing=not remove_trailing_whitespace
                    and LineUtils.has_dangling_backslash(line),
                )
                if (
                    formatted_line != original_line
                    and keep_recipe_lines
                    and self._keeps_prefixed_line(
                        line, state.recipe_prefix, recipe_reading, line_index
                    )
                ):
                    # It still counts for the nesting of the lines after it
                    # (see format()).
                    formatted_line = original_line
                    self._warn_recipe_line(
                        warnings, recipe_reading[line_index], line, line_num, config
                    )
                if formatted_line != original_line:
                    changed = True
                formatted_lines.append(formatted_line)
            else:
                # Check if this is content inside a conditional that needs
                # indentation: not a recipe line, or a line with leading spaces
                # that TabsRule leaves as makefile syntax
                if conditional_stack and (
                    not LineUtils.is_recipe_line(line, line_index, lines)
                    or (
                        tabs_reading is not None
                        and line.startswith(" ")
                        and not tabs.converts_to_recipe(
                            line,
                            line_index,
                            lines,
                            state.recipe_prefix,
                            reading=tabs_reading,
                        )
                    )
                ):
                    # This is content inside a conditional block (variable assignment, etc.)
                    if not remove_trailing_whitespace and value_lines is None:
                        value_lines = significant_whitespace_lines(
                            lines, states, as_syntax=True
                        )
                    if remove_trailing_whitespace:
                        # WhitespaceRule removes the trailing whitespace later,
                        # also after a final backslash, which makes the line
                        # continue (GNU make manual 3.1.1, lines 762-769);
                        # there it knows which lines that changes (see
                        # empty_recipes_to_keep).
                        keep_trailing = True
                    else:
                        # Only whitespace that make reads is kept: that of a
                        # value, and the whitespace after a final backslash,
                        # without which the backslash would continue the line
                        # (GNU make manual 3.1.1, lines 762-769).
                        keep_trailing = (
                            value_lines is not None and line_index in value_lines
                        ) or LineUtils.has_dangling_backslash(line)
                    formatted_line = self._format_conditional_content(
                        line, stripped, conditional_stack, tab_width, keep_trailing
                    )
                    if (
                        formatted_line != original_line
                        and keep_recipe_lines
                        and self._keeps_prefixed_line(
                            line, state.recipe_prefix, recipe_reading, line_index
                        )
                    ):
                        # make may read it as a recipe line (see format())
                        formatted_line = original_line
                        self._warn_recipe_line(
                            warnings, recipe_reading[line_index], line, line_num, config
                        )
                    if formatted_line != original_line:
                        changed = True
                    formatted_lines.append(formatted_line)
                else:
                    # Regular line or recipe line - let tabs rule handle recipe formatting
                    formatted_lines.append(line)

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=[],
        )

    @staticmethod
    def _keeps_prefixed_line(
        line: str, prefix: str, reading: _RecipeReading, index: int
    ) -> bool:
        """
        Check if a line that starts with the recipe prefix keeps its indentation.

        The prefix is a TAB, the only one for make 3.81, or the .RECIPEPREFIX
        character that the lines above set (GNU make manual, lines
        5158-5169). make reads such a line as a recipe line where a rule
        context reaches it (3.8, lines 1217-1219; 5.1, lines 2878-2884), and
        elsewhere as makefile syntax. New indentation is only safe where make
        reads the line as makefile syntax: in every branch that make may take
        at the conditionals above it, with make 3.81 and 4.x (see
        LineState.readings), also past the lines above where make stops with
        an error, which other rules may turn into recipe lines. A conditional
        directive, a define or an endef also keeps its indentation where make
        may skip it as a recipe line in a branch that it skips, as new
        indentation would make it count there (LineState.skipped_as_recipe),
        and so does any line that make skips there and reads nowhere else.
        Where make stops at the line in every branch that reads it, a line
        without references stays as written: make rejects it with or without
        the prefix (lines 1231-1236, 11292-11297).

        Args:
            line: The line
            prefix: The recipe prefix at the line
            reading: The _RecipeReading of the lines
            index: The index of the line

        Returns:
            True if the line starts with the recipe prefix and keeps its
            indentation
        """
        tab_led = line.startswith("\t")
        if not (tab_led or line.startswith(prefix)):
            return False
        state = reading[index]
        if RECIPE in state.readings:
            return True
        command = line[1:] if tab_led else line[len(state.recipe_prefix) :]
        word = LineUtils.directive_word(command.strip())
        if state.skipped_as_recipe and (
            not state.readings
            or word in _CONDITIONAL_WORDS
            or word in ("define", "endef")
        ):
            return True
        if state.readings:
            return False
        code = state.text
        comment = LineUtils.find_comment_start(code)
        if comment is not None:
            code = code[:comment]
        return "$" not in code and not _SUBSTITUTION.search(code)

    @staticmethod
    def _warn_recipe_line(
        warnings: list[str], state: LineState, line: str, line_num: int, config: dict
    ) -> None:
        """
        Report a recipe line that looks like makefile syntax and is left as is.

        make passes a line that starts with the recipe prefix in a rule
        context to the shell (GNU make manual 5.1, lines 2897-2905): a
        conditional directive, an include directive or a variable assignment
        there is a command, not makefile syntax (3.3, lines 851-854; 7.2,
        lines 5511-5513). That is where make may read the line as a recipe
        line (LineState.readings, read past errors as for
        _keeps_prefixed_line). A shell assignment such as 'NAME=value' or
        'export NAME=value' is a usual command, and the continuation lines of
        a recipe line are part of it, so neither is reported.
        """
        if state.continuation or RECIPE not in state.readings:
            return
        tab_led = line.startswith("\t")
        # The command after the recipe prefix (lines 5158-5169)
        command = line[1:] if tab_led else line[len(state.recipe_prefix) :]
        stripped = command.strip()
        words = stripped.split()
        first_word = words[0] if words else ""
        if first_word in ("ifeq", "ifneq", "ifdef", "ifndef", "else", "endif"):
            what = f"'{first_word}'"
            instead = "a conditional directive"
        elif first_word in _INCLUDE_WORDS:
            what = f"'{first_word}'"
            instead = "an include directive"
        else:
            code = stripped
            comment = LineUtils.find_comment_start(code)
            if comment is not None:
                code = code[:comment]
            assignment = LineUtils.parse_variable_assignment(code)
            if assignment is None or (
                assignment.operator == "="
                and "override" not in assignment.modifiers
                and not code.split("=", 1)[0].endswith((" ", "\t"))
            ):
                return
            what = f"assignment to '{assignment.name}'"
            instead = "a variable assignment"
        indented = "Tab-indented" if tab_led else "Recipe-prefixed"
        message = (
            f"{indented} {what} in a rule context may be read as a recipe "
            f"line, not as {instead} (left unchanged)"
        )
        if config.get("_global", {}).get("gnu_error_format", True):
            warnings.append(f"{line_num}: Warning: {message}")
        else:
            warnings.append(f"Warning: {message} (line {line_num})")

    def _is_conditional_directive(self, stripped_line: str) -> bool:
        """Check if line is a conditional directive."""
        conditional_keywords = ("ifeq", "ifneq", "ifdef", "ifndef", "else", "endif")

        # Check for exact matches at the start of the line
        for keyword in conditional_keywords:
            if (
                stripped_line == keyword
                or stripped_line.startswith(keyword + " ")
                or stripped_line.startswith(keyword + "(")
            ):
                return True

        # Handle 'else if' variants
        return stripped_line.startswith("else ") and any(
            stripped_line.startswith("else " + kw)
            for kw in ("ifeq", "ifneq", "ifdef", "ifndef")
        )

    def _format_conditional_directive(
        self,
        line: str,
        stripped: str,
        conditional_stack: list,
        line_num: int,
        tab_width: int = 2,
        keep_trailing: bool = False,
    ) -> str:
        """Format a conditional directive with proper indentation.

        With keep_trailing, the whitespace at the end of the line stays: after
        a final backslash it keeps the backslash from continuing the line
        (GNU make manual 3.1.1, lines 762-769).

        Note: According to GNU Make syntax, conditionals always start at column 1
        (even inside recipes), but nested conditionals are indented with spaces
        for stylistic purposes when indent_nested_conditionals is enabled.
        """
        # Determine the nesting level based on the directive type
        if stripped.startswith(("endif",)):
            # endif closes the current conditional
            if conditional_stack:
                conditional_stack.pop()
            indent_level = len(conditional_stack)
        elif stripped.startswith(("else",)):
            # else stays at the same level as its opening conditional
            indent_level = len(conditional_stack) - 1 if conditional_stack else 0
        else:
            # Opening conditionals (ifeq, ifneq, ifdef, ifndef)
            indent_level = len(conditional_stack)
            # Add this conditional to the stack
            conditional_stack.append(
                {
                    "type": (
                        stripped.split()[0]
                        if " " in stripped
                        else stripped.split("(")[0]
                    ),
                    "line": line_num,
                    "level": indent_level,
                }
            )

        # Ensure indent_level is not negative
        indent_level = max(0, indent_level)

        # Format the line with proper indentation using tab_width spaces per level
        # Conditionals always start at column 1 (even inside recipes), but
        # nested conditionals are indented for stylistic purposes
        spaces = " " * (indent_level * tab_width)
        return spaces + (line.lstrip() if keep_trailing else stripped)

    def _format_conditional_content(
        self,
        line: str,
        stripped: str,
        conditional_stack: list,
        tab_width: int = 2,
        keep_trailing: bool = False,
    ) -> str:
        """Format content inside conditional blocks.

        keep_trailing keeps the trailing whitespace of the line, which can be
        part of a variable value.
        """
        if not conditional_stack:
            return line

        # Content inside conditionals should be indented one level deeper than the conditional
        indent_level = len(conditional_stack)
        spaces = " " * (indent_level * tab_width)

        if keep_trailing:
            return spaces + line.lstrip()
        return spaces + stripped
