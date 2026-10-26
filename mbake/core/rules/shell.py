"""Shell script formatting rule for Makefile recipes."""

import re
from collections.abc import Mapping, Sequence
from typing import Any, Optional

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.line_utils import LineUtils, ShellUtils
from ...utils.rule_context import recipe_prefixes
from .recipe_validation import RecipeValidationRule


class ShellFormattingRule(FormatterPlugin):
    """
    Handles proper indentation of shell scripts within recipe lines.

    make passes each backslash/newline of a recipe line to the shell with
    the whitespace around it, and removes only the one recipe prefix
    character that starts the next line (GNU make manual 5.1.1, lines
    2917-2925), so each line of a block takes its new indentation only where
    the shell still gets the same words, with the whole logical line around
    the block read (see ShellUtils.keep_shell_text): the blanks of quoted
    text, of a here-document and between two words that a backslash joins
    stay as written. In a makefile where ShellUtils.recipes_are_shell_opaque
    holds, only the recipe prefix may come or go. The other lines stay as
    written; one of them at column 1 gets the TAB alone where
    RecipeValidationRule gives it one on the next run, below a line that now
    starts with a TAB, so that a second run changes nothing. That TAB is the
    recipe prefix, which make removes (see
    RecipeValidationRule._continuation_keeps_its_start).
    """

    def __init__(self) -> None:
        super().__init__("shell_formatting", priority=50)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Format shell script indentation within recipes."""
        formatted_lines: list[str] = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        hidden: Mapping[int, Sequence[str]] = context.get("disabled_region_lines") or {}
        guard = _ShellTextGuard(lines, hidden)
        # Lines at column 1 that a block keeps as written, as their new
        # indentation would reach the shell
        kept_at_column_1: list[int] = []

        i = 0
        while i < len(lines):
            line = lines[i]

            # Check if this is a recipe line
            if line.startswith("\t") and line.strip():
                # Look for shell control structures
                stripped = line.lstrip("\t ")

                # Check if this starts a shell control structure
                if self._is_shell_control_start(stripped):
                    # Process the shell block
                    shell_block, block_end = self._extract_shell_block(lines, i)
                    formatted_block = self._format_shell_block(shell_block)

                    if formatted_block != shell_block:
                        proposed = formatted_block
                        formatted_block = guard.keep(
                            formatted_lines, i, block_end, formatted_block
                        )
                        kept_at_column_1.extend(
                            i + offset
                            for offset, (old, new, kept) in enumerate(
                                zip(shell_block, proposed, formatted_block)
                            )
                            if kept == old != new and old[:1] not in (" ", "\t")
                        )

                    if formatted_block != shell_block:
                        changed = True

                    formatted_lines.extend(formatted_block)
                    i = block_end
                else:
                    formatted_lines.append(line)
                    i += 1
            else:
                formatted_lines.append(line)
                i += 1

        if kept_at_column_1 and config.get("fix_missing_recipe_tabs", True):
            # The line above such a line may now start with a TAB, below which
            # RecipeValidationRule gives the line one on the next run. It gets
            # it now. RecipeValidationRule gives a continuation line only the
            # TAB that make removes from it, the recipe prefix, so the shell
            # gets the same text (GNU make manual 5.1.1, lines 2917-2925).
            tabs = self._tabs_on_next_run(formatted_lines, kept_at_column_1, hidden)
            for index in tabs:
                formatted_lines[index] = "\t" + formatted_lines[index]
            changed = changed or bool(tabs)

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=[],
        )

    @staticmethod
    def _tabs_on_next_run(
        lines: list[str], candidates: Sequence[int], hidden: Mapping[int, Sequence[str]]
    ) -> list[int]:
        """Return the candidates that RecipeValidationRule gives a TAB in lines."""
        rule = RecipeValidationRule()
        facts = rule.line_facts(lines, {k: list(v) for k, v in hidden.items()})
        return [
            index
            for index in candidates
            if rule.is_missing_recipe_tab(
                lines[index], index, lines, facts.formatter_prefix(index), facts
            )
        ]

    def _is_shell_control_start(self, line: str) -> bool:
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

    def _extract_shell_block(
        self, lines: list[str], start_idx: int
    ) -> tuple[list[str], int]:
        """Extract a shell control block from lines.

        The block ends at a line that does not continue: only an odd number
        of backslashes at the very end continues a line (GNU make manual
        3.1.1, lines 762-769; 5.1.1, lines 2910-2915).
        """
        block = []
        i = start_idx

        while i < len(lines):
            line = lines[i]
            block.append(line)

            # If line doesn't end with continuation, this might be the end
            if not LineUtils.ends_with_continuation(line):
                i += 1
                break

            # Check for control structure end markers
            stripped = line.lstrip("\t ")
            if any(
                stripped.strip().startswith(end) for end in ["fi", "done", "esac", "}"]
            ):
                i += 1
                break

            i += 1

        return block, i

    def _format_shell_block(self, block: list[str]) -> list[str]:
        """Format a shell control block with proper indentation."""
        if not block:
            return block

        formatted = []
        indent_level = 0

        # Shell control structure keywords
        start_keywords = ("if", "for", "while", "case", "until")
        continuation_keywords = ("elif", "else")
        end_keywords = ("fi", "done", "esac")

        # Determine the base indentation level from the first line
        # This preserves the original indentation level instead of forcing it to 1 tab
        base_tabs = 1  # Default fallback
        if block and block[0].startswith("\t"):
            # Count leading tabs in the first line
            base_tabs = 0
            for char in block[0]:
                if char == "\t":
                    base_tabs += 1
                else:
                    break
            if base_tabs == 0:
                base_tabs = 1  # Fallback if no tabs found

        for line in block:
            if not line.strip():
                formatted.append(line)
                continue

            # Preserve the original line ending (including any trailing spaces)
            line_content = line.rstrip("\n\r")
            stripped = line_content.lstrip("\t ")

            # Check for trailing spaces/content after the main command
            trailing = ""
            if line_content.endswith(" "):
                # Count trailing spaces
                trailing_spaces = len(line_content) - len(line_content.rstrip(" "))
                trailing = " " * trailing_spaces
                stripped = stripped.rstrip(" ")

            # Strip make command prefixes for keyword detection
            command_content = stripped.lstrip("@-+ ")

            # Adjust indent level for closing keywords
            if any(
                command_content.strip().startswith(kw)
                for kw in continuation_keywords + end_keywords
            ):
                indent_level = max(0, indent_level - 1)

            # Calculate proper indentation, preserving base indentation level
            if indent_level == 0:
                # Primary recipe level - use base tabs from original indentation
                new_line = "\t" * base_tabs + stripped + trailing
            else:
                # Nested shell level - add extra tabs instead of mixing tabs and spaces
                new_line = "\t" * (base_tabs + indent_level) + stripped + trailing

            formatted.append(new_line)

            # Adjust indent level for opening keywords
            if any(
                command_content.strip().startswith(kw)
                for kw in start_keywords + continuation_keywords
            ) and LineUtils.ends_with_continuation(line_content):
                indent_level += 1

        return formatted


class _ShellTextGuard:
    """Decides whether a re-indented block keeps what the shell runs."""

    def __init__(self, lines: list[str], hidden: Mapping[int, Sequence[str]]) -> None:
        self._lines = lines
        self._hidden = hidden
        self._opaque: Optional[bool] = None
        self._prefixes: Optional[list[str]] = None

    def keep(
        self,
        formatted_lines: list[str],
        start: int,
        end: int,
        new_block: list[str],
    ) -> list[str]:
        """
        Return the lines of new_block that may replace lines[start:end].

        Each line takes its new indentation only where the shell still gets
        the same words, with the whole logical line around the block read
        (GNU make manual 3.1.1, lines 766-769; see ShellUtils.keep_shell_text),
        and with the blocks before it in the same line as formatted_lines has
        them; the other lines stay as written. Where the shell is not known
        (see ShellUtils.recipes_are_shell_opaque), only the changes that
        leave the text it gets as it is are made.
        """
        lines = self._lines
        hidden = self._hidden
        # The first and the last line of the logical line
        first = start
        while (
            first > 0
            and LineUtils.ends_with_continuation(lines[first - 1])
            and not hidden.get(first - 1)
        ):
            first -= 1
        last = end - 1
        while (
            last + 1 < len(lines)
            and LineUtils.ends_with_continuation(lines[last])
            and not hidden.get(last)
        ):
            last += 1
        # Lines that '# bake-format off' hides may be part of the logical
        # line: it is not known what the shell gets.
        before = hidden.get(first - 1) if first > 0 else None
        if (
            (before and LineUtils.ends_with_continuation(before[-1]))
            or any(hidden.get(index) for index in range(first, last))
            or (hidden.get(last) and LineUtils.ends_with_continuation(lines[last]))
        ):
            return lines[start:end]
        if self._prefixes is None:
            self._prefixes = recipe_prefixes(lines, hidden)
        if self._opaque is None:
            self._opaque = ShellUtils.recipes_are_shell_opaque(lines, hidden)
        old = [*formatted_lines[first:start], *lines[start : last + 1]]
        new = [*formatted_lines[first:start], *new_block, *lines[end : last + 1]]
        kept = ShellUtils.keep_shell_text(
            old, new, self._prefixes[first], opaque=self._opaque
        )
        return kept[start - first : end - first]
