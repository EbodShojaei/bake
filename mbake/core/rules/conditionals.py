"""Conditional block formatting rule for Makefiles."""

import re
from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin


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

        for line_num, line in enumerate(lines, 1):
            original_line = line
            stripped = line.strip()

            # Skip empty lines and comments
            if not stripped or stripped.startswith("#"):
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
                    line, stripped, conditional_stack, line_num, tab_width
                )
                if formatted_line != original_line:
                    changed = True
                formatted_lines.append(formatted_line)
            else:
                # Check if this is content inside a conditional that needs indentation
                if conditional_stack and not self._is_recipe_line(line):
                    # This is content inside a conditional block (variable assignment, etc.)
                    formatted_line = self._format_conditional_content(
                        line, stripped, conditional_stack, tab_width
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

    def _is_recipe_line(self, line: str) -> bool:
        """Check if line is a recipe line that should start with a tab."""
        stripped = line.strip()
        if not stripped:
            return False

        # Recipe lines start with a tab or should start with a tab
        if line.startswith("\t"):
            return True

        # Skip variable assignments and makefile directives
        if "=" in stripped and re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*[+:?]?=", stripped):
            return False

        if stripped.startswith(("include", "export", "unexport", "vpath", "-include")):
            return False

        if self._is_conditional_directive(stripped):
            return False

        # Use sophisticated pattern-based detection like LineUtils
        # instead of relying on command lists which can never be comprehensive

        # If line is indented, check for recipe indicators
        if line.startswith(" "):
            # Recipe prefix indicators (@, -, +)
            if any(stripped.startswith(prefix) for prefix in ["@", "-", "+"]):
                return True

            # Make variables and shell patterns common in recipes
            if any(
                pattern in stripped
                for pattern in ["$(", "$@", "$<", "$^", "$$", "${", "`"]
            ):
                return True

            # Shell operators that indicate recipe lines
            if any(
                op in stripped for op in ["&&", "||", "|", ">", ">>", "<", "2>", "&"]
            ):
                return True

            # Common shell built-ins (limited set to avoid false positives)
            from ...constants.shell_commands import SHELL_COMMAND_INDICATORS

            if any(
                stripped.startswith(indicator) for indicator in SHELL_COMMAND_INDICATORS
            ):
                return True

        return False

    def _format_conditional_directive(
        self,
        line: str,
        stripped: str,
        conditional_stack: list,
        line_num: int,
        tab_width: int = 2,
    ) -> str:
        """Format a conditional directive with proper indentation."""

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
        spaces = " " * (indent_level * tab_width)
        return spaces + stripped

    def _format_conditional_content(
        self, line: str, stripped: str, conditional_stack: list, tab_width: int = 2
    ) -> str:
        """Format content inside conditional blocks."""
        if not conditional_stack:
            return line

        # Content inside conditionals should be indented one level deeper than the conditional
        indent_level = len(conditional_stack)
        spaces = " " * (indent_level * tab_width)

        return spaces + stripped
