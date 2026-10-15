"""Conditional block formatting rule for Makefiles."""

from typing import Any, Optional

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.line_utils import LineUtils
from ...utils.rule_context import scan_makefile, significant_whitespace_lines


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

        # Trailing whitespace can be part of a variable value (GNU make manual
        # 6.2.2, lines 4273-4288). WhitespaceRule judges it when it removes
        # trailing whitespace; otherwise only whitespace that make reads is
        # kept here. Each line is read as makefile syntax, since TabsRule may
        # move a re-indented line into a rule context.
        remove_trailing_whitespace = config.get("remove_trailing_whitespace", True)
        value_lines: Optional[set[int]] = None

        for line_num, line in enumerate(lines, 1):
            original_line = line
            stripped = line.strip()
            line_index = line_num - 1  # Convert to 0-based index

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
                if conditional_stack and not LineUtils.is_recipe_line(
                    line, line_index, lines
                ):
                    # This is content inside a conditional block (variable assignment, etc.)
                    if not remove_trailing_whitespace and value_lines is None:
                        value_lines = significant_whitespace_lines(
                            lines,
                            scan_makefile(
                                lines, context.get("disabled_region_lines") or {}
                            ),
                            as_syntax=True,
                        )
                    if remove_trailing_whitespace:
                        # WhitespaceRule removes the trailing whitespace later,
                        # also after a final backslash, which makes the line
                        # continue (GNU make manual 3.1.1, lines 762-769);
                        # there it knows which lines that changes (see
                        # empty_recipes_to_keep).
                        keep_trailing = True
                    else:
                        # Only whitespace that make reads is kept; the
                        # whitespace after a final backslash goes, as it
                        # always did (see value_whitespace_lines).
                        keep_trailing = (
                            value_lines is not None and line_index in value_lines
                        )
                    formatted_line = self._format_conditional_content(
                        line, stripped, conditional_stack, tab_width, keep_trailing
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

    def _format_conditional_directive(
        self,
        line: str,
        stripped: str,
        conditional_stack: list,
        line_num: int,
        tab_width: int = 2,
    ) -> str:
        """Format a conditional directive with proper indentation.

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
        return spaces + stripped

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
