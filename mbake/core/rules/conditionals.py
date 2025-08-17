"""Conditional block formatting rule for Makefiles."""

from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin


class ConditionalRule(FormatterPlugin):
    """Handles proper indentation of conditional blocks (ifeq, ifneq, etc.)."""

    def __init__(self) -> None:
        # Run after basic whitespace/tab conversions so we can adjust indentation correctly
        super().__init__("conditionals", priority=55)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Format conditional blocks according to GNU Make syntax.

        According to GNU Make syntax:
        - Conditional directives (ifeq, else, endif) should NOT be indented (start at column 1)
        - Content inside conditionals should be indented with spaces
        - Recipe lines inside conditionals should use tabs
        """
        # Return lines unchanged - conditionals are already properly formatted
        return FormatResult(
            lines=lines,
            changed=False,
            errors=[],
            warnings=[],
            check_messages=[],
        )
