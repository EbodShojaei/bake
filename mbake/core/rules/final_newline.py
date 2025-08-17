"""Final newline rule for Makefiles."""

from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin


class FinalNewlineRule(FormatterPlugin):
    """Ensures files end with a final newline if configured."""

    def __init__(self) -> None:
        super().__init__(
            "final_newline", priority=70
        )  # Run late, after content changes

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Ensure final newline if configured."""
        ensure_final_newline = config.get("ensure_final_newline", True)

        if not ensure_final_newline:
            return FormatResult(
                lines=lines, changed=False, errors=[], warnings=[], check_messages=[]
            )

        # Check if file is empty
        if not lines:
            return FormatResult(
                lines=lines, changed=False, errors=[], warnings=[], check_messages=[]
            )

        formatted_lines = list(lines)
        changed = False
        errors: list[str] = []
        warnings: list[str] = []
        check_messages: list[str] = []

        # Check if the last line ends with a newline
        # In check mode, respect the original_content_ends_with_newline parameter
        original_ends_with_newline = context.get(
            "original_content_ends_with_newline", False
        )

        # If original content already ends with newline, no change needed
        if check_mode and original_ends_with_newline:
            return FormatResult(
                lines=lines, changed=False, errors=[], warnings=[], check_messages=[]
            )

        # If the last line is not empty, we need to add a newline
        if formatted_lines and formatted_lines[-1] != "":
            if check_mode:
                # Generate check message
                line_count = len(formatted_lines)
                gnu_format = config.get("gnu_error_format", False)

                if gnu_format:
                    message = f"Makefile:{line_count}: Error: Missing final newline"
                else:
                    message = f"Line {line_count}: Error: Missing final newline"

                check_messages.append(message)
            else:
                # Add empty line to ensure final newline
                formatted_lines.append("")

            changed = True

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=check_messages,
        )
