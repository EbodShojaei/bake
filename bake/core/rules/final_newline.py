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

        formatted_lines = list(lines)
        changed = False
        errors: list[str] = []
        warnings: list[str] = []
        check_messages: list[str] = []

        # Check if file is empty
        if not lines:
            return FormatResult(
                lines=lines,
                changed=False,
                errors=errors,
                warnings=warnings,
                check_messages=check_messages,
            )

        # Check if the original content was missing a final newline
        # This information is passed through context by the formatter
        original_ends_with_newline = context.get(
            "original_content_ends_with_newline", True
        )

        # If original content didn't end with newline, we need to report it
        if not original_ends_with_newline:
            if check_mode:
                # Generate check message pointing to the last line of the ORIGINAL file
                # (the line that's missing the newline, not the line after it)
                original_line_count = context.get("original_line_count", len(lines))
                gnu_format = config.get("_global", {}).get("gnu_error_format", True)

                if gnu_format:
                    message = f"{original_line_count}: Error: Missing final newline"
                else:
                    message = (
                        f"Error: Missing final newline (line {original_line_count})"
                    )

                check_messages.append(message)

            changed = True

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=check_messages,
        )
