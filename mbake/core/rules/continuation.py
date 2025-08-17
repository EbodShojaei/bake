"""Line continuation formatting rule for Makefiles."""

from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin


class ContinuationRule(FormatterPlugin):
    """Handles proper formatting of line continuations with backslashes."""

    def __init__(self) -> None:
        super().__init__("continuation", priority=9)  # Run before tabs rule

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Normalize line continuation formatting."""
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        normalize_continuations = config.get("normalize_line_continuations", True)

        if not normalize_continuations:
            return FormatResult(
                lines=lines,
                changed=False,
                errors=errors,
                warnings=warnings,
                check_messages=[],
            )

        i = 0
        while i < len(lines):
            line = lines[i]

            # Check if line ends with backslash (continuation)
            if line.rstrip().endswith("\\"):
                # Collect all continuation lines
                continuation_lines = [line]
                j = i + 1

                while j < len(lines):
                    current_line = lines[j]
                    continuation_lines.append(current_line)

                    # If this line doesn't end with backslash, it's the last line
                    if not current_line.rstrip().endswith("\\"):
                        j += 1
                        break

                    j += 1

                # Format the continuation block
                formatted_block = self._format_continuation_block(continuation_lines)

                if formatted_block != continuation_lines:
                    changed = True

                formatted_lines.extend(formatted_block)
                i = j
            else:
                formatted_lines.append(line)
                i += 1

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=[],
        )

    def _format_continuation_block(self, lines: list[str]) -> list[str]:
        """Format a block of continuation lines."""
        if not lines:
            return lines

        # Preserve original indentation structure, only normalize spacing around backslashes
        formatted_lines = []
        for line in lines:
            if line.rstrip().endswith("\\"):
                # Remove trailing whitespace before backslash, ensure single space
                content = line.rstrip()[:-1].rstrip()
                formatted_lines.append(content + " \\")
            else:
                # Last line of continuation - preserve original indentation
                formatted_lines.append(line)

        return formatted_lines
