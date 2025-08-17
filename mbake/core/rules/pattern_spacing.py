"""Pattern rule spacing rule for Makefiles."""

import re
from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin


class PatternSpacingRule(FormatterPlugin):
    """Handles spacing in pattern rules and static pattern rules."""

    def __init__(self) -> None:
        super().__init__("pattern_spacing", priority=17)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Normalize spacing in pattern rules."""
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        space_after_colon = config.get("space_after_colon", True)

        for line in lines:
            # Skip empty lines, comments, and recipe lines
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or line.startswith("\t"):
                formatted_lines.append(line)
                continue

            # Process pattern rule spacing
            new_line = self._format_pattern_rule(line, space_after_colon)
            if new_line != line:
                changed = True
                formatted_lines.append(new_line)
            else:
                formatted_lines.append(line)

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=[],
        )

    def _format_pattern_rule(self, line: str, space_after_colon: bool) -> str:
        """Format spacing in pattern rules."""
        # Handle static pattern rules with two colons: targets: pattern: prerequisites
        if re.search(r".*:\s*%.*\s*:\s*", line) and not re.search(r"[=]", line):
            static_pattern_match = re.match(
                r"^(\s*)([^:]+):\s*([^:]+)\s*:\s*(.*)$", line
            )
            if static_pattern_match:
                leading_whitespace = static_pattern_match.group(1)
                targets_part = static_pattern_match.group(2).rstrip()
                pattern_part = static_pattern_match.group(3).strip()
                prereqs_part = static_pattern_match.group(4).strip()

                new_line = (
                    leading_whitespace
                    + f"{targets_part}: {pattern_part}: {prereqs_part}"
                )
                return new_line

        # Handle simple pattern rules: %.o: %.c
        elif re.search(r"%.*:", line) and line.count(":") == 1:
            pattern_match = re.match(r"^(\s*)([^:]+):(.*)$", line)
            if pattern_match:
                leading_whitespace = pattern_match.group(1)
                pattern_part = pattern_match.group(2).rstrip()
                prereqs_part = pattern_match.group(3)

                if space_after_colon:
                    if prereqs_part.startswith(" "):
                        prereqs_part = " " + prereqs_part.lstrip()
                    elif prereqs_part:
                        prereqs_part = " " + prereqs_part
                else:
                    prereqs_part = prereqs_part.lstrip()

                new_line = leading_whitespace + pattern_part + ":" + prereqs_part
                return new_line

        return line
