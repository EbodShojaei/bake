"""Target colon spacing rule for Makefiles."""

from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils import LineUtils, PatternUtils


class TargetSpacingRule(FormatterPlugin):
    """Handles spacing around colons in target definitions."""

    def __init__(self) -> None:
        super().__init__("target_spacing", priority=18)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Normalize spacing around colons in target definitions."""
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        space_before_colon = config.get("space_before_colon", False)
        space_after_colon = config.get("space_after_colon", True)

        for line in lines:
            # Skip recipe lines, comments, and empty lines
            if LineUtils.should_skip_line(
                line, skip_recipe=True, skip_comments=True, skip_empty=True
            ):
                formatted_lines.append(line)
                continue

            # Try to format target colon spacing
            new_line = PatternUtils.format_target_colon(
                line, space_before_colon, space_after_colon
            )
            if new_line is not None:
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
