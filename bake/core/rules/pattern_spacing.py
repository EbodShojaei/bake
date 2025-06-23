"""Pattern rule spacing rule for Makefiles."""

from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils import LineUtils, PatternUtils


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
            # Skip recipe lines, comments, and empty lines
            if LineUtils.should_skip_line(
                line, skip_recipe=True, skip_comments=True, skip_empty=True
            ):
                formatted_lines.append(line)
                continue

            # Try to format pattern rule spacing
            new_line = PatternUtils.format_pattern_rule(line, space_after_colon)
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
