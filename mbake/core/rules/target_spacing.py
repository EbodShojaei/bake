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
        formatted_lines: list[str] = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        space_before_colon = config.get("space_before_colon", False)
        space_after_colon = config.get("space_after_colon", True)

        def process_target_line(line: str, line_index: int) -> tuple[str, bool]:
            """Process a single line for target colon spacing."""
            # Try to format target colon spacing
            new_line = PatternUtils.format_target_colon(
                line, space_before_colon, space_after_colon
            )
            if new_line is not None:
                return new_line, True
            else:
                return line, False

        formatted_lines, changed = LineUtils.process_lines_with_standard_skipping(
            lines=lines,
            line_processor=process_target_line,
            skip_recipe=True,
            skip_comments=True,
            skip_empty=True,
            skip_define_blocks=False,
        )

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=[],
        )
