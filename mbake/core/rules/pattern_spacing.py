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
        formatted_lines: list[str] = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        space_after_colon = config.get("space_after_colon", True)

        def process_pattern_line(line: str, line_index: int) -> tuple[str, bool]:
            """Process a single line for pattern rule spacing."""
            # Try to format pattern rule spacing
            new_line = PatternUtils.format_pattern_rule(line, space_after_colon)
            if new_line is not None:
                return new_line, True
            else:
                return line, False

        formatted_lines, changed = LineUtils.process_lines_with_standard_skipping(
            lines=lines,
            line_processor=process_pattern_line,
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
