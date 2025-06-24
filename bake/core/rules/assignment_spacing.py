"""Assignment operator spacing rule for Makefiles."""

from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils import LineUtils, PatternUtils


class AssignmentSpacingRule(FormatterPlugin):
    """Handles spacing around assignment operators (=, :=, +=, ?=)."""

    def __init__(self) -> None:
        super().__init__("assignment_spacing", priority=15)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Normalize spacing around assignment operators."""
        formatted_lines: list[str] = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        space_around_assignment = config.get("space_around_assignment", True)

        def process_assignment_line(line: str, line_index: int) -> tuple[str, bool]:
            """Process a single line for assignment spacing."""
            # Skip recipe lines completely - they're shell commands, not makefile assignments
            if LineUtils.is_recipe_line(line, line_index, lines):
                return line, False

            # Skip continuation lines (part of a multi-line assignment value)
            if line_index > 0:
                prev_line = lines[line_index - 1]
                # If the previous line is a continuation, skip this line
                if LineUtils.is_continuation_line(prev_line):
                    return line, False

            # Check if the trimmed line is actually an assignment (regardless of indentation)
            if PatternUtils.contains_assignment(line.strip()):
                new_line = PatternUtils.apply_assignment_spacing(
                    line, space_around_assignment
                )
                return new_line, new_line != line
            else:
                return line, False

        formatted_lines, changed = LineUtils.process_lines_with_standard_skipping(
            lines=lines,
            line_processor=process_assignment_line,
            skip_recipe=False,  # We handle recipe detection in our processor
            skip_comments=True,
            skip_empty=True,
            skip_define_blocks=True,  # Skip assignment formatting inside define blocks
        )

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=[],
        )
