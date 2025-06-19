"""Assignment operator spacing rule for Makefiles."""

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils import LineUtils, PatternUtils


class AssignmentSpacingRule(FormatterPlugin):
    """Handles spacing around assignment operators (=, :=, +=, ?=)."""

    def __init__(self) -> None:
        super().__init__("assignment_spacing", priority=15)

    def format(self, lines: list[str], config: dict) -> FormatResult:
        """Normalize spacing around assignment operators."""
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        space_around_assignment = config.get("space_around_assignment", True)

        for line in lines:
            # Skip comments and empty lines
            if LineUtils.should_skip_line(
                line, skip_recipe=False, skip_comments=True, skip_empty=True
            ):
                formatted_lines.append(line)
                continue

            # Check if the trimmed line is actually an assignment (regardless of indentation)
            if PatternUtils.contains_assignment(line.strip()):
                new_line = PatternUtils.apply_assignment_spacing(
                    line, space_around_assignment
                )
                if new_line != line:
                    changed = True
                formatted_lines.append(new_line)
            else:
                formatted_lines.append(line)

        return FormatResult(
            lines=formatted_lines, changed=changed, errors=errors, warnings=warnings
        )
