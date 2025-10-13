"""Rule for validating target syntax and warning about invalid constructs."""

import re
from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.line_utils import LineUtils


class TargetValidationRule(FormatterPlugin):
    """Validates target syntax and warns about invalid constructs."""

    def __init__(self) -> None:
        super().__init__(
            "target_validation", priority=6
        )  # Run after duplicate detection

    def format(
        self,
        lines: list[str],
        config: dict[str, Any],
        check_mode: bool = False,
        **context: Any,
    ) -> FormatResult:
        """Validate target syntax and return warnings."""
        warnings = self._validate_target_syntax(lines)
        # This rule doesn't modify content, just reports warnings
        return FormatResult(
            lines=lines, changed=False, errors=[], warnings=warnings, check_messages=[]
        )

    def _validate_target_syntax(self, lines: list[str]) -> list[str]:
        """Check for invalid target syntax patterns."""
        warnings = []

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Skip empty lines and comments
            if not stripped or stripped.startswith("#"):
                continue

            # Get active recipe prefix for this line
            active_prefix = LineUtils.get_active_recipe_prefix(lines, i - 1)

            # Check for invalid target syntax
            if self._is_invalid_target(line, active_prefix):
                warnings.append(f"Line {i}: Invalid target syntax: {stripped}")

        return warnings

    def _is_invalid_target(self, line: str, active_prefix: str) -> bool:
        """Check if line contains invalid target syntax."""
        stripped = line.strip()

        # Check for target with = sign
        if re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*=.*:", stripped):
            return True

        # Check for target preceded by .RECIPEPREFIX character
        if (
            LineUtils.is_recipe_line_with_prefix(line, active_prefix)
            and ":" in stripped
        ):
            parts = stripped.split(":", 1)
            if len(parts) == 2 and parts[1].strip():
                return True

        return False
