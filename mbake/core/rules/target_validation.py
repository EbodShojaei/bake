"""Rule for validating target syntax and warning about invalid constructs."""

import re
from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.line_utils import LineUtils
from ...utils.pattern_utils import PatternUtils


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

            # Skip recipe lines and their continuations entirely (shell context)
            if line.startswith("\t") or LineUtils.is_recipe_line(line, i - 1, lines):
                continue

            # Check for invalid target syntax
            if self._is_invalid_target(line, active_prefix):
                warnings.append(f"Line {i}: Invalid target syntax: {stripped}")

        return warnings

    def _is_invalid_target(self, line: str, active_prefix: str) -> bool:
        """Check if line contains invalid target syntax."""
        stripped = line.strip()

        # Check for target-like 'name=value: ...' only when there is no space after '='
        # and the value before ':' is not colon-safe (URL-like, ISO datetime, path)
        if re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*=\S*:\S*", stripped):
            after_eq = stripped.split("=", 1)[1]
            value_before_colon = after_eq.split(":", 1)[0]
            if not PatternUtils.value_is_colon_safe(value_before_colon):
                return True

        # Check for target preceded by .RECIPEPREFIX character
        if LineUtils.is_recipe_line_with_prefix(line, active_prefix):
            return False

        return False
