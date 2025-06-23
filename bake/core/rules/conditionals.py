"""Conditional block formatting rule for Makefiles."""

import re
from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin


class ConditionalRule(FormatterPlugin):
    """Handles proper indentation of conditional blocks (ifeq, ifneq, etc.)."""

    def __init__(self) -> None:
        super().__init__("conditionals", priority=35)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Format conditional block indentation."""
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        indent_level = 0
        base_indent = "    "  # 4 spaces for conditional content

        for line in lines:
            stripped = line.strip()
            original_line = line

            # Skip recipe lines (start with tab)
            if line.startswith("\t"):
                formatted_lines.append(line)
                continue

            # Skip empty lines and comments
            if not stripped or stripped.startswith("#"):
                formatted_lines.append(line)
                continue

            # Handle conditional keywords
            if self._is_conditional_start(stripped):
                # Conditional start: ifeq, ifneq, ifdef, ifndef
                formatted_line = stripped
                formatted_lines.append(formatted_line)
                indent_level += 1
                if formatted_line != original_line.rstrip():
                    changed = True
            elif self._is_conditional_middle(stripped):
                # Middle: else, else if
                formatted_line = stripped if indent_level > 0 else stripped
                formatted_lines.append(formatted_line)
                if formatted_line != original_line.rstrip():
                    changed = True
            elif self._is_conditional_end(stripped):
                # Conditional end: endif
                indent_level = max(0, indent_level - 1)
                formatted_line = stripped
                formatted_lines.append(formatted_line)
                if formatted_line != original_line.rstrip():
                    changed = True
            elif indent_level > 0:
                # Inside conditional block - indent content
                if "=" in stripped and not self._is_target_line(stripped):
                    # Variable assignment inside conditional
                    formatted_line = base_indent * indent_level + stripped
                    formatted_lines.append(formatted_line)
                    if formatted_line != original_line.rstrip():
                        changed = True
                else:
                    # Other content (could be nested conditionals or targets)
                    formatted_lines.append(line)
            else:
                # Regular line outside conditionals
                formatted_lines.append(line)

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=[],
        )

    def _is_conditional_start(self, line: str) -> bool:
        """Check if line starts a conditional block."""
        return bool(re.match(r"^(ifeq|ifneq|ifdef|ifndef)\s*\(", line))

    def _is_conditional_middle(self, line: str) -> bool:
        """Check if line is a conditional middle (else)."""
        return bool(re.match(r"^else(\s|$)", line))

    def _is_conditional_end(self, line: str) -> bool:
        """Check if line ends a conditional block."""
        return line == "endif"

    def _is_target_line(self, line: str) -> bool:
        """Check if line is a target definition."""
        return ":" in line and not line.startswith(("ifeq", "ifneq", "ifdef", "ifndef"))
