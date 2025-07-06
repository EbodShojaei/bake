"""Tab formatting rule for Makefile recipes."""

import re
from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils import LineUtils


class TabsRule(FormatterPlugin):
    """Ensures tabs are used for recipe indentation instead of spaces."""

    def __init__(self) -> None:
        super().__init__("tabs", priority=10)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Only normalize lines that start with a tab. Never add a tab to lines indented with spaces only, even if they are continuations. All other lines are left as-is."""
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        for i, line in enumerate(lines):
            stripped = line.lstrip()
            # If this line is a continuation of the previous (previous ends with backslash), leave it alone
            if i > 0 and lines[i-1].rstrip().endswith('\\'):
                formatted_lines.append(line)
                continue
            
            # Use robust LineUtils helper to detect actual target lines
            is_target = LineUtils.is_target_line(stripped)

            # Check if this is a special Makefile directive or function call (non-recipe only)
            is_special_directive = False
            special_directives = ["$(error", "$(warning", "$(info", "$(shell", "$(eval", "$(file", "$(call"]
            if not line.startswith("\t") and any(stripped.startswith(d) for d in special_directives):
                is_special_directive = True

            if is_target or is_special_directive:
                # Targets/directives must be flush-left. Remove any leading whitespace.
                if line.startswith((" ", "\t")):
                    formatted_lines.append(stripped)
                    changed = True
                else:
                    formatted_lines.append(line)
                continue

            # Special-case continuation lines (-n "$(shell ...)) to preserve indentation
            if stripped.startswith('-n "') and i > 0 and lines[i-1].rstrip().endswith('\\'):
                formatted_lines.append(line)
                continue
            if line.startswith("\t"):
                formatted_lines.append(line)
                continue

            # All other lines, including space-indented continuations, are left as-is
            formatted_lines.append(line)

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=[],
        )
