"""PHONY declaration formatting rule for Makefiles."""

from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin


class PhonyRule(FormatterPlugin):
    """Handles proper grouping and placement of .PHONY declarations."""

    def __init__(self) -> None:
        super().__init__("phony", priority=40)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Group and organize .PHONY declarations."""
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        group_phony = config.get("group_phony_declarations", True)

        if not group_phony:
            return FormatResult(
                lines=lines,
                changed=False,
                errors=errors,
                warnings=warnings,
                check_messages=[],
            )

        # Collect all phony targets
        phony_targets = set()  # Use set to avoid duplicates
        other_lines = []

        for line in lines:
            if line.strip().startswith(".PHONY:"):
                # Extract targets from .PHONY line, handling line continuations
                content = line.strip()[7:].strip()  # Remove '.PHONY:'

                # Handle continuation character
                if content.endswith("\\"):
                    content = content[:-1].strip()

                targets = [t.strip() for t in content.split() if t.strip()]
                phony_targets.update(targets)
            else:
                other_lines.append(line)

        # If we found phony targets, create a single .PHONY declaration
        if phony_targets:
            sorted_targets = sorted(phony_targets)  # Sort for consistent output
            phony_line = f".PHONY: {' '.join(sorted_targets)}"
            formatted_lines.append(phony_line)
            formatted_lines.append("")  # Add blank line after .PHONY
            changed = True

        # Add all other lines
        formatted_lines.extend(other_lines)

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=[],
        )
