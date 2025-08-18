"""Target colon spacing rule for Makefiles."""

from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin


class TargetSpacingRule(FormatterPlugin):
    """Handles spacing around colons in target definitions."""

    def __init__(self) -> None:
        super().__init__("target_spacing", priority=18)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Normalize spacing around colons in target definitions."""
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        space_before_colon = config.get("space_before_colon", False)
        space_after_colon = config.get("space_after_colon", True)

        for line in lines:
            # Skip recipe lines, comments, and empty lines
            if (
                line.startswith("\t")
                or line.strip().startswith("#")
                or not line.strip()
            ):
                formatted_lines.append(line)
                continue

            # Check if line contains a target (has a colon)
            if ":" in line and not line.strip().startswith("."):
                # Skip if this looks like an assignment (has = after the colon)
                if "=" in line and line.find("=") > line.find(":"):
                    formatted_lines.append(line)
                    continue

                # Skip if this is a recipe line (starts with space)
                if line.startswith(" "):
                    formatted_lines.append(line)
                    continue

                # Skip if this contains variable references with substitution (like $(VAR:pattern=replacement))
                if "$(" in line and ":" in line and "=" in line:
                    formatted_lines.append(line)
                    continue

                # Check for double-colon rules first - these must not be modified
                if "::" in line:
                    formatted_lines.append(line)
                    continue

                # Format target colon spacing
                parts = line.split(":", 1)
                target = parts[0].rstrip()
                prerequisites = parts[1] if len(parts) > 1 else ""

                # Apply spacing rules
                if space_before_colon:
                    target += " "
                if space_after_colon and prerequisites.strip():
                    # Only add space after colon if there are actual prerequisites
                    prerequisites = " " + prerequisites.lstrip()
                else:
                    prerequisites = prerequisites.lstrip()

                new_line = target + ":" + prerequisites
                if new_line != line:
                    changed = True
                    formatted_lines.append(new_line)
                else:
                    formatted_lines.append(line)
            else:
                formatted_lines.append(line)

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=[],
        )
