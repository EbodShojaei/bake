"""Target colon spacing rule for Makefiles."""

import re
from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.line_utils import LineUtils
from ...utils.pattern_utils import PatternUtils


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

        for line_index, line in enumerate(lines):
            # Skip recipe lines, comments, and empty lines
            if (
                line.startswith("\t")
                or line.strip().startswith("#")
                or not line.strip()
            ):
                formatted_lines.append(line)
                continue

            # Get active recipe prefix for this line
            active_prefix = LineUtils.get_active_recipe_prefix(lines, line_index)

            # Update active .RECIPEPREFIX when encountered and emit unchanged
            m_prefix = re.match(r"^\s*\.RECIPEPREFIX\s*(?::=|=)\s*(.)\s*$", line)
            if m_prefix:
                formatted_lines.append(line)
                continue

            # Handle VPATH normalization (both start-of-line and target-specific)
            # First try target-specific: "target: VPATH = ..."
            assign = re.match(
                r"^([A-Za-z_][A-Za-z0-9_]*:)\s*([A-Za-z_][A-Za-z0-9_]*)\s*(:=|\+=|\?=|=|!=)\s*(.*)$",
                line,
            )
            if assign:
                target_part = assign.group(1)  # "target:"
                var_name = assign.group(2)
                operator = assign.group(3)
                value_part = assign.group(4)
            else:
                # Try start-of-line: "VPATH = ..."
                assign = re.match(
                    r"^([A-Za-z_][A-Za-z0-9_]*)\s*(:=|\+=|\?=|=|!=)\s*(.*)$", line
                )
                if assign:
                    target_part = ""
                    var_name = assign.group(1)
                    operator = assign.group(2)
                    value_part = assign.group(3)
                else:
                    assign = None

            if assign:

                # Normalize VPATH to fix invalid syntax and maintain consistent style
                if var_name == "VPATH":
                    # Split by colons and spaces, then rejoin based on original style
                    dirs = re.split(r"[: ]+", value_part.strip())
                    # Filter out empty strings
                    clean_dirs = [d for d in dirs if d.strip()]

                    # Determine style: if original had any colons, use colon-separated
                    # Otherwise preserve space-separated style
                    if ":" in value_part:
                        # Normalize to colon-separated (fixes invalid mixed syntax)
                        normalized_dirs = ":".join(clean_dirs)
                    else:
                        # Keep space-separated style
                        normalized_dirs = " ".join(clean_dirs)

                    # Handle empty VPATH case - preserve original spacing
                    if not normalized_dirs:
                        # If original value was just whitespace, preserve it
                        normalized_dirs = value_part if not value_part.strip() else " "

                    # Ensure proper spacing after target colon
                    if target_part and not target_part.endswith(": "):
                        target_part = target_part.rstrip(":") + ": "
                    new_line = f"{target_part}{var_name} {operator} {normalized_dirs}"
                    if new_line != line:
                        changed = True
                        formatted_lines.append(new_line)
                    else:
                        formatted_lines.append(line)
                    continue

                # Skip other assignments with colon-sensitive literals (URLs, datetimes, paths)
                if PatternUtils.value_is_colon_safe(value_part):
                    formatted_lines.append(line)
                    continue

            # Check if line contains a target (has a colon)
            # Treat lines that begin with the active recipe prefix as recipes (do not format)
            if LineUtils.is_recipe_line_with_prefix(line, active_prefix):
                formatted_lines.append(line)
                continue

            if LineUtils.colon_is_target_separator(
                line
            ) and not line.strip().startswith("."):
                # Skip if this looks like an assignment with colons in the value
                # (not assignment operators like :=, +=, etc.)
                if "=" in line:
                    # Check if this is an assignment with colons in the value
                    # Pattern: VAR = value:with:colons (skip target colon spacing)
                    # Pattern: VAR:=value (allow target colon spacing for assignment operators)
                    first_equals = line.find("=")
                    first_colon = line.find(":")

                    # If = comes before :, this might be an assignment
                    if first_equals < first_colon:
                        # Check if the colon is part of an assignment operator (:=, +=, etc.)
                        # or if it's in the value part
                        after_equals = line[first_equals:].strip()

                        # If the colon is immediately after = (like =: or =+), it's an assignment operator
                        if (
                            after_equals.startswith("=")
                            and len(after_equals) > 1
                            and after_equals[1] == ":"
                        ):
                            # This is an assignment operator like :=, allow target colon spacing
                            pass
                        else:
                            # This is an assignment with colons in the value, skip target colon spacing
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

                # Skip if this looks like an assignment operator (:=, +=, etc.)
                if prerequisites.strip().startswith("="):
                    formatted_lines.append(line)
                    continue

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
