"""Assignment operator spacing rule for Makefiles."""

import re
from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin


class AssignmentSpacingRule(FormatterPlugin):
    """Handles spacing around assignment operators (=, :=, +=, ?=)."""

    def __init__(self) -> None:
        super().__init__("assignment_spacing", priority=15)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Normalize spacing around assignment operators."""
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        space_around_assignment = config.get("space_around_assignment", True)

        for line in lines:
            # Skip recipe lines (lines starting with tab)
            if line.startswith("\t"):
                formatted_lines.append(line)
                continue

            # Skip comments and empty lines
            if line.strip().startswith("#") or not line.strip():
                formatted_lines.append(line)
                continue

            # Check if line contains assignment operator
            # Look for variable assignment at the start of the line
            # Use a more specific regex to avoid splitting := incorrectly
            # Variable assignments can contain variable references in their values
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*(:=|\+=|\?=|=|!=)\s*", line):
                # Skip substitution references like $(VAR:pattern=replacement) which are not assignments
                if re.search(r"\$\([^)]*:[^)]*=[^)]*\)", line):
                    formatted_lines.append(line)
                    continue

                # Extract the parts - be more careful about the operator
                # Use a more specific regex to avoid splitting := incorrectly
                match = re.match(
                    r"^([A-Za-z_][A-Za-z0-9_]*)\s*(:=|\+=|\?=|=|!=)\s*(.*)", line
                )
                if match:
                    var_name = match.group(1)
                    operator = match.group(2)
                    value = match.group(3)

                    # Only format if this is actually an assignment (not a target)
                    if operator in ["=", ":=", "?=", "+=", "!="]:
                        if space_around_assignment:
                            # Only add trailing space if there's actually a value
                            if value.strip():
                                new_line = f"{var_name} {operator} {value}"
                            else:
                                new_line = f"{var_name} {operator}"
                        else:
                            new_line = f"{var_name}{operator}{value}"

                        if new_line != line:
                            changed = True
                            formatted_lines.append(new_line)
                        else:
                            formatted_lines.append(line)
                    else:
                        formatted_lines.append(line)
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
