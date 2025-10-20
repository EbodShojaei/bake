"""Assignment operator spacing rule for Makefiles."""

import re
from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.pattern_utils import PatternUtils


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

        for i, line in enumerate(lines, 1):
            new_line = line  # Default to original line

            # Skip recipe lines (lines starting with tab) or comments or empty lines
            if (
                line.startswith("\t")
                or line.strip().startswith("#")
                or not line.strip()
            ):
                pass  # Keep original line
            # Check if line contains assignment operator
            elif re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*(:=|\+=|\?=|=|!=)\s*", line):
                # Check for reversed assignment operators first
                reversed_warning = self._check_reversed_operators(line, i)
                if reversed_warning:
                    warnings.append(reversed_warning)

                # Skip substitution references like $(VAR:pattern=replacement) which are not assignments
                # or skip invalid target-like lines of the form VAR=token:... (no space after '=')
                if re.search(
                    r"\$\([^)]*:[^)]*=[^)]*\)", line
                ) or self._is_invalid_target_syntax(line):
                    pass  # Keep original line
                else:
                    # Extract the parts - be more careful about the operator
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

            # Single append at the end
            if new_line != line:
                changed = True
            formatted_lines.append(new_line)

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=[],
        )

    def _is_invalid_target_syntax(self, line: str) -> bool:
        """Check if line contains invalid target syntax that should be preserved."""
        stripped = line.strip()
        # Only flag when there is NO whitespace after '=' before the first ':'
        # This avoids flagging typical assignments whose values contain ':' (URLs, times, paths).
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*=\S*:\S*", stripped):
            return False
        # Allow colon-safe values to pass (URLs, datetimes, drive/path patterns)
        after_eq = stripped.split("=", 1)[1]
        return not PatternUtils.value_is_colon_safe(after_eq)

    def _check_reversed_operators(self, line: str, line_number: int) -> str:
        """Check for reversed assignment operators and return warning message if found."""
        stripped = line.strip()

        # Skip if this is not a variable assignment line
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", stripped):
            return ""

        # Check for reversed operators: =?, =:, =+
        # Pattern: variable = [space] [?:+] [space or end or value]
        # This handles both "FOO = ? bar" and "FOO =?bar" cases
        reversed_match = re.search(r"=\s*([?:+])(?:\s|$|[a-zA-Z0-9_])", stripped)
        if reversed_match:
            reversed_char = reversed_match.group(1)
            correct_operator = f"{reversed_char}="
            reversed_operator = f"={reversed_char}"

            # Get the variable name for context
            var_match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)", stripped)
            var_name = var_match.group(1) if var_match else "variable"

            return (
                f"Line {line_number}: Possible typo in assignment operator '{reversed_operator}' "
                f"for variable '{var_name}', did you mean '{correct_operator}'? "
                f"Make will treat this as a regular assignment with '{reversed_char}' as part of the value."
            )

        return ""
