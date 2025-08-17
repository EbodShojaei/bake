"""Tab formatting rule for Makefile recipes."""

from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.line_utils import LineUtils


class TabsRule(FormatterPlugin):
    """Ensures tabs are used for recipe indentation instead of spaces."""

    def __init__(self) -> None:
        super().__init__("tabs", priority=10)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Convert spaces to tabs for recipe lines only."""
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        for line_index, line in enumerate(lines):
            # Skip empty lines
            if not line.strip():
                formatted_lines.append(line)
                continue

            # Skip comments
            if line.strip().startswith("#"):
                formatted_lines.append(line)
                continue

            stripped = line.strip()

            # Handle conditional directives - these should start at column 1 according to GNU Make syntax
            # BUT: nested conditionals inside else blocks should preserve indentation
            if line.startswith(" ") and stripped.startswith(
                ("ifeq", "ifneq", "ifdef", "ifndef", "else", "endif")
            ):

                # Check if this is a nested conditional that should preserve indentation
                if self._is_nested_conditional(line_index, lines, stripped):
                    # This is a nested conditional inside an else block - preserve indentation
                    formatted_lines.append(line)
                else:
                    # This is a top-level conditional directive - move to column 1
                    new_line = stripped
                    if new_line != line:
                        changed = True
                        formatted_lines.append(new_line)
                    else:
                        formatted_lines.append(line)
            # Check if this is a recipe line (command that should be executed)
            # Recipe lines are indented lines that are not:
            # - Variable assignments
            # - Include statements
            # - Variable definition continuations
            # - Function calls
            # - Other makefile constructs
            elif (
                line.startswith(" ")
                and stripped  # Not empty
                and not stripped.startswith("#")  # Not a comment
                and not self._is_target_definition(stripped)  # Not a target definition
                # Note: we DO want to process continuation lines for tab conversion
                and not self._is_variable_assignment_line(
                    stripped
                )  # Not a variable assignment
                and not stripped.startswith(
                    ("include", "-include", "vpath")
                )  # Not include/vpath
                and not self._is_variable_continuation(
                    line, line_index, lines
                )  # Not variable continuation
                and not LineUtils.is_makefile_construct(
                    stripped
                )  # Not a makefile construct
            ):
                # Convert leading spaces to tab for recipe lines
                content = line.lstrip()
                # For recipe lines, always use exactly one tab
                new_line = "\t" + content
                if new_line != line:
                    changed = True
                    formatted_lines.append(new_line)
                else:
                    formatted_lines.append(line)
            elif line.startswith("\t"):
                # Already starts with tab
                formatted_lines.append(line)
            else:
                # Not a recipe line, preserve as-is
                formatted_lines.append(line)

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=[],
        )

    def _is_nested_conditional(
        self, line_index: int, lines: list[str], stripped: str
    ) -> bool:
        """Check if this conditional directive is nested inside another conditional block."""
        if line_index == 0:
            return False

        # Track conditional nesting depth
        conditional_depth = 0

        # Look backwards to see if we're inside a conditional block
        for i in range(line_index - 1, -1, -1):
            prev_line = lines[i]
            prev_stripped = prev_line.strip()

            # Skip empty lines and comments
            if not prev_stripped or prev_stripped.startswith("#"):
                continue

            # Check for conditional directives
            if prev_stripped.startswith("endif"):
                conditional_depth += 1
            elif prev_stripped.startswith(("ifeq", "ifneq", "ifdef", "ifndef")):
                conditional_depth -= 1

                # If we've reached depth 0, we found the matching opening conditional
                if conditional_depth < 0:
                    # We are inside a conditional block, so this could be nested
                    # But only preserve indentation for conditionals inside else blocks
                    # or for nested conditionals that have meaningful indentation
                    return True

        return False

    def _is_variable_continuation(
        self, line: str, line_index: int, lines: list[str]
    ) -> bool:
        """Check if this line is a continuation of a variable definition."""
        if line_index == 0:
            return False

        # Look at the previous line(s) to see if this is a continuation
        for i in range(line_index - 1, -1, -1):
            prev_line = lines[i]
            prev_stripped = prev_line.strip()

            # Skip empty lines and comments
            if not prev_stripped or prev_stripped.startswith("#"):
                continue

            # If we find a line ending with \, this could be a continuation
            if prev_stripped.endswith("\\"):
                # Check if it's a variable assignment or part of one
                # Look for the original assignment line
                for j in range(i, -1, -1):
                    check_line = lines[j].strip()
                    if not check_line or check_line.startswith("#"):
                        continue
                    if "=" in check_line and not check_line.startswith("\t"):
                        return True
                    if not check_line.endswith("\\"):
                        break
                return False
            else:
                # No backslash, so this is not a continuation
                return False

        return False

    def _is_variable_assignment_line(self, stripped: str) -> bool:
        """Check if this is a Makefile variable assignment (not a shell command with =)."""
        if "=" not in stripped:
            return False

        # Use the existing LineUtils method which properly detects Makefile variable assignments
        return LineUtils.is_variable_assignment(stripped)

    def _is_target_definition(self, stripped: str) -> bool:
        """Check if this is a target definition (not a command with colons)."""
        if ":" not in stripped:
            return False

        # Basic target pattern: target_name : prerequisites
        # The colon should be at the top level, not inside quotes, parentheses, etc.

        # Find the position of the first unquoted, unescaped colon
        in_single_quote = False
        in_double_quote = False
        paren_depth = 0
        i = 0

        while i < len(stripped):
            char = stripped[i]

            # Handle escape sequences
            if char == "\\" and i + 1 < len(stripped):
                i += 2  # Skip escaped character
                continue

            # Handle quotes
            if char == "'" and not in_double_quote:
                in_single_quote = not in_single_quote
            elif char == '"' and not in_single_quote:
                in_double_quote = not in_double_quote
            elif char == "(" and not in_single_quote and not in_double_quote:
                paren_depth += 1
            elif char == ")" and not in_single_quote and not in_double_quote:
                paren_depth -= 1
            elif (
                char == ":"
                and not in_single_quote
                and not in_double_quote
                and paren_depth == 0
            ):
                # Found an unquoted, top-level colon
                # Check if this looks like a target definition
                target_part = stripped[:i].strip()

                # Empty target part means this isn't a target definition
                if not target_part:
                    return False

                # Target names shouldn't contain spaces (unless escaped or quoted)
                # But make does allow multiple targets separated by spaces
                # So we'll be conservative and say if it contains unquoted spaces, it's likely not a target

                # Check for obvious non-target patterns
                return not (
                    target_part.startswith(("@", "-", "+"))  # Recipe prefixes
                    or "=" in target_part  # Variable assignments within
                    or target_part.endswith("\\")  # Continuation lines
                )

            i += 1

        return False
