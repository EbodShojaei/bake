"""Tab formatting rule for Makefile recipes."""

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
        """Convert spaces to tabs in recipe lines."""
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        tab_width = config.get("tab_width", 4)

        for i, line in enumerate(lines):
            # Check if this is an indented line or should be indented
            is_recipe = LineUtils.is_recipe_line(line, i, lines)

            if line.startswith((" ", "\t")) and line.strip():
                # This line is already indented

                if is_recipe:
                    # This is a recipe line - convert spaces to tabs while normalizing basic indentation
                    stripped = line.lstrip(" \t")

                    # Calculate the indentation level in terms of tabs
                    indent_chars = line[: len(line) - len(stripped)]
                    total_spaces = 0

                    # Convert existing tabs and spaces to a space count
                    for char in indent_chars:
                        if char == " ":
                            total_spaces += 1
                        elif char == "\t":
                            total_spaces += tab_width

                    # Convert to tabs, with normalization for basic recipe lines
                    if total_spaces <= tab_width:
                        # Basic recipe indentation - normalize to single tab
                        num_tabs = 1
                    else:
                        # Deeper indentation - preserve relative levels but ensure tab alignment
                        num_tabs = max(1, total_spaces // tab_width)

                    # Create new line with proper tab indentation (no remaining spaces for simplicity)
                    new_line = "\t" * num_tabs + stripped

                    if new_line != line:
                        changed = True
                        formatted_lines.append(new_line)
                    else:
                        formatted_lines.append(line)
                else:
                    # Not a recipe line (e.g., variable continuation) - convert tabs to spaces
                    stripped = line.lstrip(" \t")
                    if line.startswith("\t"):
                        # Convert tab to spaces (use 2 spaces for continuation lines)
                        new_line = "  " + stripped
                        if new_line != line:
                            changed = True
                        formatted_lines.append(new_line)
                    else:
                        # Already uses spaces, keep as is
                        formatted_lines.append(line)
            elif is_recipe and line.strip():
                # This line should be indented as a recipe but isn't yet
                stripped = line.strip()
                new_line = "\t" + stripped
                changed = True
                formatted_lines.append(new_line)
            else:
                # Empty line or non-indented line that shouldn't be indented
                formatted_lines.append(line)

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=[],
        )
