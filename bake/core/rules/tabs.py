"""Tab formatting rule for Makefile recipes."""

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils import LineUtils


class TabsRule(FormatterPlugin):
    """Ensures tabs are used for recipe indentation instead of spaces."""

    def __init__(self) -> None:
        super().__init__("tabs", priority=10)

    def format(self, lines: list[str], config: dict) -> FormatResult:
        """Convert spaces to tabs in recipe lines."""
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        tab_width = config.get("tab_width", 4)

        for i, line in enumerate(lines):
            # Check if this is an indented line
            if line.startswith((" ", "\t")) and line.strip():
                # Determine if this is a recipe line or continuation line
                is_recipe = LineUtils.is_recipe_line(line, i, lines)

                if is_recipe:
                    # This is a recipe line - convert spaces to tabs preserving relative indentation
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

                    # Convert to tabs, ensuring at least 1 tab for recipe lines
                    num_tabs = max(1, total_spaces // tab_width)
                    remaining_spaces = total_spaces % tab_width

                    # Only preserve remaining spaces if the original line had meaningful mixed indentation
                    # (i.e., original had tabs + a small number of spaces for alignment)
                    original_has_tabs = "\t" in indent_chars
                    original_space_count = indent_chars.count(" ")

                    # Don't preserve remaining spaces if:
                    # 1. Original was all spaces (pure space indentation should become clean tabs)
                    # 2. Original had many spaces that don't represent intentional alignment
                    # 3. Original had mixed indentation (spaces before tabs) - should be cleaned up
                    spaces_before_tabs = False
                    if original_has_tabs:
                        # Check if spaces appear before tabs (bad mixed indentation)
                        first_tab_pos = indent_chars.find("\t")
                        if first_tab_pos > 0 and " " in indent_chars[:first_tab_pos]:
                            spaces_before_tabs = True

                    if (
                        not original_has_tabs
                        or original_space_count > 3
                        or spaces_before_tabs
                    ):
                        remaining_spaces = 0

                    # Create new line with proper tab indentation
                    new_line = "\t" * num_tabs + " " * remaining_spaces + stripped

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
            else:
                # Empty line or non-indented line
                formatted_lines.append(line)

        return FormatResult(
            lines=formatted_lines, changed=changed, errors=errors, warnings=warnings
        )
