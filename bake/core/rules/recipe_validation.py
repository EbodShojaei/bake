"""Recipe validation rule for Makefile recipes."""

from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.line_utils import LineUtils


class RecipeValidationRule(FormatterPlugin):
    """Validates that recipe lines have the required leading tab."""

    def __init__(self) -> None:
        super().__init__("recipe_validation", priority=8)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Validate and fix recipe lines that are missing required tabs."""
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []
        check_messages: list[str] = []

        fix_missing_tabs = config.get("fix_missing_recipe_tabs", True)

        for i, line in enumerate(lines):
            line_num = i + 1

            # Check if this should be a recipe line but is missing a tab
            if self._is_missing_recipe_tab(line, i, lines):
                error_msg = "Missing required tab separator in recipe line"

                if check_mode:
                    check_messages.append(
                        LineUtils.format_error_message(error_msg, line_num, config)
                    )
                else:
                    if fix_missing_tabs:
                        # Fix by replacing leading spaces with a tab
                        stripped_content = line.lstrip(" \t")
                        fixed_line = "\t" + stripped_content
                        formatted_lines.append(fixed_line)
                        changed = True
                    else:
                        # Report as error but don't fix
                        errors.append(
                            LineUtils.format_error_message(error_msg, line_num, config)
                        )
                        formatted_lines.append(line)
            else:
                formatted_lines.append(line)

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=check_messages,
        )

    def _is_missing_recipe_tab(
        self, line: str, line_index: int, all_lines: list[str]
    ) -> bool:
        """
        Check if a line should be a recipe line but is missing the required tab.

        Args:
            line: The line to check
            line_index: Index of the line in the file
            all_lines: All lines in the file

        Returns:
            True if this line should be a recipe but is missing a tab
        """
        stripped = line.strip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("#"):
            return False

        # Skip lines that already start with tab (correctly formatted)
        if line.startswith("\t"):
            return False

        # Skip variable assignments and directives
        if "=" in stripped or stripped.startswith(
            (
                ".PHONY",
                "include",
                "export",
                "unexport",
                "define",
                "ifeq",
                "ifneq",
                "ifdef",
                "ifndef",
                "else",
                "endif",
                "endef",
            )
        ):
            return False

        # Skip content inside define blocks
        if LineUtils.is_inside_define_block(line_index, all_lines):
            return False

        # Skip target lines themselves (they shouldn't start with tabs)
        if ":" in stripped and not (
            "=" in stripped and stripped.find("=") < stripped.find(":")
        ):
            return False

        # Use the same logic as the formatter - check if this should be a recipe line
        return LineUtils.is_recipe_line(line, line_index, all_lines)

    def _follows_target_line(self, line_index: int, all_lines: list[str]) -> bool:
        """
        Check if this line follows a target definition (directly or through other recipe lines).

        Args:
            line_index: Index of the current line
            all_lines: All lines in the file

        Returns:
            True if this line should be part of a recipe
        """
        # Look backward to find what this line belongs to
        for i in range(line_index - 1, -1, -1):
            prev_line = all_lines[i]
            prev_stripped = prev_line.strip()

            # Skip empty lines and comments (comments should not break context)
            if not prev_stripped or prev_stripped.startswith("#"):
                continue

            # If we find another indented line, check if it's a recipe line
            if prev_line.startswith(("\t", " ")):
                # If the previous line is a properly formatted recipe line (starts with tab),
                # then this line should also be a recipe line
                if prev_line.startswith("\t"):
                    return True
                # If previous line is also missing a tab, continue looking backward
                continue

            # If we find a target line, this should be a recipe
            if LineUtils.is_target_line(prev_line):
                return True

            # If we find a non-target, non-recipe line, this is not a recipe
            break

        return False
