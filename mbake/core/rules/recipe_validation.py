"""Rule for validating recipe line formatting."""

import re
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

            # Get active recipe prefix for this line
            active_prefix = LineUtils.get_active_recipe_prefix(lines, i)

            # Check if this should be a recipe line but is missing a tab
            if self._is_missing_recipe_tab(line, i, lines, active_prefix):
                error_msg = "Missing required tab separator in recipe line"

                if check_mode:
                    gnu_format = config.get("gnu_error_format", False)
                    if gnu_format:
                        check_messages.append(
                            f"Makefile:{line_num}: Error: {error_msg}"
                        )
                    else:
                        check_messages.append(f"Line {line_num}: Error: {error_msg}")
                else:
                    if fix_missing_tabs:
                        # Fix by replacing leading spaces with a tab
                        stripped_content = line.lstrip(" \t")
                        fixed_line = "\t" + stripped_content
                        formatted_lines.append(fixed_line)
                        changed = True
                    else:
                        # Report as error but don't fix
                        gnu_format = config.get("gnu_error_format", False)
                        if gnu_format:
                            errors.append(f"Makefile:{line_num}: Error: {error_msg}")
                        else:
                            errors.append(f"Line {line_num}: Error: {error_msg}")
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
        self, line: str, line_index: int, all_lines: list[str], active_prefix: str
    ) -> bool:
        """
        Check if a line should be a recipe line but is missing the required tab.

        Args:
            line: The line to check
            line_index: Index of the line in the file
            all_lines: All lines in the file
            active_prefix: The active recipe prefix character

        Returns:
            True if this line should be a recipe but is missing a tab
        """
        stripped = line.strip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("#"):
            return False

        # Skip lines that already start with the active recipe prefix (correctly formatted)
        if LineUtils.is_recipe_line_with_prefix(line, active_prefix):
            return False

        # Skip lines that already start with tab (correctly formatted) or space (continuations/intentional indent)
        if line.startswith(("\t", " ")):
            return False

        # Skip variable assignments and directives
        if (
            "=" in stripped
            or stripped.startswith(
                (
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
            )
            or stripped in self._get_special_make_targets()
        ):
            return False

        # Skip content inside define blocks
        if self._is_inside_define_block(line_index, all_lines):
            return False

        # Skip target lines themselves (they shouldn't start with tabs)
        if ":" in stripped and not (
            "=" in stripped and stripped.find("=") < stripped.find(":")
        ):
            return False

        # Check if this should be a recipe line based on context
        return self._should_be_recipe_line(line, line_index, all_lines)

    def _get_special_make_targets(self) -> set[str]:
        """Get all special Makefile targets."""
        return {
            ".PHONY",
            ".SUFFIXES",
            ".PRECIOUS",
            ".INTERMEDIATE",
            ".SECONDARY",
            ".DELETE_ON_ERROR",
            ".IGNORE",
            ".SILENT",
            ".EXPORT_ALL_VARIABLES",
            ".NOTPARALLEL",
            ".ONESHELL",
            ".POSIX",
            ".LOW_RESOLUTION_TIME",
            ".SECOND_EXPANSION",
            ".SECONDEXPANSION",
            ".VARIABLES",
            ".MAKE",
            ".WAIT",
            ".INCLUDE_DIRS",
            ".LIBPATTERNS",
        }

    def _is_inside_define_block(self, line_index: int, all_lines: list[str]) -> bool:
        """Check if the current line is inside a define block."""
        define_stack = []
        for i in range(line_index):
            check_line = all_lines[i].strip()
            if check_line.startswith("define "):
                define_stack.append(i)
            elif check_line == "endef" and define_stack:
                define_stack.pop()

        # If define_stack is not empty, we're inside a define block
        return bool(define_stack)

    def _should_be_recipe_line(
        self, line: str, line_index: int, all_lines: list[str]
    ) -> bool:
        """Check if a line should be a recipe line based on context."""
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
            if self._is_target_line(prev_line, i, all_lines):
                return True

            # If we find a non-target, non-recipe line, this is not a recipe
            break

        return False

    def _is_target_line(self, line: str, line_index: int, all_lines: list[str]) -> bool:
        """Check if a line is a target definition."""
        stripped = line.strip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("#"):
            return False

        # Skip variable assignments
        if "=" in stripped and (
            ":" not in stripped
            or ":=" in stripped
            or "+=" in stripped
            or "?=" in stripped
        ):
            return False

        # Skip export variable assignments
        if stripped.startswith("export ") and "=" in stripped:
            return False

        # Skip function calls and other constructs
        if stripped.startswith("$(") and stripped.endswith(")"):
            return False

        # Skip lines that are clearly not target definitions
        if stripped.startswith("@") or "$(" in stripped:
            return False

        # Check for target pattern: name: prerequisites
        target_pattern = re.compile(r"^([^:=]+):(:?)\s*(.*)$")
        match = target_pattern.match(stripped)
        if match:
            target_name = match.group(1).strip()
            target_body = match.group(3).strip()

            # Skip comment-only targets (documentation targets)
            if target_body.startswith("##"):
                return False

            # Skip target-specific variable assignments
            if re.match(r"^\s*[A-Z_][A-Z0-9_]*\s*[+:?]?=", target_body):
                return False

            # Skip template placeholders
            return not re.fullmatch(r"\$[({][^})]+[})]", target_name)

        return False
