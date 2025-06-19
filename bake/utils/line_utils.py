"""Utility functions for line processing in Makefile formatting."""


class LineUtils:
    """Common line processing utilities used across formatting rules."""

    @staticmethod
    def should_skip_line(
        line: str,
        skip_recipe: bool = True,
        skip_comments: bool = True,
        skip_empty: bool = True,
    ) -> bool:
        """
        Check if a line should be skipped based on common criteria.

        Args:
            line: The line to check
            skip_recipe: Skip recipe lines (start with tab or spaces)
            skip_comments: Skip comment lines (start with #)
            skip_empty: Skip empty lines

        Returns:
            True if the line should be skipped
        """
        # Skip recipe lines (start with tab or spaces)
        if skip_recipe and line.startswith(("\t", " ")):
            return True

        # Skip comment lines
        if skip_comments and line.strip().startswith("#"):
            return True

        # Skip empty lines
        return bool(skip_empty and not line.strip())

    @staticmethod
    def is_recipe_line(line: str, line_index: int, all_lines: list[str]) -> bool:
        """
        Check if a line is a recipe line (indented line that belongs to a target).

        Args:
            line: The line to check
            line_index: Index of the line in the file
            all_lines: All lines in the file

        Returns:
            True if this is a recipe line
        """
        return LineUtils._is_recipe_line_helper(line, line_index, all_lines, set())

    @staticmethod
    def _is_recipe_line_helper(
        line: str, line_index: int, all_lines: list[str], visited: set
    ) -> bool:
        """Helper method to avoid infinite recursion."""
        if not (line.startswith(("\t", " ")) and line.strip()):
            return False

        # Avoid infinite recursion
        if line_index in visited:
            return False
        visited.add(line_index)

        # Look backward to find what this indented line belongs to
        for i in range(line_index - 1, -1, -1):
            if i in visited:
                continue

            prev_line = all_lines[i]
            prev_stripped = prev_line.strip()

            # Skip empty lines
            if not prev_stripped:
                continue

            # If previous line is an indented line that ends with backslash,
            # this could be a recipe continuation line
            if prev_line.startswith(("\t", " ")) and prev_stripped.endswith("\\"):
                # Check if the previous line is a recipe line
                if LineUtils._is_recipe_line_helper(
                    prev_line, i, all_lines, visited.copy()
                ):
                    return True
                continue

            # If previous line is an indented recipe line, this is also a recipe line
            if prev_line.startswith(("\t", " ")):
                if LineUtils._is_recipe_line_helper(
                    prev_line, i, all_lines, visited.copy()
                ):
                    return True
                continue

            # Check if this is a target line (contains : but not an assignment)
            if ":" in prev_stripped and not prev_stripped.startswith("#"):
                # Exclude variable assignments that contain colons
                if "=" in prev_stripped and prev_stripped.find(
                    "="
                ) < prev_stripped.find(":"):
                    return False
                # Exclude conditional blocks and function definitions
                # This is a target line (could be target:, target: prereq, or %.o: %.c)
                return not prev_stripped.startswith(
                    ("ifeq", "ifneq", "ifdef", "ifndef", "define")
                )

            # If we find a variable assignment without colon, this is a continuation
            if "=" in prev_stripped and not prev_stripped.startswith(
                ("ifeq", "ifneq", "ifdef", "ifndef")
            ):
                return False

            # If we find a directive line, not a recipe
            if prev_stripped.startswith((".PHONY", "include", "export", "unexport")):
                return False

            # If we reach a non-indented, non-target line, default to False
            if not prev_line.startswith(("\t", " ")):
                break

        # Default to not a recipe if we can't determine context
        return False

    @staticmethod
    def is_target_line(line: str) -> bool:
        """
        Check if a line defines a target.

        Args:
            line: The line to check

        Returns:
            True if this is a target definition line
        """
        stripped = line.strip()

        # Must contain a colon and not be a comment
        if ":" not in stripped or stripped.startswith("#"):
            return False

        # Exclude conditional blocks and function definitions
        if stripped.startswith(("ifeq", "ifneq", "ifdef", "ifndef", "define", "endef")):
            return False

        # Exclude variable assignments that contain colons
        return not ("=" in stripped and stripped.find("=") < stripped.find(":"))

    @staticmethod
    def is_variable_assignment(line: str) -> bool:
        """
        Check if a line is a variable assignment.

        Args:
            line: The line to check

        Returns:
            True if this is a variable assignment
        """
        stripped = line.strip()

        # Must contain an equals sign and not be a comment
        if "=" not in stripped or stripped.startswith("#"):
            return False

        # Exclude conditional blocks
        return not stripped.startswith(("ifeq", "ifneq", "ifdef", "ifndef"))

    @staticmethod
    def is_continuation_line(line: str) -> bool:
        """
        Check if a line ends with a backslash (continuation).

        Args:
            line: The line to check

        Returns:
            True if this is a continuation line
        """
        return line.rstrip().endswith("\\")

    @staticmethod
    def normalize_whitespace(line: str, remove_trailing: bool = True) -> str:
        """
        Normalize whitespace in a line.

        Args:
            line: The line to normalize
            remove_trailing: Whether to remove trailing whitespace

        Returns:
            The normalized line
        """
        if remove_trailing:
            return line.rstrip()
        return line
