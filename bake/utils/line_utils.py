"""Utility functions for line processing in Makefile formatting."""

import re
from typing import Any


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
    def should_skip_makefile_line(line: str) -> bool:
        """
        Check if a line should be skipped when parsing Makefile structure.

        This is commonly used across phony rules to skip non-target lines.

        Args:
            line: The line to check

        Returns:
            True if the line should be skipped during Makefile parsing
        """
        stripped = line.strip()

        # Skip empty lines, comments, includes, conditionals
        return (
            not stripped
            or stripped.startswith("#")
            or stripped.startswith("include")
            or stripped.startswith("-include")
            or stripped.startswith("ifeq")
            or stripped.startswith("ifneq")
            or stripped.startswith("ifdef")
            or stripped.startswith("ifndef")
            or stripped.startswith("else")
            or stripped.startswith("endif")
        )

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
    def is_variable_assignment_with_colon(line: str) -> bool:
        """
        Check if a line is a variable assignment that contains a colon.

        This is used to distinguish between variable assignments like 'CC := gcc'
        and target definitions like 'target: dependencies'.

        Args:
            line: The line to check

        Returns:
            True if this is a variable assignment with := or = that contains a colon
        """
        stripped = line.strip()

        # Check for variable assignment patterns
        return bool(
            ":=" in stripped or "=" in stripped and ":" not in stripped.split("=")[0]
        )

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


class MakefileParser:
    """Utilities for parsing Makefile structure and extracting targets."""

    @staticmethod
    def parse_targets_and_recipes(lines: list[str]) -> list[tuple[str, list[str]]]:
        """
        Parse all targets and their recipe lines from the Makefile.

        This is commonly used across phony rules to extract target information.

        Args:
            lines: List of lines from the Makefile

        Returns:
            List of tuples containing (target_name, recipe_lines)
        """
        targets = []
        current_target = None
        current_recipe: list[str] = []

        for line in lines:
            stripped = line.strip()

            # Skip lines that don't contribute to target structure
            if LineUtils.should_skip_makefile_line(line):
                continue

            # Check if this is a target line (has colon and is not indented)
            if ":" in stripped and not line.startswith("\t"):
                # Save previous target if exists
                if current_target:
                    targets.append((current_target, current_recipe.copy()))

                # Check if this is a variable assignment
                if LineUtils.is_variable_assignment_with_colon(line):
                    current_target = None
                    current_recipe = []
                    continue

                # Parse target name (everything before first colon)
                target_part = stripped.split(":")[0].strip()

                # Skip pattern rules, special targets, and complex targets
                if MakefileParser._should_skip_target(target_part):
                    current_target = None
                    current_recipe = []
                    continue

                current_target = target_part
                current_recipe = []

            # Check if this is a recipe line
            elif line.startswith("\t") and current_target:
                current_recipe.append(line.strip())

        # Don't forget the last target
        if current_target:
            targets.append((current_target, current_recipe.copy()))

        return targets

    @staticmethod
    def _should_skip_target(target_part: str) -> bool:
        """
        Check if a target should be skipped during parsing.

        Args:
            target_part: The target name part of the line

        Returns:
            True if this target should be skipped
        """
        return (
            target_part.startswith(".")
            or "%" in target_part
            or "$" in target_part
            or " " in target_part  # Multiple targets
            or not target_part  # Empty target
        )

    @staticmethod
    def extract_phony_targets(lines: list[str]) -> set[str]:
        """
        Extract targets from existing .PHONY declarations.

        Args:
            lines: List of lines from the Makefile

        Returns:
            Set of target names found in .PHONY declarations
        """
        phony_targets = set()

        for line in lines:
            stripped = line.strip()
            if stripped.startswith(".PHONY:"):
                targets_part = stripped[7:].strip()  # Remove '.PHONY:'
                targets = [t.strip() for t in targets_part.split() if t.strip()]
                phony_targets.update(targets)

        return phony_targets

    @staticmethod
    def has_phony_declarations(lines: list[str]) -> bool:
        """
        Check if the Makefile has any .PHONY declarations.

        Args:
            lines: List of lines from the Makefile

        Returns:
            True if .PHONY declarations exist
        """
        return any(line.strip().startswith(".PHONY:") for line in lines)

    @staticmethod
    def find_phony_insertion_point(lines: list[str]) -> int:
        """
        Find the best place to insert .PHONY declarations at the top.

        Uses enhanced logic that respects comment blocks:
        - Treats contiguous comments as file header
        - Inserts .PHONY after first blank line following header comments
        - Preserves section comments that come after variables/blank lines

        Args:
            lines: List of lines from the Makefile

        Returns:
            Index where .PHONY should be inserted
        """
        in_header_comments = True
        last_comment_index = -1

        for i, line in enumerate(lines):
            stripped = line.strip()

            if not stripped:  # Empty line
                if in_header_comments and last_comment_index >= 0:
                    # Found blank line after header comments - insert here
                    return i
                # Continue looking (empty line in middle of file)
                continue

            elif stripped.startswith("#"):  # Comment
                if not in_header_comments:
                    # This is a section comment after variables/rules, skip it
                    continue
                last_comment_index = i
                continue

            elif (
                "=" in stripped
                or stripped.startswith("include")
                or stripped.startswith("-include")
            ):
                # Variable assignment or include - part of declarations
                in_header_comments = False
                continue

            else:
                # First rule/target found
                return i

        # If we get here, insert at the end
        return len(lines)


class ConditionalTracker:
    """Utility for tracking conditional contexts in Makefiles."""

    def __init__(self) -> None:
        """Initialize the conditional tracker."""
        self.conditional_stack: list[dict[str, Any]] = []
        self.conditional_branch_id: int = 0

    def process_line(self, line: str, line_index: int) -> tuple:
        """Process a line and return the conditional context the line is IN.

        Args:
            line: The line to process
            line_index: Index of the line (for debugging)

        Returns:
            Tuple representing the conditional context the line is IN
        """
        stripped = line.strip()

        # Get current context BEFORE processing conditional directives
        # This way we return the context the line is IN, not the context after processing it
        current_context = tuple(block["branch_id"] for block in self.conditional_stack)

        # Track conditional blocks (update state after getting current context)
        if stripped.startswith(("ifeq", "ifneq", "ifdef", "ifndef")):
            self.conditional_stack.append(
                {
                    "type": "if",
                    "line": line_index,
                    "branch_id": self.conditional_branch_id,
                }
            )
            self.conditional_branch_id += 1
        elif stripped.startswith("else"):
            if self.conditional_stack and self.conditional_stack[-1]["type"] == "if":
                self.conditional_stack[-1]["type"] = "else"
                self.conditional_stack[-1]["branch_id"] = self.conditional_branch_id
                self.conditional_branch_id += 1
        elif stripped.startswith("endif"):
            if self.conditional_stack:
                self.conditional_stack.pop()

        # Return the context the line was IN (before processing)
        return current_context

    def reset(self) -> None:
        """Reset the tracker state."""
        self.conditional_stack = []
        self.conditional_branch_id = 0

    @staticmethod
    def are_mutually_exclusive(context1: tuple, context2: tuple) -> bool:
        """Check if two conditional contexts are mutually exclusive.

        Two contexts are mutually exclusive if they differ at any conditional level,
        which means they're in different branches of some conditional block.

        Args:
            context1: First conditional context
            context2: Second conditional context

        Returns:
            True if contexts are mutually exclusive
        """
        # If contexts are identical, not mutually exclusive
        if context1 == context2:
            return False

        # If one context is empty and the other not, not mutually exclusive
        # in the sense that one is unconditional and the other is conditional
        if not context1 or not context2:
            return False

        # Compare contexts level by level
        min_len = min(len(context1), len(context2))

        # If contexts differ at any level, mutually exclusive
        return any(context1[i] != context2[i] for i in range(min_len))


class PhonyAnalyzer:
    """Utilities for analyzing whether targets are phony."""

    @staticmethod
    def is_target_phony(target_name: str, recipe_lines: list[str]) -> bool:
        """
        Determine if a target is phony by analyzing its recipe.

        Args:
            target_name: Name of the target
            recipe_lines: List of recipe command lines

        Returns:
            True if the target is likely phony
        """
        if not recipe_lines:
            # No recipe usually means phony (like .PHONY: help)
            return True

        # Analyze recipe commands to determine if they create a file with target_name
        creates_target_file = False

        for recipe_line in recipe_lines:
            # Remove variable expansions and quotes for analysis
            clean_line = PhonyAnalyzer._clean_command_for_analysis(recipe_line)

            # Check for file creation patterns that create target file
            if PhonyAnalyzer._command_creates_target_file(clean_line, target_name):
                creates_target_file = True
                break

        # Target is phony if it doesn't create a file with its own name
        return not creates_target_file

    @staticmethod
    def _clean_command_for_analysis(command: str) -> str:
        """
        Clean command line for analysis by removing variables and quotes.

        Args:
            command: Raw command line

        Returns:
            Cleaned command line suitable for analysis
        """
        # Remove common variable patterns
        clean = re.sub(r"\$\([^)]+\)", "", command)
        clean = re.sub(r"\$\{[^}]+\}", "", clean)
        clean = re.sub(r"\$[A-Za-z_][A-Za-z0-9_]*", "", clean)

        # Remove quotes
        clean = clean.replace('"', "").replace("'", "")

        return clean.strip()

    @staticmethod
    def _command_creates_target_file(command: str, target_name: str) -> bool:
        """
        Check if command creates a file with the target name.

        Args:
            command: Cleaned command line
            target_name: Name of the target

        Returns:
            True if the command creates a file with the target name
        """
        # Compilation patterns that create target file with -o flag
        compile_patterns = [
            rf"\b\w+\s+.*-o\s+{re.escape(target_name)}\b",  # gcc ... -o target
            rf"\b\w+\s+.*-o\s*{re.escape(target_name)}\b",  # gcc ... -otarget
            rf"-o\s+{re.escape(target_name)}\b",  # -o target (after variable cleaning)
            rf"-o\s*{re.escape(target_name)}\b",  # -otarget (after variable cleaning)
        ]

        for pattern in compile_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return True

        # Direct file creation with redirection to target name (exact match)
        redirect_patterns = [
            rf">\s*{re.escape(target_name)}\s*$",  # > target_name at end
            rf">\s*{re.escape(target_name)}\s+",  # > target_name with space after
        ]

        for pattern in redirect_patterns:
            if re.search(pattern, command):
                return True

        # Touch command creating target
        if command.startswith("touch") and target_name in command:
            return True

        # Check for Make-style implicit compilation (common case)
        if target_name.endswith(".o"):
            # Check if compiling a .c file to create this .o file
            base_name = target_name[:-2]  # Remove .o
            if f"{base_name}.c" in command and "-c" in command:
                return True
            if f"{base_name}.cpp" in command and "-c" in command:
                return True
            if f"{base_name}.cc" in command and "-c" in command:
                return True

        return False
