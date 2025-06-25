"""Utility functions for line processing in Makefile formatting."""

import re
from typing import Any, Callable, Optional


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
        stripped = line.strip()

        if skip_empty and not stripped:
            return True

        if skip_comments and stripped.startswith("#"):
            return True

        return bool(skip_recipe and line.startswith(("\t", " ")))

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
    def is_inside_define_block(line_index: int, all_lines: list[str]) -> bool:
        """
        Check if the current line is inside a define block.

        Args:
            line_index: Index of the current line
            all_lines: All lines in the file

        Returns:
            True if the line is inside a define block
        """
        define_stack = []
        for i in range(line_index):
            check_line = all_lines[i].strip()
            if check_line.startswith("define "):
                define_stack.append(i)
            elif check_line == "endef" and define_stack:
                define_stack.pop()

        # If define_stack is not empty, we're inside a define block
        return bool(define_stack)

    @staticmethod
    def get_conditional_depth(line_index: int, all_lines: list[str]) -> int:
        """
        Get the current conditional block nesting depth at the given line.

        Args:
            line_index: Index of the current line
            all_lines: All lines in the file

        Returns:
            The nesting depth (0 = not in any conditional, 1+ = nested depth)
        """
        conditional_depth = 0
        for i in range(line_index):
            check_line = all_lines[i].strip()
            if check_line.startswith(("ifeq", "ifneq", "ifdef", "ifndef")):
                conditional_depth += 1
            elif check_line == "endif":
                conditional_depth = max(0, conditional_depth - 1)

        return conditional_depth

    @staticmethod
    def is_makefile_construct(line: str) -> bool:
        """
        Check if a line is a special Makefile construct that should be excluded
        from recipe line detection.

        Args:
            line: The line to check

        Returns:
            True if the line is a special Makefile construct
        """
        stripped = line.strip()
        return stripped.startswith(
            (
                "include",
                "-include",
                "ifeq",
                "ifneq",
                "ifdef",
                "ifndef",
                "define",
                "endef",
                ".PHONY",
                "export",
                "unexport",
                "vpath",
            )
        ) or stripped in ("else", "endif")

    @staticmethod
    def is_conditional_start(line: str) -> bool:
        """Check if line starts a conditional block."""
        return bool(re.match(r"^(ifeq|ifneq|ifdef|ifndef)\s*\(", line.strip()))

    @staticmethod
    def is_conditional_middle(line: str) -> bool:
        """Check if line is a conditional middle (else)."""
        return bool(re.match(r"^else(\s|$)", line.strip()))

    @staticmethod
    def is_conditional_end(line: str) -> bool:
        """Check if line ends a conditional block."""
        return line.strip() == "endif"

    @staticmethod
    def detect_define_block_indentation(lines: list[str], define_start: int) -> str:
        """
        Detect the indentation pattern within a define block.

        Args:
            lines: All lines in the file
            define_start: Index of the 'define' line

        Returns:
            The indentation string to use for content (e.g., '    ', '\t', '')
        """
        # Find the matching endef
        define_end = None
        for i in range(define_start + 1, len(lines)):
            if lines[i].strip() == "endef":
                define_end = i
                break

        if define_end is None:
            # No matching endef found, default to no indentation
            return ""

        # Analyze indentation patterns in the define block content
        indentations = []
        non_indented_count = 0

        for i in range(define_start + 1, define_end):
            line = lines[i]
            stripped = line.strip()

            # Skip empty lines and comments
            if not stripped or stripped.startswith("#"):
                continue

            # Calculate indentation
            indent_len = len(line) - len(line.lstrip())
            if indent_len > 0:
                indentations.append(line[:indent_len])
            else:
                non_indented_count += 1

        # If there are no content lines, return no indentation
        total_content_lines = len(indentations) + non_indented_count
        if total_content_lines == 0:
            return ""

        # If all lines have no indentation, keep it that way
        if len(indentations) == 0:
            return ""

        # If most lines have no indentation, don't add indentation
        if non_indented_count > len(indentations):
            return ""

        # Find the most common indentation pattern among indented lines
        from collections import Counter

        indent_counts = Counter(indentations)

        if indent_counts:
            # Use the most common indentation
            most_common_indent = indent_counts.most_common(1)[0][0]
            return most_common_indent

        # Fallback to no indentation
        return ""

    @staticmethod
    def normalize_define_block_indentation(
        lines: list[str], define_start: int
    ) -> tuple[list[str], bool]:
        """
        Normalize indentation within a define block to be consistent.

        Args:
            lines: All lines in the file
            define_start: Index of the 'define' line

        Returns:
            Tuple of (modified_lines, changed_flag)
        """
        # Find the matching endef
        define_end = None
        for i in range(define_start + 1, len(lines)):
            if lines[i].strip() == "endef":
                define_end = i
                break

        if define_end is None:
            return lines, False

        # Detect the target indentation pattern
        target_indent = LineUtils.detect_define_block_indentation(lines, define_start)

        # Apply consistent indentation to all content lines
        modified_lines = lines.copy()
        changed = False

        for i in range(define_start + 1, define_end):
            line = lines[i]
            stripped = line.strip()

            # Skip empty lines and comments
            if not stripped or stripped.startswith("#"):
                continue

            # Apply target indentation
            new_line = target_indent + stripped
            if new_line != line:
                modified_lines[i] = new_line
                changed = True

        return modified_lines, changed

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
        # First check if it's already indented
        if line.startswith(("\t", " ")) and line.strip():
            return LineUtils._is_recipe_line_helper(line, line_index, all_lines, set())

        # If not indented, check if it should be based on context
        return LineUtils._should_be_recipe_line(line, line_index, all_lines)

    @staticmethod
    def _is_recipe_line_helper(
        line: str, line_index: int, all_lines: list[str], visited: set
    ) -> bool:
        """Helper method to avoid infinite recursion."""
        if not (line.startswith(("\t", " ")) and line.strip()):
            return False

        # Don't treat makefile constructs as recipe lines even if indented
        if LineUtils.is_makefile_construct(line):
            return False

            # Don't treat variable assignments inside conditional blocks as recipe lines
        stripped = line.strip()
        if (
            LineUtils.is_variable_assignment(stripped)
            and LineUtils.get_conditional_depth(line_index, all_lines) > 0
        ):
            # If we're inside a conditional block, this variable assignment
            # should not be treated as a recipe line
            return False

        # Don't treat content inside define blocks as recipe lines
        if LineUtils.is_inside_define_block(line_index, all_lines):
            return False

        # Don't treat variable assignment continuation lines as recipe lines
        if LineUtils._is_variable_assignment_continuation(line_index, all_lines):
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

            # Skip empty lines and comments (comments should not break recipe context)
            if not prev_stripped or prev_stripped.startswith("#"):
                continue

            # If previous line is an indented line that ends with backslash,
            # this could be a recipe continuation line
            if prev_line.startswith(("\t", " ")) and prev_stripped.endswith("\\"):
                # Check if the previous line is a recipe line
                if LineUtils._is_recipe_line_helper(prev_line, i, all_lines, visited):
                    return True
                continue

            # If previous line is an indented recipe line, this is also a recipe line
            if prev_line.startswith(("\t", " ")):
                if LineUtils._is_recipe_line_helper(prev_line, i, all_lines, visited):
                    return True
                continue

            # If previous line is detected as a recipe line by the new logic, this is also a recipe line
            if LineUtils._should_be_recipe_line(prev_line, i, all_lines):
                return True

            # Check if this is a target line (contains : but not an assignment)
            if ":" in prev_stripped and not prev_stripped.startswith("#"):
                # Exclude variable assignments that contain colons (e.g., CC := gcc)
                if "=" in prev_stripped and prev_stripped.find(
                    "="
                ) < prev_stripped.find(":"):
                    return False
                # Exclude conditional blocks and function definitions
                # This is a target line (could be target:, target: prereq, or %.o: %.c)
                return not prev_stripped.startswith(
                    ("ifeq", "ifneq", "ifdef", "ifndef", "define")
                )

            # If we find a variable assignment without colon, this is NOT a recipe
            # BUT only if it's at the top level (not indented)
            if (
                "=" in prev_stripped
                and not prev_stripped.startswith(("ifeq", "ifneq", "ifdef", "ifndef"))
                and not prev_line.startswith(("\t", " "))
            ):
                # This is a top-level variable assignment
                return False

            # If we reach a non-indented, non-target line, default to False
            if not prev_line.startswith(("\t", " ")):
                break

        # Default to not a recipe if we can't determine context
        return False

    @staticmethod
    def _is_variable_assignment_continuation(
        line_index: int, all_lines: list[str]
    ) -> bool:
        """
        Check if this line is a continuation of a variable assignment.

        Args:
            line_index: Index of the current line
            all_lines: All lines in the file

        Returns:
            True if this line is part of a variable assignment continuation
        """
        # Look backward to find the start of the variable assignment
        for i in range(line_index - 1, -1, -1):
            prev_line = all_lines[i]
            prev_stripped = prev_line.strip()

            # Skip empty lines and comments (comments should not break variable assignment context)
            if not prev_stripped or prev_stripped.startswith("#"):
                continue

            # If we find another indented line that ends with backslash,
            # continue looking backward
            if prev_line.startswith((" ", "\t")) and prev_stripped.endswith("\\"):
                continue

            # If we find a non-indented line, check if it's a variable assignment
            if not prev_line.startswith((" ", "\t")):
                # Check if this is a variable assignment line that ends with backslash
                if (
                    "=" in prev_stripped
                    and prev_stripped.endswith("\\")
                    and not prev_stripped.startswith(
                        ("ifeq", "ifneq", "ifdef", "ifndef")
                    )
                ):
                    return True
                # If it's not a variable assignment, stop looking
                break

        return False

    @staticmethod
    def _should_be_recipe_line(
        line: str, line_index: int, all_lines: list[str]
    ) -> bool:
        """
        Check if a non-indented line should be a recipe line based on context.

        This handles cases where recipe lines are improperly formatted (not indented).
        This function is very conservative to avoid false positives.
        """
        # Skip empty lines and comments
        if not line.strip() or line.strip().startswith("#"):
            return False

        # Don't treat special makefile constructs as recipe lines
        if LineUtils.is_makefile_construct(line) or LineUtils.is_target_line(line):
            return False

        # If we're inside a define block, this is not a recipe line
        if LineUtils.is_inside_define_block(line_index, all_lines):
            return False

        # Check if we're inside a conditional block (but not followed by a target)
        conditional_depth = LineUtils.get_conditional_depth(line_index, all_lines)
        if conditional_depth > 0:
            # Find the last non-conditional line to see if it was a target
            last_non_conditional_line = None
            for i in range(line_index):
                check_line = all_lines[i].strip()
                if (
                    check_line
                    and not check_line.startswith(
                        ("ifeq", "ifneq", "ifdef", "ifndef", "else", "endif", "#")
                    )
                    and LineUtils.get_conditional_depth(i, all_lines) == 0
                ):
                    last_non_conditional_line = check_line

            # If we're inside a conditional block and the last non-conditional line
            # wasn't a target, then this is not a recipe
            if last_non_conditional_line is None or not LineUtils.is_target_line(
                last_non_conditional_line
            ):
                return False

        # Look backward to find context - either direct target or through recipe lines
        target_line_found = False
        for i in range(line_index - 1, -1, -1):
            prev_line = all_lines[i]
            prev_stripped = prev_line.strip()

            # Skip empty lines and comments (comments should not break context)
            if not prev_stripped or prev_stripped.startswith("#"):
                continue

            # If we find a target line, this could be a recipe
            if LineUtils.is_target_line(prev_line):
                target_line_found = True
                break

            # If we find another potential recipe line (with shell patterns), continue looking
            if any(
                pattern in prev_line for pattern in ["$(call ", "$@", "$<", "$^", "$$"]
            ):
                continue

            # If we find a non-target, non-recipe line, this is not a recipe
            if not prev_line.startswith(("\t", " ")):
                break

        # Only consider this a recipe line if:
        # 1. We found a target line in the context above
        # 2. AND this line looks like a shell command (not a typical makefile variable assignment)
        if target_line_found:
            # Additional heuristics to identify shell commands vs makefile variables:

            # If it contains shell-specific patterns, likely a shell command
            if any(pattern in line for pattern in ["$(call ", "$@", "$<", "$^", "$$"]):
                return True

            # If it's a simple variable assignment (no shell patterns),
            # it's likely a makefile variable, not a shell command
            if LineUtils.is_variable_assignment(line):
                # Check for shell variable patterns vs makefile variable patterns
                # Shell variables often have different naming conventions
                var_name = line.split("=")[0].strip()

                # Common makefile variable names (uppercase, with underscores)
                if var_name.isupper() and (
                    "_" in var_name
                    or var_name in ["CC", "CXX", "CFLAGS", "LDFLAGS", "AR", "AS"]
                ):
                    return False

                # Lowercase or mixed case more likely to be shell variables
                if not var_name.isupper():
                    return True

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

    @staticmethod
    def format_error_message(message: str, line_num: int, config: dict) -> str:
        """
        Format an error message according to GNU error format setting.

        Args:
            message: The error message content
            line_num: Line number where error occurred
            config: Configuration dictionary

        Returns:
            Formatted error message string
        """
        gnu_error_format = config.get("_global", {}).get("gnu_error_format", False)

        if gnu_error_format:
            return f"{line_num}: Error: {message}"
        else:
            return f"Line {line_num}: {message}"

    @staticmethod
    def create_define_block_processor() -> Callable[[str], bool]:
        """
        Create a define block processor for tracking define/endef blocks.

        Returns:
            A function that can be used to process lines and track define blocks
        """
        inside_define = False

        def process_line(line: str) -> bool:
            """
            Process a line and return whether we're inside a define block.

            Args:
                line: The line to process

            Returns:
                True if inside a define block after processing this line
            """
            nonlocal inside_define

            stripped = line.strip()

            if stripped.startswith("define "):
                inside_define = True
            elif stripped == "endef":
                inside_define = False

            return inside_define

        return process_line

    @staticmethod
    def process_lines_with_standard_skipping(
        lines: list[str],
        line_processor: Callable[[str, int], tuple[str, bool]],
        skip_recipe: bool = True,
        skip_comments: bool = True,
        skip_empty: bool = True,
        skip_define_blocks: bool = False,
    ) -> tuple[list[str], bool]:
        """
        Process lines with standard skipping logic used across multiple rules.

        Args:
            lines: Lines to process
            line_processor: Function that takes (line, line_index) and returns (new_line, changed)
            skip_recipe: Whether to skip recipe lines
            skip_comments: Whether to skip comment lines
            skip_empty: Whether to skip empty lines
            skip_define_blocks: Whether to skip content inside define blocks

        Returns:
            Tuple of (processed_lines, changed_flag)
        """
        formatted_lines = []
        changed = False

        # Optional define block processor
        define_processor = (
            LineUtils.create_define_block_processor() if skip_define_blocks else None
        )

        for i, line in enumerate(lines):
            # Check if we should skip this line
            should_skip = LineUtils.should_skip_line(
                line,
                skip_recipe=skip_recipe,
                skip_comments=skip_comments,
                skip_empty=skip_empty,
            )

            # Check define block status if needed
            if define_processor and not should_skip:
                inside_define = define_processor(line)
                if inside_define and skip_define_blocks:
                    should_skip = True

            if should_skip:
                formatted_lines.append(line)
                continue

            # Process the line
            new_line, line_changed = line_processor(line, i)
            if line_changed:
                changed = True
            formatted_lines.append(new_line)

        return formatted_lines, changed

    @staticmethod
    def is_template_placeholder_target(target_name: str) -> bool:
        """
        Returns True if the target is a template placeholder like $(1), $(2), $(VAR), ${1}, ${VAR}, etc.
        This includes both numeric and named variable references in either $() or ${} format.
        """
        # Match $(number), $(NAME), ${number}, ${NAME}
        return bool(re.fullmatch(r"\$[({][^})]+[})]", target_name))


class ShellUtils:
    """Utilities for processing shell commands within Makefile recipes."""

    # Keywords for shell control structures
    START_KEYWORDS = ("if", "for", "while", "case", "until")
    CONTINUATION_KEYWORDS = ("elif", "else")
    END_KEYWORDS = ("fi", "done", "esac")
    END_KEYWORDS_WITH_SEMICOLON = ("fi;", "done;", "esac;")

    # All keywords combined, for comprehensive checks
    ALL_KEYWORDS = (
        START_KEYWORDS
        + CONTINUATION_KEYWORDS
        + END_KEYWORDS
        + END_KEYWORDS_WITH_SEMICOLON
    )

    # Simple keywords for checking if a line contains any shell control structures
    SIMPLE_KEYWORDS = START_KEYWORDS + CONTINUATION_KEYWORDS + ("do", "then")

    # Common shell operators
    OPERATORS = ("&&", "||", ";", "|", ">", "<", ">>", "<<", "$(", "`")

    @staticmethod
    def is_shell_control_start(line: str) -> bool:
        """Check if a line starts a shell control structure."""
        # Strip make command prefixes (@, -, +)
        stripped = line.lstrip("@-+ ")

        # More precise matching than just startswith, to avoid matching substrings
        control_patterns = [
            r"^if\s+\[",
            r"^for\s+",
            r"^while\s+",
            r"^case\s+",
            r"^until\s+",
            r"^{\s*$",
        ]
        return any(re.match(pattern, stripped) for pattern in control_patterns)

    @staticmethod
    def is_shell_control_end(line: str) -> bool:
        """Check if a line ends a shell control structure."""
        stripped = line.lstrip("@-+ \t").rstrip()
        return any(stripped.startswith(kw) for kw in ShellUtils.END_KEYWORDS) or any(
            stripped.endswith(kw) for kw in ShellUtils.END_KEYWORDS_WITH_SEMICOLON
        )

    @staticmethod
    def contains_shell_operators(line: str) -> bool:
        """Check if content contains shell operators that suggest deliberate structure."""
        return any(op in line for op in ShellUtils.OPERATORS)


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

        Uses enhanced logic that respects comment blocks and variable continuations:
        - Treats contiguous comments as file header
        - Inserts .PHONY after first blank line following header comments
        - Preserves section comments that come after variables/blank lines
        - Properly handles multiline variable assignments

        Args:
            lines: List of lines from the Makefile

        Returns:
            Index where .PHONY should be inserted
        """
        in_header_comments = True
        last_comment_index = -1
        in_variable_block = False

        for i, line in enumerate(lines):
            stripped = line.strip()

            if not stripped:  # Empty line
                if in_header_comments and last_comment_index >= 0:
                    # Found blank line after header comments - insert here
                    return i
                # If we were in a variable block, this marks the end
                in_variable_block = False
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
                in_variable_block = True
                continue

            elif in_variable_block and stripped.endswith("\\"):
                # We're in a variable continuation
                continue

            elif in_variable_block and i > 0 and lines[i - 1].strip().endswith("\\"):
                # This line is part of a variable continuation
                continue

            else:
                # First rule/target found or end of variable block
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
    def is_target_phony(
        target_name: str, recipe_lines: list[str], all_lines: Optional[list[str]] = None
    ) -> bool:
        """
        Determine if a target is phony by analyzing its recipe.

        Args:
            target_name: Name of the target
            recipe_lines: List of recipe command lines
            all_lines: All lines in the Makefile for context analysis

        Returns:
            True if the target is likely phony
        """
        if not recipe_lines:
            # No recipe could mean:
            # 1. Phony target (like .PHONY: help)
            # 2. Dependency-only rule (like header.h: source.c)
            #
            # File targets (especially .h, .o, .c, .cpp, etc.) with no recipe
            # are typically dependency-only rules, not phony targets
            # Otherwise assume it's phony (like help, clean, etc.)
            return not PhonyAnalyzer._looks_like_file_target(target_name, all_lines)

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
    def _looks_like_file_target(
        target_name: str, all_lines: Optional[list[str]] = None
    ) -> bool:
        """
        Check if a target name looks like a file target using dynamic analysis.

        Args:
            target_name: Name of the target
            all_lines: All lines in the Makefile for context analysis

        Returns:
            True if the target name looks like a file target
        """
        # If we have context, use dynamic analysis
        if all_lines:
            return PhonyAnalyzer._analyze_file_patterns_dynamically(
                target_name, all_lines
            )

        # Fallback to basic heuristics if no context available
        return PhonyAnalyzer._basic_file_target_heuristics(target_name)

    @staticmethod
    def _analyze_file_patterns_dynamically(
        target_name: str, all_lines: list[str]
    ) -> bool:
        """
        Dynamically analyze the Makefile to determine if target looks like a file.

        Args:
            target_name: Name of the target to analyze
            all_lines: All lines in the Makefile

        Returns:
            True if target appears to be a file based on Makefile patterns
        """
        # First check if it looks like an action target by name
        if PhonyAnalyzer._looks_like_action_target(target_name):
            return False

        # Extract all extensions used in the Makefile
        discovered_extensions = PhonyAnalyzer._discover_file_extensions(all_lines)

        # Check if target has an extension that appears elsewhere in the Makefile
        if "." in target_name:
            ext = "." + target_name.split(".")[-1].lower()
            if ext in discovered_extensions:
                return True

        # Check if target appears in file-related contexts
        if PhonyAnalyzer._appears_in_file_contexts(target_name, all_lines):
            return True

        # Check if target follows naming patterns of other file targets
        if PhonyAnalyzer._matches_file_naming_patterns(target_name, all_lines):
            return True

        # Check if target's recipe suggests it's a file target
        return PhonyAnalyzer._recipe_suggests_file_target(target_name, all_lines)

    @staticmethod
    def _recipe_suggests_file_target(target_name: str, all_lines: list[str]) -> bool:
        """
        Analyze target's recipe to determine if it creates a file.
        Uses structural analysis, not semantic command knowledge.

        Args:
            target_name: Name of the target
            all_lines: All lines in the Makefile

        Returns:
            True if recipe suggests target creates a file
        """
        # Find the target definition and its recipe
        target_pattern = re.compile(rf"^{re.escape(target_name)}:")

        for i, line in enumerate(all_lines):
            if target_pattern.match(line.strip()):
                # Get recipe lines for this target
                recipe_lines = []
                for j in range(i + 1, len(all_lines)):
                    recipe_line = all_lines[j]
                    if recipe_line.startswith("\t"):
                        recipe_lines.append(recipe_line.strip())
                    elif recipe_line.strip():  # Non-empty, non-recipe line
                        break

                # If no recipe, check if target has file-like characteristics
                if not recipe_lines:
                    # Targets with extensions are likely files even without recipes
                    if "." in target_name and not target_name.startswith("."):
                        return True
                    # Targets with paths are likely files
                    return "/" in target_name or "\\" in target_name

                # Analyze recipe for file creation patterns
                for recipe in recipe_lines:
                    cleaned_recipe = PhonyAnalyzer._clean_command_for_analysis(recipe)

                    # Check if command creates target file using structural patterns
                    if PhonyAnalyzer._command_creates_target_file(
                        cleaned_recipe, target_name
                    ):
                        return True

                    # Output redirection patterns (structural, not command-specific)
                    if any(op in recipe for op in [" > ", " >> ", " 2> "]):
                        return True

                    # Structural indicators of file creation (not semantic)
                    # Look for patterns that suggest file output
                    if any(
                        pattern in recipe
                        for pattern in [
                            "$@",  # Make automatic variable for target
                            "$< $@",  # Common Make pattern: input to output
                        ]
                    ):
                        return True

                break

        return False

    @staticmethod
    def _discover_file_extensions(all_lines: list[str]) -> set[str]:
        """
        Discover file extensions used throughout the Makefile.
        Completely dynamic - no hardcoded exclusions.

        Args:
            all_lines: All lines in the Makefile

        Returns:
            Set of discovered file extensions
        """
        extensions = set()

        for line in all_lines:
            # Skip comments and empty lines
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Find all words that look like filenames (contain dots)
            import re

            # Match words with extensions (word.ext pattern)
            filename_pattern = r"\b\w+\.\w+\b"
            matches = re.findall(filename_pattern, stripped)

            for match in matches:
                # Extract extension
                if "." in match:
                    ext = "." + match.split(".")[-1].lower()
                    # No hardcoded exclusions - include all discovered extensions
                    extensions.add(ext)

        return extensions

    @staticmethod
    def _appears_in_file_contexts(target_name: str, all_lines: list[str]) -> bool:
        """
        Check if target appears in file-related contexts in the Makefile.
        Completely dynamic - no hardcoded command patterns.

        Args:
            target_name: Name of the target
            all_lines: All lines in the Makefile

        Returns:
            True if target appears in file contexts
        """
        # Only structural patterns, no hardcoded commands
        file_context_patterns = [
            r"\$\(wildcard.*" + re.escape(target_name),  # $(wildcard *.ext)
            r"include\s+.*" + re.escape(target_name),  # include target
            r"-o\s+" + re.escape(target_name),  # -o target
            r">\s*" + re.escape(target_name),  # > target
            r"rm\s+.*" + re.escape(target_name),  # rm target (file being removed)
            r"rm\s+-[rf]*\s+.*" + re.escape(target_name),  # rm -f target
        ]

        for line in all_lines:
            for pattern in file_context_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    return True

        return False

    @staticmethod
    def _matches_file_naming_patterns(target_name: str, all_lines: list[str]) -> bool:
        """
        Check if target follows naming patterns of other file targets.

        Args:
            target_name: Name of the target
            all_lines: All lines in the Makefile

        Returns:
            True if target matches file naming patterns
        """
        # Extract all target names from the Makefile
        target_pattern = re.compile(r"^([^:=]+):(?!:)")
        all_targets = []

        for line in all_lines:
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "\t")):
                continue

            match = target_pattern.match(stripped)
            if match:
                target_list = match.group(1).strip()
                targets = [t.strip() for t in target_list.split() if t.strip()]
                all_targets.extend(targets)

        # Analyze naming patterns
        return PhonyAnalyzer._has_similar_naming_pattern(target_name, all_targets)

    @staticmethod
    def _has_similar_naming_pattern(target_name: str, all_targets: list[str]) -> bool:
        """
        Check if target has similar naming pattern to other targets.
        Completely dynamic - no hardcoded patterns.

        Args:
            target_name: Name of the target to check
            all_targets: List of all targets in the Makefile

        Returns:
            True if target has similar pattern to file targets
        """
        # If target has extension, check if other targets have same extension
        if "." in target_name:
            target_ext = "." + target_name.split(".")[-1].lower()
            similar_targets = [t for t in all_targets if t.endswith(target_ext)]

            # If we find multiple targets with same extension, likely file targets
            if len(similar_targets) > 1:
                return True

        # Check for path-like patterns (contains slashes)
        return "/" in target_name or "\\" in target_name

    @staticmethod
    def _basic_file_target_heuristics(target_name: str) -> bool:
        """
        Basic heuristics for file target detection when no context is available.
        Conservative approach using only structural indicators.

        Args:
            target_name: Name of the target

        Returns:
            True if target looks like a file based on basic heuristics
        """
        # If it looks like an action target, it's not a file target
        if PhonyAnalyzer._looks_like_action_target(target_name):
            return False

        # Has file extension (most reliable indicator)
        if "." in target_name and not target_name.startswith("."):
            return True

        # Has path separators (likely a file path)
        return "/" in target_name or "\\" in target_name

    @staticmethod
    def _looks_like_action_target(target_name: str) -> bool:
        """
        Check if target looks like an action target.
        Completely dynamic - no hardcoded patterns at all.

        Args:
            target_name: Name of the target

        Returns:
            Always False - let recipe analysis determine everything
        """
        # No hardcoded patterns whatsoever
        # All phony detection is now based purely on recipe analysis
        return False

    @staticmethod
    def detect_phony_targets_excluding_conditionals(lines: list[str]) -> set[str]:
        """Detect phony targets excluding those inside conditional blocks."""
        target_pattern = re.compile(r"^([^:=]+):(:?)\s*(.*)$")
        conditional_tracker = ConditionalTracker()
        phony_targets = set()

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Skip empty lines, comments, and lines that start with tab (recipes)
            if not stripped or stripped.startswith("#") or line.startswith("\t"):
                continue

            # Track conditional context
            current_context = conditional_tracker.process_line(line, i)

            # Skip targets inside conditional blocks
            if current_context:
                continue

            # Skip variable assignments (=, :=, +=, ?=)
            if "=" in stripped and (
                ":" not in stripped
                or ":=" in stripped
                or "+=" in stripped
                or "?=" in stripped
            ):
                continue

            # Skip export variable assignments (e.g., "export VAR:=value")
            if stripped.startswith("export ") and "=" in stripped:
                continue

            # Skip $(info) function calls and other function calls
            if stripped.startswith("$(") and stripped.endswith(")"):
                continue

            # Skip lines that are clearly not target definitions
            # (e.g., lines that start with @ or contain function calls)
            if stripped.startswith("@") or "$(" in stripped:
                continue

            # Check for target definitions
            match = target_pattern.match(stripped)
            if match:
                target_list = match.group(1).strip()
                is_double_colon = match.group(2) == ":"
                target_body = match.group(3).strip()

                # Handle multiple targets on one line
                target_names = [t.strip() for t in target_list.split() if t.strip()]

                # Skip special targets that can be duplicated
                allowed_duplicates = {
                    ".PHONY",
                    ".SUFFIXES",
                    ".DEFAULT",
                    ".PRECIOUS",
                    ".INTERMEDIATE",
                    ".SECONDARY",
                    ".DELETE_ON_ERROR",
                    ".IGNORE",
                    ".LOW_RESOLUTION_TIME",
                    ".SILENT",
                    ".EXPORT_ALL_VARIABLES",
                    ".NOTPARALLEL",
                    ".ONESHELL",
                    ".POSIX",
                }

                # Double-colon rules are allowed to have multiple definitions
                if is_double_colon:
                    continue

                # Check if this is a static pattern rule (contains %)
                if any("%" in name for name in target_names):
                    continue

                # Check if this is a target-specific variable assignment
                if re.match(r"^\s*[A-Z_][A-Z0-9_]*\s*[+:?]?=", target_body):
                    continue

                # Get recipe lines for this target
                recipe_lines = PhonyAnalyzer._get_target_recipe_lines(lines, i)

                # Process each target name
                for target_name in target_names:
                    if target_name in allowed_duplicates:
                        continue

                    # Skip targets that contain quotes or special characters that shouldn't be in target names
                    if (
                        '"' in target_name
                        or "'" in target_name
                        or "@" in target_name
                        or "$" in target_name
                        or "(" in target_name
                        or ")" in target_name
                    ):
                        continue

                    # Analyze if target is phony
                    if PhonyAnalyzer.is_target_phony(target_name, recipe_lines, lines):
                        phony_targets.add(target_name)

        return phony_targets

    @staticmethod
    def _get_target_recipe_lines(lines: list[str], target_index: int) -> list[str]:
        """Get the recipe lines for a target starting at target_index."""
        recipe_lines = []

        # Start from the line after the target
        for i in range(target_index + 1, len(lines)):
            line = lines[i]

            # Stop at empty line or next target/directive
            if not line.strip():
                continue

            # Recipe lines start with tab
            if line.startswith("\t"):
                recipe_lines.append(line.strip())
            else:
                # Hit a non-recipe line, stop collecting
                break

        return recipe_lines

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
        Uses structural patterns, not semantic command knowledge.

        Args:
            command: Cleaned command line
            target_name: Name of the target

        Returns:
            True if the command creates a file with the target name
        """
        # Check for -o flag patterns (structural, not command-specific)
        output_flag_patterns = [
            rf"-o\s+{re.escape(target_name)}\b",  # -o target
            rf"-o\s*{re.escape(target_name)}\b",  # -otarget
        ]

        for pattern in output_flag_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return True

        # Check for Make automatic variables that represent the target
        # $@ is the target name in Make
        if "-o $@" in command or "-o$@" in command:
            return True

        # Direct file creation with redirection to target name (exact match)
        redirect_patterns = [
            rf">\s*{re.escape(target_name)}\s*$",  # > target_name at end
            rf">\s*{re.escape(target_name)}\s+",  # > target_name with space after
        ]

        for pattern in redirect_patterns:
            if re.search(pattern, command):
                return True

        # Make automatic variable patterns - very common in Makefiles
        # Pattern: command $< $@ (input to output)
        if "$< $@" in command:
            return True

        # Pattern: command $^ $@ (all prerequisites to output)
        if "$^ $@" in command:
            return True

        # Pattern: command ... $@ (any command ending with target)
        if command.strip().endswith(" $@"):
            return True

        # Structural patterns for common file creation (not semantic)
        # These are based on command structure, not specific command names

        # Pattern: any command that outputs to the target name
        if f" {target_name}" in command and any(
            indicator in command for indicator in ["-o", ">", ">"]
        ):
            return True

        # Pattern: commands that explicitly mention creating the target
        if target_name in command and any(
            word in command.lower() for word in ["create", "generate", "build", "make"]
        ):
            return True

        # Structural pattern: compilation to object files
        # If target is .o file and command has -c flag, it's likely compilation
        if target_name.endswith(".o") and "-c" in command:
            # Check if source file with same base name is mentioned
            base_name = target_name[:-2]  # Remove .o
            # Look for any file with the same base name (structural pattern)
            if base_name in command and "." in command:
                return True

        # Structural pattern: general file transformation
        # If target has extension and command mentions a file with same base name
        if "." in target_name and not target_name.startswith("."):
            base_name = target_name.rsplit(".", 1)[0]  # Remove extension
            if base_name in command and base_name != target_name:
                return True

        return False
