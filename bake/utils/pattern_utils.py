"""Utility functions for pattern matching in Makefile formatting."""

import re
from typing import Optional


class PatternUtils:
    """Common pattern matching utilities used across formatting rules."""

    # Common regex patterns
    ASSIGNMENT_PATTERNS = {
        "spaced": [
            (r"^([^:+=?!]*?)\s*:=\s*(.*)", r"\1 := \2"),
            (r"^([^:+=?!]*?)\s*\+=\s*(.*)", r"\1 += \2"),
            (r"^([^:+=?!]*?)\s*\?=\s*(.*)", r"\1 ?= \2"),
            (r"^([^:+=?!]*?)\s*=\s*(.*)", r"\1 = \2"),
        ],
        "compact": [
            (r"^([^:+=?!]*?)\s*:=\s*(.*)", r"\1:=\2"),
            (r"^([^:+=?!]*?)\s*\+=\s*(.*)", r"\1+=\2"),
            (r"^([^:+=?!]*?)\s*\?=\s*(.*)", r"\1?=\2"),
            (r"^([^:+=?!]*?)\s*=\s*(.*)", r"\1=\2"),
        ],
    }

    @staticmethod
    def contains_assignment(line: str) -> bool:
        """
        Check if line contains an assignment operator.

        Args:
            line: The line to check

        Returns:
            True if line contains assignment operators
        """
        # Check for assignment operators, but exclude shell comparison operators like !=, <=, >=
        return bool(
            re.search(r"[^:+=?!<>]*[=]", line) and not re.search(r"[!<>=]=", line)
        )

    @staticmethod
    def apply_assignment_spacing(line: str, use_spaces: bool = True) -> str:
        """
        Apply consistent spacing around assignment operators.

        Args:
            line: The line to format
            use_spaces: Whether to use spaces around operators

        Returns:
            The formatted line
        """
        patterns = PatternUtils.ASSIGNMENT_PATTERNS[
            "spaced" if use_spaces else "compact"
        ]

        for pattern, replacement in patterns:
            new_line = re.sub(pattern, replacement, line)
            if new_line != line:
                return new_line

        return line

    @staticmethod
    def format_target_colon(
        line: str, space_before: bool = False, space_after: bool = True
    ) -> Optional[str]:
        """
        Format colon spacing in target definitions.

        Args:
            line: The line to format
            space_before: Whether to add space before colon
            space_after: Whether to add space after colon

        Returns:
            Formatted line or None if no changes needed
        """
        # Handle target colons (but not in conditionals, functions, assignments, or pattern rules)
        if (
            ":" in line
            and not line.strip().startswith(("if", "else", "endif", "define", "endef"))
            and not re.search(r"[=]", line)  # Skip if contains assignment operators
            and not re.search(r"%.*:", line)  # Skip pattern rules
            and line.count(":") == 1
        ):  # Only single colon lines
            # Match target: dependencies pattern
            colon_match = re.match(r"^([^:]+):(.*)$", line)
            if colon_match:
                target_part = colon_match.group(1)
                deps_part = colon_match.group(2)

                # Format target part (remove trailing spaces)
                if space_before:
                    target_part = target_part.rstrip() + " "
                else:
                    target_part = target_part.rstrip()

                # Format dependencies part
                if space_after:
                    if deps_part.strip():
                        # Normalize multiple spaces between dependencies to single spaces
                        deps_part = " " + " ".join(deps_part.split())
                    else:
                        deps_part = ""
                else:
                    # Normalize multiple spaces between dependencies to single spaces
                    deps_part = " ".join(deps_part.split()) if deps_part.strip() else ""

                new_line = target_part + ":" + deps_part
                if new_line != line:
                    return new_line

        return None

    @staticmethod
    def format_pattern_rule(line: str, space_after_colon: bool = True) -> Optional[str]:
        """
        Format spacing in pattern rules.

        Args:
            line: The line to format
            space_after_colon: Whether to add space after colon

        Returns:
            Formatted line or None if no changes needed
        """
        # Handle static pattern rules with two colons specially
        if re.search(r".*:\s*%.*\s*:\s*", line):
            # Static pattern rule: targets: pattern: prerequisites
            static_pattern_match = re.match(r"^([^:]+):\s*([^:]+)\s*:\s*(.*)$", line)
            if static_pattern_match:
                targets_part = static_pattern_match.group(1).rstrip()
                pattern_part = static_pattern_match.group(2).strip()
                prereqs_part = static_pattern_match.group(3).strip()

                new_line = f"{targets_part}: {pattern_part}: {prereqs_part}"
                if new_line != line:
                    return new_line

        # Handle simple pattern rules (%.o: %.c)
        elif re.search(r"%.*:", line) and line.count(":") == 1:
            # Simple pattern rule
            pattern_match = re.match(r"^([^:]+):(.*)$", line)
            if pattern_match:
                pattern_part = pattern_match.group(1).rstrip()
                prereqs_part = pattern_match.group(2)

                if space_after_colon:
                    if prereqs_part.startswith(" "):
                        prereqs_part = " " + prereqs_part.lstrip()
                    elif prereqs_part:
                        prereqs_part = " " + prereqs_part
                else:
                    prereqs_part = prereqs_part.lstrip()

                new_line = pattern_part + ":" + prereqs_part
                if new_line != line:
                    return new_line

        return None

    @staticmethod
    def is_conditional_directive(line: str) -> bool:
        """
        Check if line is a conditional directive.

        Args:
            line: The line to check

        Returns:
            True if this is a conditional directive
        """
        stripped = line.strip()
        return stripped.startswith(
            ("ifeq", "ifneq", "ifdef", "ifndef", "else", "endif")
        )

    @staticmethod
    def get_conditional_indent_level(line: str) -> int:
        """
        Get the appropriate indentation level for conditional directives.

        Args:
            line: The conditional directive line

        Returns:
            Number of spaces for indentation
        """
        stripped = line.strip()

        if stripped.startswith(("ifeq", "ifneq", "ifdef", "ifndef")):
            return 0  # Top-level conditionals
        elif stripped.startswith("else") or stripped.startswith("endif"):
            return 0  # Same level as opening conditional
        else:
            return 2  # Content inside conditionals
