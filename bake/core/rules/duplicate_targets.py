"""Duplicate target detection rule for Makefiles."""

import re
from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin


class DuplicateTargetRule(FormatterPlugin):
    """Detects and warns about duplicate target definitions."""

    def __init__(self) -> None:
        super().__init__("duplicate_targets", priority=60)

    def format(self, lines: list[str], config: dict[str, Any]) -> FormatResult:
        """Detect duplicate target definitions and warn."""
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        # Track targets we've seen
        seen_targets: dict[str, dict[str, Any]] = {}
        target_pattern = re.compile(
            r"^([^:\s]+):(:?)\s*(.*)$"
        )  # Capture single vs double colon

        # Special targets that can appear multiple times
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

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Skip empty lines, comments, and lines that start with tab (recipes)
            if not stripped or stripped.startswith("#") or stripped.startswith("\t"):
                continue

            # Skip variable assignments and conditionals
            if ("=" in stripped and ":" not in stripped) or stripped.startswith(
                ("ifeq", "ifneq", "ifdef", "ifndef", "else", "endif")
            ):
                continue

            # Check for target definitions
            match = target_pattern.match(stripped)
            if match:
                target_name = match.group(1).strip()
                is_double_colon = (
                    match.group(2) == ":"
                )  # Check if it's a double-colon rule
                target_body = match.group(3).strip()

                # Skip special targets that can be duplicated
                if target_name in allowed_duplicates:
                    continue

                # Double-colon rules are allowed to have multiple definitions
                if is_double_colon:
                    continue

                # Check if this is a static pattern rule (contains %)
                # Static pattern rules can coexist with other rules for the same target
                is_static_pattern = "%" in target_body

                # Check for duplicate
                if target_name in seen_targets:
                    prev_line_num: int = seen_targets[target_name]["line"]
                    prev_body: str = seen_targets[target_name]["body"]
                    prev_is_static_pattern = "%" in prev_body

                    # If either rule is a static pattern rule, they can coexist
                    if is_static_pattern or prev_is_static_pattern:
                        continue

                    # Check if this is a target-specific variable assignment
                    # Pattern: "target: VARIABLE += value" or "target: VARIABLE = value"
                    is_var_assignment = bool(
                        re.match(r"^\s*[A-Z_][A-Z0-9_]*\s*[+:?]?=", target_body)
                    )
                    prev_is_var_assignment = bool(
                        re.match(r"^\s*[A-Z_][A-Z0-9_]*\s*[+:?]?=", prev_body)
                    )

                    if is_var_assignment or prev_is_var_assignment:
                        # This looks like target-specific variable assignments, which are valid
                        continue

                    # Check if this is a target with only a comment (help target pattern)
                    if target_body.startswith("##"):
                        # This looks like a help comment for an existing target
                        warnings.append(
                            f"Target '{target_name}' defined at line {prev_line_num + 1} "
                            f"has a duplicate help comment at line {i + 1}. "
                            f"Consider combining: '{target_name}: {prev_body} {target_body}'"
                        )
                    elif prev_body.startswith("##"):
                        # Previous was just a comment, this might be the real target
                        warnings.append(
                            f"Target '{target_name}' has help comment at line {prev_line_num + 1} "
                            f"and definition at line {i + 1}. "
                            f"Consider combining: '{target_name}: {target_body} {prev_body}'"
                        )
                    else:
                        # Both are real target definitions - this is an error
                        errors.append(
                            f"Duplicate target '{target_name}' defined at lines {prev_line_num + 1} and {i + 1}. "
                            f"Second definition will override the first."
                        )
                else:
                    # Record this target
                    seen_targets[target_name] = {
                        "line": i,
                        "body": target_body,
                    }

        return FormatResult(
            lines=lines, changed=changed, errors=errors, warnings=warnings
        )
