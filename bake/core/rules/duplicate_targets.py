"""Rule for detecting duplicate targets in Makefiles."""

import re
from typing import Any

from bake.plugins.base import FormatResult, FormatterPlugin
from bake.utils.line_utils import ConditionalTracker, LineUtils


class DuplicateTargetRule(FormatterPlugin):
    """Detects duplicate target definitions."""

    def __init__(self) -> None:
        super().__init__("duplicate_targets", priority=5)

    def format(
        self,
        lines: list[str],
        config: dict[str, Any],
        check_mode: bool = False,
        **context: Any,
    ) -> FormatResult:
        """Format lines by detecting duplicate targets."""
        errors = self._detect_duplicates(lines, config)
        # This rule doesn't modify content, just reports errors
        return FormatResult(
            lines=lines, changed=False, errors=errors, warnings=[], check_messages=[]
        )

    def _detect_duplicates(self, lines: list[str], config: dict[str, Any]) -> list[str]:
        """Detect duplicate target definitions."""
        target_pattern = re.compile(r"^([^:\s]+):(:?)\s*(.*)$")
        seen_targets: dict[str, tuple[int, tuple, str]] = {}
        conditional_tracker = ConditionalTracker()
        errors = []

        for i, line in enumerate(lines):
            stripped = line.strip()
            line_num = i + 1

            # Skip empty lines, comments, and recipes
            if not stripped or stripped.startswith("#") or stripped.startswith("\t"):
                continue

            # Track conditional context
            current_context = conditional_tracker.process_line(line, i)

            # Check for target definitions
            match = target_pattern.match(stripped)
            if match:
                target_name = match.group(1).strip()
                is_double_colon = match.group(2) == ":"
                target_body = match.group(3).strip()

                # Skip comment-only targets (documentation targets)
                # These are lines like "target: ## Comment" that are documentation only
                if target_body.startswith("##"):
                    continue

                # Skip special targets that can be duplicated
                # These targets should not be tracked at all, as they can legitimately appear multiple times
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
                if target_name in allowed_duplicates:
                    continue

                # Suppress duplicate errors for template placeholder targets like $(1), $(2)
                if LineUtils.is_template_placeholder_target(target_name):
                    continue

                # Double-colon rules are allowed to have multiple definitions
                if is_double_colon:
                    continue

                # Check for previous definition
                if target_name in seen_targets:
                    prev_line, prev_context, prev_body = seen_targets[target_name]

                    # Only report as duplicate if not in mutually exclusive contexts
                    if not ConditionalTracker.are_mutually_exclusive(
                        current_context, prev_context
                    ):
                        # Check if this is a static pattern rule (contains %)
                        # Static pattern rules can coexist with other rules for the same target
                        is_static_pattern = "%" in target_body
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

                        # Format error message
                        message = f"Duplicate target '{target_name}' defined at lines {prev_line} and {line_num}. Second definition will override the first."
                        error_msg = LineUtils.format_error_message(
                            message, line_num, config
                        )

                        errors.append(error_msg)
                else:
                    # Store target with its line number, conditional context, and body
                    seen_targets[target_name] = (line_num, current_context, target_body)

        return errors
