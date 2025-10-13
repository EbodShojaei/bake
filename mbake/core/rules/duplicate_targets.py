"""Rule for detecting duplicate targets in Makefiles."""

import re
from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.line_utils import ConditionalTracker


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
        seen_targets: dict[str, tuple[int, str, tuple]] = (
            {}
        )  # Added conditional context
        errors = []

        # Track conditional context
        conditional_tracker = ConditionalTracker()

        # Special targets that can be duplicated
        declarative_targets = {".PHONY", ".SUFFIXES"}

        for i, line in enumerate(lines):
            stripped = line.strip()
            line_num = i + 1

            # Get conditional context for this line
            conditional_context = conditional_tracker.process_line(line, i)

            # Skip empty lines, comments, and recipes (must check original line for tab)
            if not stripped or stripped.startswith("#") or line.startswith("\t"):
                continue

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
                if target_name in declarative_targets:
                    continue

                # Suppress duplicate errors for template placeholder targets like $(1), $(2)
                if self._is_template_placeholder(target_name):
                    continue

                # Double-colon rules are allowed to have multiple definitions
                if is_double_colon:
                    continue

                # Check for previous definition
                if target_name in seen_targets:
                    prev_line, prev_body, prev_context = seen_targets[target_name]

                    # Check if targets are in mutually exclusive conditional branches
                    if ConditionalTracker.are_mutually_exclusive(
                        prev_context, conditional_context
                    ):
                        # Targets in mutually exclusive branches are not duplicates
                        seen_targets[target_name] = (
                            line_num,
                            target_body,
                            conditional_context,
                        )
                        continue

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
                    error_msg = self._format_error_message(message, line_num, config)
                    errors.append(error_msg)
                # Record target with conditional context
                seen_targets[target_name] = (line_num, target_body, conditional_context)

        return errors

    def _is_template_placeholder(self, target_name: str) -> bool:
        """Check if target is a template placeholder like $(1), $(2), $(VAR), etc."""
        return bool(re.fullmatch(r"\$[({][^})]+[})]", target_name))

    def _format_error_message(self, message: str, line_num: int, config: dict) -> str:
        """Format error message according to configuration."""
        gnu_error_format = config.get("gnu_error_format", False)

        if gnu_error_format:
            return f"Makefile:{line_num}: Error: {message}"
        else:
            return f"Line {line_num}: {message}"
