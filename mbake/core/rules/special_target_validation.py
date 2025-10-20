"""Special target validation and formatting rule for Makefiles."""

import re
from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin


class SpecialTargetValidationRule(FormatterPlugin):
    """Validates special target usage and syntax."""

    def __init__(self) -> None:
        super().__init__("special_target_validation", priority=10)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Validate special target declarations."""
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        special_targets = self._get_special_targets()
        target_usage = self._analyze_special_target_usage(lines)

        for _i, line in enumerate(lines):
            stripped = line.strip()

            if stripped.startswith(".") and ":" in stripped:
                new_line, line_errors, line_warnings = self._validate_special_target(
                    line, special_targets, target_usage
                )
                if new_line != line:
                    changed = True
                errors.extend(line_errors)
                warnings.extend(line_warnings)
                formatted_lines.append(new_line)
            else:
                formatted_lines.append(line)

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=[],
        )

    def _get_special_targets(self) -> dict[str, dict[str, Any]]:
        """Get information about special targets."""
        return {
            ".PHONY": {"duplicatable": True, "requires_prereqs": True},
            ".SUFFIXES": {"duplicatable": True, "requires_prereqs": False},
            ".DEFAULT": {"duplicatable": False, "requires_prereqs": False},
            ".PRECIOUS": {"duplicatable": True, "requires_prereqs": True},
            ".INTERMEDIATE": {"duplicatable": True, "requires_prereqs": True},
            ".SECONDARY": {"duplicatable": True, "requires_prereqs": True},
            ".IGNORE": {"duplicatable": True, "requires_prereqs": True},
            ".SILENT": {"duplicatable": True, "requires_prereqs": True},
            ".POSIX": {"duplicatable": False, "requires_prereqs": False},
            ".NOTPARALLEL": {"duplicatable": False, "requires_prereqs": False},
            ".ONESHELL": {"duplicatable": False, "requires_prereqs": False},
            ".EXPORT_ALL_VARIABLES": {"duplicatable": False, "requires_prereqs": False},
            ".LOW_RESOLUTION_TIME": {"duplicatable": False, "requires_prereqs": False},
            ".SECOND_EXPANSION": {"duplicatable": False, "requires_prereqs": False},
            ".SECONDEXPANSION": {"duplicatable": False, "requires_prereqs": False},
            ".VARIABLES": {"duplicatable": False, "requires_prereqs": False},
            ".MAKE": {"duplicatable": False, "requires_prereqs": False},
            ".WAIT": {"duplicatable": False, "requires_prereqs": False},
            ".INCLUDE_DIRS": {"duplicatable": False, "requires_prereqs": False},
            ".LIBPATTERNS": {"duplicatable": False, "requires_prereqs": False},
        }

    def _analyze_special_target_usage(self, lines: list[str]) -> dict[str, int]:
        """Analyze how many times each special target is used."""
        usage: dict[str, int] = {}

        for line in lines:
            stripped = line.strip()
            if stripped.startswith(".") and ":" in stripped:
                target_name = stripped.split(":")[0]
                usage[target_name] = usage.get(target_name, 0) + 1

        return usage

    def _validate_special_target(
        self, line: str, special_targets: dict, target_usage: dict
    ) -> tuple[str, list[str], list[str]]:
        """Validate a special target declaration."""
        errors: list[str] = []
        warnings: list[str] = []

        # Extract target name
        match = re.match(r"^(\.[A-Z_]+):", line)
        if not match:
            return line, errors, warnings

        target_name = match.group(1)

        if target_name not in special_targets:
            errors.append(f"Unknown special target '{target_name}'")
            return line, errors, warnings

        target_info = special_targets[target_name]

        # Check if target is used multiple times when it shouldn't be
        if not target_info["duplicatable"] and target_usage.get(target_name, 0) > 1:
            errors.append(
                f"Special target '{target_name}' cannot be declared multiple times"
            )

        # Check if prerequisites are required
        content = line[line.find(":") + 1 :].strip()
        if target_info["requires_prereqs"] and not content:
            warnings.append(
                f"Special target '{target_name}' typically requires prerequisites"
            )

        return line, errors, warnings
