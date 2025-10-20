"""Suffix rule validation and formatting rule for Makefiles."""

import re
from typing import Any

from ...constants.makefile_targets import DEFAULT_SUFFIXES
from ...plugins.base import FormatResult, FormatterPlugin


class SuffixValidationRule(FormatterPlugin):
    """Validates and formats suffix rules and .SUFFIXES declarations."""

    def __init__(self) -> None:
        super().__init__("suffix_validation", priority=15)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Validate suffix rules and .SUFFIXES declarations."""
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        declared_suffixes: set[str] = set()

        for _i, line in enumerate(lines):
            stripped = line.strip()

            # Validate .SUFFIXES declarations
            if stripped.startswith(".SUFFIXES:"):
                new_line, line_errors, line_warnings = (
                    self._validate_suffixes_declaration(line, declared_suffixes)
                )
                if new_line != line:
                    changed = True
                errors.extend(line_errors)
                warnings.extend(line_warnings)
                formatted_lines.append(new_line)

                # Update declared suffixes with new ones from this line
                content = line[line.find(":") + 1 :].strip()
                if content:
                    new_suffixes = [s for s in content.split() if s.startswith(".")]
                    declared_suffixes.update(new_suffixes)

            # Validate suffix rules
            elif self._is_suffix_rule_line(stripped):
                line_errors, line_warnings = self._validate_suffix_rule(
                    line, declared_suffixes
                )
                errors.extend(line_errors)
                warnings.extend(line_warnings)
                formatted_lines.append(line)

            else:
                formatted_lines.append(line)

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=[],
        )

    def _is_suffix_rule_line(self, line: str) -> bool:
        """Check if line defines a suffix rule."""
        # Pattern: .suffix1.suffix2: (no prerequisites for suffix rules)
        return bool(re.match(r"^\.[^:]+\.\w+:\s*$", line))

    def _validate_suffix_rule(
        self, line: str, declared_suffixes: set[str]
    ) -> tuple[list[str], list[str]]:
        """Validate a suffix rule."""
        errors: list[str] = []
        warnings: list[str] = []

        # Extract target (e.g., .a.b)
        match = re.match(r"^(\.[^:]+\.\w+):", line)
        if not match:
            return errors, warnings

        target = match.group(1)
        parts = target.split(".")
        if len(parts) != 3:
            return errors, warnings

        suffix1 = "." + parts[1]
        suffix2 = "." + parts[2]

        # Check if suffixes are declared
        if suffix1 not in declared_suffixes:
            errors.append(f"Suffix rule '{target}' uses undeclared suffix '{suffix1}'")

        if suffix2 not in declared_suffixes:
            errors.append(f"Suffix rule '{target}' uses undeclared suffix '{suffix2}'")

        return errors, warnings

    def _validate_suffixes_declaration(
        self, line: str, declared_suffixes: set[str]
    ) -> tuple[str, list[str], list[str]]:
        """Validate a .SUFFIXES declaration."""
        errors: list[str] = []
        warnings: list[str] = []

        # Extract suffixes from .SUFFIXES: .a .b .c
        content = line[line.find(":") + 1 :].strip()

        if content:
            suffixes = content.split()
            new_suffixes = set()

            for suffix in suffixes:
                # Validate suffix format
                if not suffix.startswith("."):
                    errors.append(
                        f"Invalid suffix '{suffix}' - suffixes must start with '.'"
                    )
                    continue

                # Check for duplicate declarations
                if suffix in declared_suffixes:
                    warnings.append(
                        f"Suffix '{suffix}' is already declared in previous .SUFFIXES statement"
                    )

                # Check for duplicates within this declaration
                if suffix in new_suffixes:
                    errors.append(
                        f"Duplicate suffix '{suffix}' in .SUFFIXES declaration"
                    )

                new_suffixes.add(suffix)

            # Check for unusual suffix patterns
            for suffix in new_suffixes:
                if len(suffix) < 2:  # Just "." or very short
                    warnings.append(
                        f"Unusual suffix '{suffix}' - consider if this is intentional"
                    )
                elif suffix.count(".") > 1:  # Multiple dots like ".tar.gz"
                    warnings.append(
                        f"Complex suffix '{suffix}' - ensure this is supported by your Make version"
                    )

        return line, errors, warnings

    def _get_declared_suffixes(self, all_lines: list[str]) -> set[str]:
        """Extract suffixes declared in .SUFFIXES statements."""
        suffixes = set()

        for line in all_lines:
            stripped = line.strip()
            if stripped.startswith(".SUFFIXES:"):
                # Parse suffixes from .SUFFIXES: .a .b .c
                content = stripped[9:].strip()  # Remove '.SUFFIXES:'
                if content:  # If not empty (which clears all suffixes)
                    suffixes.update(content.split())

        # If no .SUFFIXES found, use default suffixes
        if not suffixes:
            suffixes = DEFAULT_SUFFIXES

        return suffixes
