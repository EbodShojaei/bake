"""Plugin for enhancing existing .PHONY declarations with additional detected targets."""

from typing import Any

from bake.plugins.base import FormatResult, FormatterPlugin
from bake.utils.line_utils import MakefileParser, PhonyAnalyzer


class PhonyDetectionRule(FormatterPlugin):
    """Enhance existing .PHONY declarations with additional detected phony targets."""

    def __init__(self) -> None:
        super().__init__("phony_detection", priority=41)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Enhance existing .PHONY declarations with additional detected targets."""
        errors: list[str] = []
        warnings: list[str] = []
        check_messages: list[str] = []
        changed = False

        # Only run if auto-insertion is enabled (same setting controls both features)
        if not config.get("auto_insert_phony_declarations", False) and not check_mode:
            return FormatResult(
                lines=lines,
                changed=False,
                errors=errors,
                warnings=warnings,
                check_messages=check_messages,
            )

        # Check if .PHONY already exists
        if not MakefileParser.has_phony_declarations(lines):
            return FormatResult(
                lines=lines,
                changed=False,
                errors=errors,
                warnings=warnings,
                check_messages=check_messages,
            )

        # Get existing phony targets
        existing_phony_targets = MakefileParser.extract_phony_targets(lines)

        # Detect phony targets using conditional-aware analysis (same as PhonyInsertionRule)
        detected_targets = PhonyAnalyzer.detect_phony_targets_excluding_conditionals(
            lines
        )

        # Only add newly detected targets that weren't already in .PHONY
        new_targets = detected_targets - existing_phony_targets

        # In check mode, generate messages about missing targets
        if check_mode and new_targets:
            auto_insert_enabled = config.get("auto_insert_phony_declarations", False)
            sorted_new_targets = sorted(new_targets)

            # Find the line number of the existing .PHONY declaration
            phony_line_num = None
            for i, line in enumerate(lines):
                if line.strip().startswith(".PHONY:"):
                    phony_line_num = i + 1  # 1-indexed
                    break

            gnu_format = config.get("_global", {}).get("gnu_error_format", True)

            if auto_insert_enabled:
                if gnu_format:
                    message = f"{phony_line_num}: Error: Missing targets in .PHONY declaration: {', '.join(sorted_new_targets)}"
                else:
                    message = f"Error: Missing targets in .PHONY declaration: {', '.join(sorted_new_targets)} (line {phony_line_num})"
            else:
                if gnu_format:
                    message = f"{phony_line_num}: Warning: Consider adding targets to .PHONY declaration: {', '.join(sorted_new_targets)}"
                else:
                    message = f"Warning: Consider adding targets to .PHONY declaration: {', '.join(sorted_new_targets)} (line {phony_line_num})"

            check_messages.append(message)

        if not new_targets:
            return FormatResult(
                lines=lines,
                changed=False,
                errors=errors,
                warnings=warnings,
                check_messages=check_messages,
            )

        if check_mode:
            # In check mode, don't actually modify the file
            auto_insert_enabled = config.get("auto_insert_phony_declarations", False)
            return FormatResult(
                lines=lines,
                changed=auto_insert_enabled,  # Only mark as changed if auto-insertion is enabled
                errors=errors,
                warnings=warnings,
                check_messages=check_messages,
            )
        else:
            # Update .PHONY line with new targets
            all_targets = existing_phony_targets | new_targets
            sorted_targets = sorted(all_targets)
            new_phony_line = f".PHONY: {' '.join(sorted_targets)}"

            # Replace existing .PHONY line
            formatted_lines = []
            for line in lines:
                if line.strip().startswith(".PHONY:"):
                    formatted_lines.append(new_phony_line)
                    changed = True
                else:
                    formatted_lines.append(line)

            return FormatResult(
                lines=formatted_lines,
                changed=changed,
                errors=errors,
                warnings=warnings,
                check_messages=check_messages,
            )
