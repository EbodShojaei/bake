"""Plugin for automatically inserting .PHONY declarations when missing."""

from typing import Any

from bake.plugins.base import FormatResult, FormatterPlugin
from bake.utils.line_utils import MakefileParser, PhonyAnalyzer


class PhonyInsertionRule(FormatterPlugin):
    """Auto-insert .PHONY declarations when missing and enabled."""

    def __init__(self) -> None:
        super().__init__("phony_insertion", priority=39)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Insert .PHONY declarations for detected phony targets."""
        if not config.get("auto_insert_phony_declarations", False) and not check_mode:
            return FormatResult(
                lines=lines, changed=False, errors=[], warnings=[], check_messages=[]
            )

        errors: list[str] = []
        warnings: list[str] = []
        check_messages: list[str] = []
        changed = False

        # Check if .PHONY already exists
        if MakefileParser.has_phony_declarations(lines):
            return FormatResult(
                lines=lines,
                changed=False,
                errors=errors,
                warnings=warnings,
                check_messages=check_messages,
            )

        # Detect phony targets using dynamic analysis (excluding conditional targets)
        detected_targets = PhonyAnalyzer.detect_phony_targets_excluding_conditionals(
            lines
        )

        if not detected_targets:
            return FormatResult(
                lines=lines,
                changed=False,
                errors=errors,
                warnings=warnings,
                check_messages=check_messages,
            )

        # Insert .PHONY declaration at the top
        phony_at_top = config.get("phony_at_top", True)
        sorted_targets = sorted(detected_targets)
        new_phony_line = f".PHONY: {' '.join(sorted_targets)}"

        if check_mode:
            # In check mode, always report missing phony declarations (even if auto-insertion is disabled)
            auto_insert_enabled = config.get("auto_insert_phony_declarations", False)

            if phony_at_top:
                insert_index = MakefileParser.find_phony_insertion_point(lines)
                # Report at the line where it would be inserted
                gnu_format = config.get("_global", {}).get("gnu_error_format", True)

                if auto_insert_enabled:
                    if gnu_format:
                        message = f"{insert_index + 1}: Error: Missing .PHONY declaration for targets: {', '.join(sorted_targets)}"
                    else:
                        message = f"Error: Missing .PHONY declaration for targets: {', '.join(sorted_targets)} (line {insert_index + 1})"
                else:
                    # When auto-insertion is disabled, suggest the missing targets
                    if gnu_format:
                        message = f"{insert_index + 1}: Warning: Consider adding .PHONY declaration for targets: {', '.join(sorted_targets)}"
                    else:
                        message = f"Warning: Consider adding .PHONY declaration for targets: {', '.join(sorted_targets)} (line {insert_index + 1})"

                check_messages.append(message)
            else:
                # Missing at the beginning
                gnu_format = config.get("_global", {}).get("gnu_error_format", True)

                if auto_insert_enabled:
                    if gnu_format:
                        message = f"1: Error: Missing .PHONY declaration for targets: {', '.join(sorted_targets)}"
                    else:
                        message = f"Error: Missing .PHONY declaration for targets: {', '.join(sorted_targets)} (line 1)"
                else:
                    # When auto-insertion is disabled, suggest the missing targets
                    if gnu_format:
                        message = f"1: Warning: Consider adding .PHONY declaration for targets: {', '.join(sorted_targets)}"
                    else:
                        message = f"Warning: Consider adding .PHONY declaration for targets: {', '.join(sorted_targets)} (line 1)"

                check_messages.append(message)

            # Only mark as changed if auto-insertion is enabled
            changed = auto_insert_enabled
            formatted_lines = lines  # Don't actually modify in check mode
        else:
            # Actually perform the insertion
            if phony_at_top:
                insert_index = MakefileParser.find_phony_insertion_point(lines)
                formatted_lines = []

                for i, line in enumerate(lines):
                    if i == insert_index:
                        formatted_lines.append(new_phony_line)
                        formatted_lines.append("")  # Add blank line after
                        changed = True
                    formatted_lines.append(line)
            else:
                # Add at the beginning
                formatted_lines = [new_phony_line, ""] + lines
                changed = True

            warnings.append(
                f"Auto-inserted .PHONY declaration for {len(detected_targets)} targets: {', '.join(sorted_targets)}"
            )

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=check_messages,
        )
