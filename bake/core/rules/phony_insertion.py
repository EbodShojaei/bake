"""Plugin for automatically inserting .PHONY declarations when missing."""

import re
from typing import Any

from bake.plugins.base import FormatResult, FormatterPlugin
from bake.utils.line_utils import ConditionalTracker, MakefileParser, PhonyAnalyzer


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
        detected_targets = self._detect_phony_targets_excluding_conditionals(lines)

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

    def _detect_phony_targets_excluding_conditionals(
        self, lines: list[str]
    ) -> set[str]:
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
                recipe_lines = self._get_target_recipe_lines(lines, i)

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
                    if PhonyAnalyzer.is_target_phony(target_name, recipe_lines):
                        phony_targets.add(target_name)

        return phony_targets

    def _get_target_recipe_lines(
        self, lines: list[str], target_index: int
    ) -> list[str]:
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
