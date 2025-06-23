"""Plugin for enhancing existing .PHONY declarations with additional detected targets."""

import re
from typing import Any

from bake.plugins.base import FormatResult, FormatterPlugin
from bake.utils.line_utils import ConditionalTracker, MakefileParser, PhonyAnalyzer


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
        detected_targets = self._detect_phony_targets_excluding_conditionals(lines)

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
