"""Plugin for enhancing existing .PHONY declarations with additional detected targets."""

import re
from typing import Any

from ...constants.makefile_targets import ALL_SPECIAL_MAKE_TARGETS, DEFAULT_SUFFIXES
from ...constants.phony_targets import COMMON_PHONY_TARGETS
from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.line_utils import PhonyAnalyzer


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

        # Only run if auto-insertion is enabled
        if not config.get("auto_insert_phony_declarations", False) and not check_mode:
            return FormatResult(
                lines=lines,
                changed=False,
                errors=errors,
                warnings=warnings,
                check_messages=check_messages,
            )

        # Check if .PHONY already exists
        if not self._has_phony_declarations(lines):
            return FormatResult(
                lines=lines,
                changed=False,
                errors=errors,
                warnings=warnings,
                check_messages=check_messages,
            )

        # Get existing phony targets
        existing_phony_targets = self._extract_phony_targets(lines)

        # Detect phony targets
        detected_targets = self._detect_phony_targets(lines)

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

            gnu_format = config.get("gnu_error_format", False)

            if auto_insert_enabled:
                if gnu_format:
                    message = f"Makefile:{phony_line_num}: Error: Missing targets in .PHONY declaration: {', '.join(sorted_new_targets)}"
                else:
                    message = f"Error: Missing targets in .PHONY declaration: {', '.join(sorted_new_targets)} (line {phony_line_num})"
            else:
                if gnu_format:
                    message = f"Makefile:{phony_line_num}: Warning: Consider adding targets to .PHONY declaration: {', '.join(sorted_new_targets)}"
                else:
                    message = f"Warning: Consider adding targets to .PHONY declaration: {', '.join(sorted_new_targets)} (line {phony_line_num})"

            warnings.append(message)

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

    def _has_phony_declarations(self, lines: list[str]) -> bool:
        """Check if the Makefile has any .PHONY declarations."""
        return any(line.strip().startswith(".PHONY:") for line in lines)

    def _extract_phony_targets(self, lines: list[str]) -> set[str]:
        """Extract targets from existing .PHONY declarations."""
        phony_targets = set()

        for line in lines:
            stripped = line.strip()
            if stripped.startswith(".PHONY:"):
                # Remove .PHONY: prefix and any line continuation
                content = stripped[7:].strip()  # Remove '.PHONY:'

                # Handle continuation character
                if content.endswith("\\"):
                    content = content[:-1].strip()

                targets = [t.strip() for t in content.split() if t.strip()]
                phony_targets.update(targets)

        return phony_targets

    def _detect_phony_targets(self, lines: list[str]) -> set[str]:
        """Detect phony targets in the Makefile."""
        target_pattern = re.compile(r"^([^:=]+):(:?)\s*(.*)$")
        phony_targets = set()

        # Use special targets from constants
        declarative_targets = ALL_SPECIAL_MAKE_TARGETS

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Skip empty lines, comments, and lines that start with tab (recipes)
            if not stripped or stripped.startswith("#") or line.startswith("\t"):
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
                    if target_name in declarative_targets:
                        continue

                    # Skip targets that contain quotes or special characters
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
                    if self._is_target_phony(target_name, recipe_lines, lines):
                        phony_targets.add(target_name)

        return phony_targets

    def _get_target_recipe_lines(
        self, lines: list[str], target_line_index: int
    ) -> list[str]:
        """Get recipe lines for a target."""
        recipe_lines = []
        i = target_line_index + 1

        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            # Stop at next target definition or empty line
            if not stripped or (
                ":" in stripped
                and not line.startswith("\t")
                and not line.startswith(" ")
            ):
                break

            # Add recipe lines (lines starting with tab)
            if line.startswith("\t"):
                recipe_lines.append(line)

            i += 1

        return recipe_lines

    def _is_target_phony(
        self, target_name: str, recipe_lines: list[str], all_lines: list[str]
    ) -> bool:
        """Determine if a target is phony (has no real file)."""
        # Check if this is a suffix rule (e.g., .a.b, .c.o)
        if self._is_suffix_rule(target_name, all_lines):
            return False  # Suffix rules are NOT phony

        # Check if this is a pattern rule (e.g., %.o, %.c)
        if "%" in target_name:
            return False  # Pattern rules are NOT phony

        # Use PhonyAnalyzer for dynamic analysis
        dynamic_result = PhonyAnalyzer.is_target_phony(
            target_name, recipe_lines, all_lines
        )

        # Use hardcoded patterns for edge cases dynamic analysis might miss
        if target_name.lower() in COMMON_PHONY_TARGETS:
            return True

        return dynamic_result

    def _is_suffix_rule(self, target_name: str, all_lines: list[str]) -> bool:
        """Check if target is a suffix rule (e.g., .a.b, .c.o)."""
        if not target_name.startswith("."):
            return False

        # Check if it contains exactly one more dot (e.g., .a.b, .c.o)
        if target_name.count(".") != 2:
            return False

        # Check if the suffixes are declared in .SUFFIXES
        declared_suffixes = self._get_declared_suffixes(all_lines)
        if not declared_suffixes:
            return False

        # Extract the two suffixes
        parts = target_name.split(".")
        if len(parts) != 3:  # ['', 'a', 'b']
            return False

        suffix1 = "." + parts[1]  # .a
        suffix2 = "." + parts[2]  # .b

        return suffix1 in declared_suffixes and suffix2 in declared_suffixes

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

    def _is_file_target(self, target_name: str, all_lines: list[str]) -> bool:
        """Check if target is likely a file target (not phony)."""
        # Has file extension and doesn't look like an action
        if "." in target_name and not target_name.startswith("."):
            return True

        # Has path separators
        if "/" in target_name or "\\" in target_name:
            return True

        # Check if it's a target that creates a file with its own name
        return self._target_creates_file_with_same_name(target_name, all_lines)

    def _target_creates_file_with_same_name(
        self, target_name: str, all_lines: list[str]
    ) -> bool:
        """Check if target creates a file with its own name by analyzing its recipe."""

        # Find the target definition and get its recipe lines
        target_pattern = re.compile(r"^([^:=]+):(:?)\s*(.*)$")

        for i, line in enumerate(all_lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or line.startswith("\t"):
                continue

            match = target_pattern.match(stripped)
            if match:
                target_list = match.group(1).strip()
                target_names = [t.strip() for t in target_list.split() if t.strip()]

                if target_name in target_names:
                    # Get recipe lines for this target
                    recipe_lines = PhonyAnalyzer._get_target_recipe_lines(all_lines, i)

                    # Analyze if any recipe command creates the target file
                    for recipe_line in recipe_lines:
                        if recipe_line.strip() and not recipe_line.strip().startswith(
                            "#"
                        ):
                            # Clean the command for analysis
                            clean_command = PhonyAnalyzer._clean_command_for_analysis(
                                recipe_line
                            )
                            if PhonyAnalyzer._command_creates_target_file(
                                clean_command, target_name
                            ):
                                return True
                    break

        # If no recipe analysis found, use simple heuristic
        # Targets with file extensions are likely file targets
        return "." in target_name and not target_name.startswith(".")
