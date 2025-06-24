"""PHONY declaration formatting rule for Makefiles."""

import re
from typing import Any

from bake.utils.line_utils import ConditionalTracker, MakefileParser

from ...plugins.base import FormatResult, FormatterPlugin


class PhonyRule(FormatterPlugin):
    """Handles proper grouping and placement of .PHONY declarations."""

    def __init__(self) -> None:
        super().__init__("phony", priority=40)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Group and organize .PHONY declarations."""
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        group_phony = config.get("group_phony_declarations", True)

        if not group_phony:
            return FormatResult(
                lines=lines,
                changed=False,
                errors=errors,
                warnings=warnings,
                check_messages=[],
            )

        # Use ConditionalTracker to track which lines are inside conditional blocks
        conditional_tracker = ConditionalTracker()

        # Find all .PHONY declarations and detect obvious phony targets
        top_level_phony_targets = (
            set()
        )  # Only targets from top-level .PHONY declarations
        top_level_phony_line_indices = []  # Only top-level .PHONY line indices
        conditional_phony_line_indices = []  # .PHONY lines inside conditionals
        malformed_phony_found = False
        has_phony_declarations = False
        has_conditional_phony = False

        # Common phony target names that should be automatically detected
        common_phony_targets = {
            "all",
            "clean",
            "install",
            "uninstall",
            "test",
            "check",
            "help",
            "build",
            "rebuild",
            "debug",
            "release",
            "dist",
            "distclean",
            "docs",
            "doc",
            "lint",
            "format",
            "setup",
            "run",
            "docker",
            "package",
        }

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Get the conditional context this line is IN
            conditional_context = conditional_tracker.process_line(line, i)
            is_in_conditional = bool(conditional_context)

            # Check for .PHONY declaration
            if stripped.startswith(".PHONY:"):
                has_phony_declarations = True

                if is_in_conditional:
                    # This .PHONY is inside a conditional block - don't consolidate it
                    conditional_phony_line_indices.append(i)
                    has_conditional_phony = True
                else:
                    # This .PHONY is at top level - can be consolidated
                    top_level_phony_line_indices.append(i)

                    # Extract targets from this PHONY line
                    targets_part = stripped[7:].strip()  # Remove '.PHONY:'

                    # Normal .PHONY line - extract targets
                    targets = [t.strip() for t in targets_part.split() if t.strip()]
                    if not is_in_conditional:
                        top_level_phony_targets.update(targets)

                    # Now look ahead to see if there are malformed continuation lines
                    j = i + 1
                    while j < len(lines):
                        next_line = lines[j].strip()
                        original_line = lines[
                            j
                        ]  # Keep the original line for tab checking
                        if not next_line or next_line.startswith("#"):
                            j += 1
                            continue

                        # Check if this looks like a malformed continuation
                        # Lines that start with tab and contain backslashes or target names
                        if original_line.startswith("\t") and (
                            original_line.startswith("\t\\")
                            or original_line.startswith(
                                "\t\\ \\"
                            )  # Match "tab backslash space backslash"
                            or next_line.replace("\\", "").strip()
                            in common_phony_targets
                        ):

                            malformed_phony_found = True
                            # Extract targets, removing backslashes and excess whitespace
                            clean_line = next_line.replace("\\", "").strip()
                            if clean_line:
                                target_names = [
                                    t.strip()
                                    for t in clean_line.split()
                                    if t.strip() and not t.startswith("#")
                                ]
                                # Since we're processing continuation of a top-level .PHONY,
                                # these targets should also be treated as top-level
                                top_level_phony_targets.update(target_names)

                            # Continuation lines are always treated the same as their parent .PHONY line
                            top_level_phony_line_indices.append(j)
                            j += 1
                        else:
                            # This doesn't look like a continuation line
                            break

        # Warn about conditional .PHONY declarations
        if has_conditional_phony:
            warnings.append(
                "Found .PHONY declarations inside conditional blocks. These will be preserved as-is to maintain conditional logic."
            )

        # Auto-detect obvious phony targets (only if we already have .PHONY declarations)
        if has_phony_declarations:
            for _i, line in enumerate(lines):
                stripped = line.strip()
                if (
                    ":" in stripped
                    and not stripped.startswith("\t")
                    and not stripped.startswith(".PHONY:")
                ):
                    # Check for target definitions
                    target_match = re.match(r"^([^:]+):", stripped)
                    if target_match:
                        target_name = target_match.group(1).strip()
                        # Only auto-detect common phony targets at top level
                        if target_name in common_phony_targets:
                            top_level_phony_targets.add(target_name)

        # If no top-level .PHONY declarations found, return original
        if not top_level_phony_targets:
            return FormatResult(
                lines=lines,
                changed=False,
                errors=errors,
                warnings=warnings,
                check_messages=[],
            )

        # Always make changes if we found malformed .PHONY or multiple top-level .PHONY lines
        if len(top_level_phony_line_indices) <= 1 and not malformed_phony_found:
            return FormatResult(
                lines=lines,
                changed=False,
                errors=errors,
                warnings=warnings,
                check_messages=[],
            )

        # If we have multiple top-level .PHONY lines or malformed ones, clean them up
        phony_at_top = config.get("phony_at_top", True)

        # Create a single, clean .PHONY declaration for top-level targets
        sorted_targets = sorted(top_level_phony_targets)
        new_phony_line = f".PHONY: {' '.join(sorted_targets)}"

        # Replace all top-level .PHONY lines with a single clean one
        # Note: we only touch top_level_phony_line_indices, leaving conditional ones alone
        if phony_at_top and (
            len(top_level_phony_line_indices) > 1 or malformed_phony_found
        ):
            # Group multiple top-level .PHONY declarations at the top
            formatted_lines = []
            phony_inserted = False
            insert_index = MakefileParser.find_phony_insertion_point(lines)

            for i, line in enumerate(lines):
                if i == insert_index and not phony_inserted:
                    # Insert the grouped .PHONY declaration
                    formatted_lines.append(new_phony_line)
                    formatted_lines.append("")  # Add blank line after
                    phony_inserted = True
                    changed = True

                if i not in top_level_phony_line_indices:
                    formatted_lines.append(line)
                else:
                    changed = True  # We're removing this top-level .PHONY line
        else:
            # Simple replacement - just clean up malformed top-level .PHONY
            formatted_lines = []
            phony_inserted = False

            for i, line in enumerate(lines):
                if i in top_level_phony_line_indices:
                    # Replace the first top-level .PHONY line with our clean version
                    if not phony_inserted:
                        formatted_lines.append(new_phony_line)
                        phony_inserted = True
                        changed = True
                    # Skip other top-level .PHONY lines (they get removed)
                    elif i != top_level_phony_line_indices[0]:
                        changed = True
                else:
                    formatted_lines.append(line)

        if malformed_phony_found:
            warnings.append(
                "Fixed malformed .PHONY declaration with invalid continuation syntax"
            )

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=[],
        )

    def _extract_phony_targets(self, line: str) -> list[str]:
        """Extract target names from a .PHONY line."""
        # Remove .PHONY: prefix and any line continuation
        content = line.strip()
        if content.startswith(".PHONY:"):
            content = content[7:].strip()

        if content.endswith("\\"):
            content = content[:-1].strip()

        return [target.strip() for target in content.split() if target.strip()]
