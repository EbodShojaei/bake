"""PHONY declaration formatting rule for Makefiles."""

import re
from typing import Union

from ...plugins.base import FormatResult, FormatterPlugin


class PhonyRule(FormatterPlugin):
    """Handles proper grouping and placement of .PHONY declarations."""

    def __init__(self) -> None:
        super().__init__("phony", priority=40)

    def format(self, lines: list[str], config: dict) -> FormatResult:
        """Group and organize .PHONY declarations."""
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        group_phony = config.get("group_phony_declarations", True)
        phony_at_top = config.get("phony_at_top", True)

        if not group_phony:
            return FormatResult(
                lines=lines, changed=False, errors=errors, warnings=warnings
            )

        # Find all .PHONY declarations and targets
        phony_targets = set()
        phony_line_indices = []
        non_phony_lines = []
        has_existing_phony = False

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
        }

        # First pass: check for existing .PHONY declarations
        for _i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith(".PHONY:"):
                has_existing_phony = True
                break

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Check for .PHONY declaration
            if stripped.startswith(".PHONY:"):
                phony_line_indices.append(i)
                # Extract targets from this PHONY line
                targets_part = stripped[7:].strip()  # Remove '.PHONY:'
                if targets_part:
                    targets = [t.strip() for t in targets_part.split()]
                    phony_targets.update(targets)
                changed = True  # Mark as changed since we're reorganizing
            elif (
                has_existing_phony and ":" in stripped and not stripped.startswith("\t")
            ):
                # Only auto-detect targets if there are already .PHONY declarations
                # Check for target definitions
                target_match = re.match(r"^([^:]+):", stripped)
                if target_match:
                    target_name = target_match.group(1).strip()
                    # Check if it's a common phony target or has no file dependencies
                    if target_name in common_phony_targets or (
                        stripped.endswith(":") and target_name.isalpha()
                    ):
                        phony_targets.add(target_name)
                        changed = True
                non_phony_lines.append((i, line))
            else:
                non_phony_lines.append((i, line))

        # If no .PHONY declarations found, return original
        if not phony_targets:
            return FormatResult(
                lines=lines, changed=False, errors=errors, warnings=warnings
            )

        # Create grouped .PHONY declaration
        sorted_targets = sorted(phony_targets)
        phony_declaration: Union[str, list[str]]
        if len(sorted_targets) <= 8:  # Single line if not too many targets
            phony_declaration = f".PHONY: {' '.join(sorted_targets)}"
        else:
            # Multi-line format for many targets
            phony_lines = [".PHONY: \\"]
            for i, target in enumerate(sorted_targets):
                if i == len(sorted_targets) - 1:
                    phony_lines.append(f"\t{target}")
                else:
                    phony_lines.append(f"\t{target} \\")
            phony_declaration = phony_lines

        # Rebuild the file
        if phony_at_top:
            # Add .PHONY at the top (after initial comments/variables)
            insert_index = self._find_insertion_point(lines)

            # Insert grouped .PHONY
            result_lines = lines[:insert_index]
            if isinstance(phony_declaration, list):
                result_lines.extend(phony_declaration)
            else:
                result_lines.append(phony_declaration)

            # Add empty line after .PHONY if next line isn't empty
            if insert_index < len(lines) and lines[insert_index].strip():
                result_lines.append("")

            # Add remaining lines, skipping original .PHONY declarations
            for i in range(insert_index, len(lines)):
                if i not in phony_line_indices:
                    result_lines.append(lines[i])

            formatted_lines = result_lines
        else:
            # Keep .PHONY declarations near the end
            result_lines = []
            for i, line in enumerate(lines):
                if i not in phony_line_indices:
                    result_lines.append(line)

            # Add grouped .PHONY at the end
            if isinstance(phony_declaration, list):
                result_lines.extend(phony_declaration)
            else:
                result_lines.append(phony_declaration)

            formatted_lines = result_lines

        return FormatResult(
            lines=formatted_lines, changed=changed, errors=errors, warnings=warnings
        )

    def _find_insertion_point(self, lines: list[str]) -> int:
        """Find the best place to insert .PHONY declarations at the top."""
        # Skip initial comments and variable declarations
        for i, line in enumerate(lines):
            stripped = line.strip()

            # Skip empty lines, comments, and variable assignments
            if (
                not stripped
                or stripped.startswith("#")
                or "=" in stripped
                or stripped.startswith("include")
                or stripped.startswith("-include")
            ):
                continue

            # This looks like the first rule, insert here
            return i

        # If we get here, insert at the end
        return len(lines)

    def _extract_phony_targets(self, line: str) -> list[str]:
        """Extract target names from a .PHONY line."""
        # Remove .PHONY: prefix and any line continuation
        content = line.strip()
        if content.startswith(".PHONY:"):
            content = content[7:].strip()

        if content.endswith("\\"):
            content = content[:-1].strip()

        return [target.strip() for target in content.split() if target.strip()]
