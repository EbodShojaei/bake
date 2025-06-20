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
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        group_phony = config.get("group_phony_declarations", True)

        if not group_phony:
            return FormatResult(
                lines=lines, changed=False, errors=errors, warnings=warnings
            )

        # Find all .PHONY declarations and detect obvious phony targets
        phony_targets = set()
        phony_line_indices = []
        malformed_phony_found = False
        has_phony_declarations = False

        # Common phony target names that should be automatically detected
        common_phony_targets = {
            "all", "clean", "install", "uninstall", "test", "check", "help", 
            "build", "rebuild", "debug", "release", "dist", "distclean", 
            "docs", "doc", "lint", "format", "setup", "run"
        }

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Check for .PHONY declaration
            if stripped.startswith(".PHONY:"):
                has_phony_declarations = True
                phony_line_indices.append(i)
                
                # Extract targets from this PHONY line
                targets_part = stripped[7:].strip()  # Remove '.PHONY:'
                
                # Check for malformed .PHONY (like the one with backslashes)
                if not targets_part or targets_part.startswith("\\"):
                    malformed_phony_found = True
                    # Look ahead for continuation lines to collect all targets
                    j = i + 1
                    while j < len(lines):
                        next_line = lines[j].strip()
                        if not next_line or next_line.startswith("#"):
                            j += 1
                            continue
                        if next_line.startswith("\\") or not next_line.startswith("\t"):
                            break
                        # This is a continuation line with targets
                        targets = [t.strip() for t in next_line.replace("\\", "").split() if t.strip()]
                        phony_targets.update(targets)
                        phony_line_indices.append(j)
                        j += 1
                else:
                    # Normal .PHONY line
                    targets = [t.strip() for t in targets_part.split() if t.strip()]
                    phony_targets.update(targets)

        # Auto-detect obvious phony targets (only if we already have .PHONY declarations)
        if has_phony_declarations:
            for i, line in enumerate(lines):
                stripped = line.strip()
                if ":" in stripped and not stripped.startswith("\t") and not stripped.startswith(".PHONY:"):
                    # Check for target definitions
                    target_match = re.match(r"^([^:]+):", stripped)
                    if target_match:
                        target_name = target_match.group(1).strip()
                        # Only auto-detect common phony targets
                        if target_name in common_phony_targets:
                            phony_targets.add(target_name)

        # If no .PHONY declarations found, return original
        if not phony_targets:
            return FormatResult(
                lines=lines, changed=False, errors=errors, warnings=warnings
            )

        # Only make changes if we found malformed .PHONY or multiple .PHONY lines
        if len(phony_line_indices) <= 1 and not malformed_phony_found:
            return FormatResult(
                lines=lines, changed=False, errors=errors, warnings=warnings
            )

        # If we have multiple .PHONY lines, group them at the top
        phony_at_top = config.get("phony_at_top", True)

        # Create a single, clean .PHONY declaration
        sorted_targets = sorted(phony_targets)
        new_phony_line = f".PHONY: {' '.join(sorted_targets)}"

        # Replace all .PHONY lines with a single clean one
        if phony_at_top and len(phony_line_indices) > 1:
            # Group multiple .PHONY declarations at the top
            formatted_lines = []
            phony_inserted = False
            insert_index = self._find_insertion_point(lines)

            for i, line in enumerate(lines):
                if i == insert_index and not phony_inserted:
                    # Insert the grouped .PHONY declaration
                    formatted_lines.append(new_phony_line)
                    formatted_lines.append("")  # Add blank line after
                    phony_inserted = True
                    changed = True

                if i not in phony_line_indices:
                    formatted_lines.append(line)
                else:
                    changed = True  # We're removing this .PHONY line
        else:
            # Simple replacement - just clean up malformed .PHONY
            formatted_lines = []
            phony_inserted = False

            for i, line in enumerate(lines):
                if i in phony_line_indices:
                    # Replace the first .PHONY line with our clean version
                    if not phony_inserted:
                        formatted_lines.append(new_phony_line)
                        phony_inserted = True
                        changed = True
                    # Skip other .PHONY lines (they get removed)
                    elif i != phony_line_indices[0]:
                        changed = True
                else:
                    formatted_lines.append(line)

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
