"""Unified PHONY declaration rule: detection, insertion, and grouping."""

import re
from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.line_utils import MakefileParser, PhonyAnalyzer


class PhonyRule(FormatterPlugin):
    """Unified rule for detecting, inserting, and organizing .PHONY declarations."""

    def __init__(self) -> None:
        super().__init__("phony", priority=40)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """
        Unified phony rule that:
        1. Always detects phony targets (for check mode)
        2. Inserts missing .PHONY declarations (if enabled)
        3. Adds missing targets to existing .PHONY (if enabled)
        4. Groups/ungroups based on group_phony_declarations
        """
        errors: list[str] = []
        warnings: list[str] = []
        check_messages: list[str] = []

        # Get format-disabled line information from context
        disabled_line_indices = context.get("disabled_line_indices", set())
        block_start_index = context.get("block_start_index", 0)

        # Always detect phony targets (for check mode)
        detected_targets = PhonyAnalyzer.detect_phony_targets_excluding_conditionals(
            lines, disabled_line_indices, block_start_index
        )

        # Check if .PHONY declarations exist
        has_phony = MakefileParser.has_phony_declarations(lines)
        auto_insert_enabled = config.get("auto_insert_phony_declarations", False)
        group_phony = config.get("group_phony_declarations", True)

        if not has_phony:
            # No .PHONY exists - insert if enabled
            if not detected_targets:
                return FormatResult(
                    lines=lines,
                    changed=False,
                    errors=errors,
                    warnings=warnings,
                    check_messages=check_messages,
                )

            # In check mode, always report missing declarations
            if check_mode:
                phony_at_top = config.get("phony_at_top", True)
                gnu_format = config.get("_global", {}).get("gnu_error_format", True)
                ordered_targets = list(detected_targets)

                if phony_at_top:
                    insert_index = MakefileParser.find_phony_insertion_point(lines)
                    line_num = insert_index + 1
                else:
                    line_num = 1

                if auto_insert_enabled:
                    if gnu_format:
                        message = f"{line_num}: Warning: Missing .PHONY declaration for targets: {', '.join(ordered_targets)}"
                    else:
                        message = f"Warning: Missing .PHONY declaration for targets: {', '.join(ordered_targets)} (line {line_num})"
                else:
                    if gnu_format:
                        message = f"{line_num}: Warning: Consider adding .PHONY declaration for targets: {', '.join(ordered_targets)}"
                    else:
                        message = f"Warning: Consider adding .PHONY declaration for targets: {', '.join(ordered_targets)} (line {line_num})"

                check_messages.append(message)
                return FormatResult(
                    lines=lines,
                    changed=auto_insert_enabled,
                    errors=errors,
                    warnings=warnings,
                    check_messages=check_messages,
                )

            # Actually insert if enabled
            if not auto_insert_enabled:
                return FormatResult(
                    lines=lines,
                    changed=False,
                    errors=errors,
                    warnings=warnings,
                    check_messages=check_messages,
                )

            # Insert declarations
            return self._insert_phony_declarations(
                lines,
                list(detected_targets),
                config,
                errors,
                warnings,
                check_messages,
            )

        # .PHONY exists - enhance and organize
        existing_phony_targets = self._extract_phony_targets(lines)
        existing_phony_set = set(existing_phony_targets)

        # Find missing targets
        missing_targets = [t for t in detected_targets if t not in existing_phony_set]

        # In check mode, report missing targets
        if check_mode and missing_targets:
            gnu_format = config.get("_global", {}).get("gnu_error_format", True)
            phony_line_num = self._find_first_phony_line(lines)

            if auto_insert_enabled:
                if gnu_format:
                    message = f"{phony_line_num}: Warning: Missing targets in .PHONY declaration: {', '.join(missing_targets)}"
                else:
                    message = f"Warning: Missing targets in .PHONY declaration: {', '.join(missing_targets)} (line {phony_line_num})"
            else:
                if gnu_format:
                    message = f"{phony_line_num}: Warning: Consider adding targets to .PHONY declaration: {', '.join(missing_targets)}"
                else:
                    message = f"Warning: Consider adding targets to .PHONY declaration: {', '.join(missing_targets)} (line {phony_line_num})"

            check_messages.append(message)

        # Only organize .PHONY declarations (group/ungroup) if auto_insert_phony_declarations is enabled
        if not auto_insert_enabled:
            # If auto-insertion is disabled, don't modify existing .PHONY declarations
            # (but still report missing targets in check mode)
            return FormatResult(
                lines=lines,
                changed=False,
                errors=errors,
                warnings=warnings,
                check_messages=check_messages,
            )

        # Organize .PHONY declarations (group/ungroup)
        if group_phony:
            # Group mode: ensure all .PHONY declarations are grouped
            return self._group_phony_declarations(
                lines,
                existing_phony_set | detected_targets,
                missing_targets if auto_insert_enabled else [],
                config,
                check_mode,
                errors,
                warnings,
                check_messages,
            )
        else:
            # Ungroup mode: ensure all .PHONY declarations are individual
            return self._ungroup_phony_declarations(
                lines,
                existing_phony_set | detected_targets,
                missing_targets if auto_insert_enabled else [],
                config,
                check_mode,
                errors,
                warnings,
                check_messages,
            )

    def _insert_phony_declarations(
        self,
        lines: list[str],
        target_names: list[str],
        config: dict,
        errors: list[str],
        warnings: list[str],
        check_messages: list[str],
    ) -> FormatResult:
        """Insert .PHONY declarations for detected targets."""
        group_phony = config.get("group_phony_declarations", True)
        phony_at_top = config.get("phony_at_top", True)

        if not group_phony:
            # Insert individual declarations before each target
            return self._insert_individual_phony_declarations(
                lines, target_names, config, errors, warnings, check_messages
            )

        # Insert grouped declaration
        new_phony_line = f".PHONY: {' '.join(target_names)}"

        if phony_at_top:
            insert_index = MakefileParser.find_phony_insertion_point(lines)
            formatted_lines = []
            for i, line in enumerate(lines):
                if i == insert_index:
                    formatted_lines.append(new_phony_line)
                    formatted_lines.append("")  # Add blank line after
                formatted_lines.append(line)
        else:
            formatted_lines = [new_phony_line, ""] + lines

        warnings.append(
            f"Auto-inserted .PHONY declaration for {len(target_names)} targets: {', '.join(target_names)}"
        )

        return FormatResult(
            lines=formatted_lines,
            changed=True,
            errors=errors,
            warnings=warnings,
            check_messages=check_messages,
        )

    def _insert_individual_phony_declarations(
        self,
        lines: list[str],
        target_names: list[str],
        config: dict,
        errors: list[str],
        warnings: list[str],
        check_messages: list[str],
    ) -> FormatResult:
        """Insert individual .PHONY declarations before each target."""
        target_positions = self._find_target_line_positions(lines, target_names)

        if not target_positions:
            return FormatResult(
                lines=lines,
                changed=False,
                errors=errors,
                warnings=warnings,
                check_messages=check_messages,
            )

        # Sort targets by position in reverse order for insertion
        sorted_targets = sorted(
            target_positions.items(), key=lambda x: x[1], reverse=True
        )

        formatted_lines = lines[:]
        inserted_targets = []

        for target_name, line_index in sorted_targets:
            if not self._has_phony_declaration_nearby(
                formatted_lines, line_index, target_name
            ):
                formatted_lines.insert(line_index, f".PHONY: {target_name}")
                inserted_targets.append(target_name)

        if inserted_targets:
            warnings.append(
                f"Auto-inserted individual .PHONY declarations for {len(inserted_targets)} targets: {', '.join(inserted_targets)}"
            )

        return FormatResult(
            lines=formatted_lines,
            changed=len(inserted_targets) > 0,
            errors=errors,
            warnings=warnings,
            check_messages=check_messages,
        )

    def _group_phony_declarations(
        self,
        lines: list[str],
        all_phony_targets: set[str],
        new_targets: list[str],
        config: dict,
        check_mode: bool,
        errors: list[str],
        warnings: list[str],
        check_messages: list[str],
    ) -> FormatResult:
        """Group all .PHONY declarations into a single declaration."""
        # Order targets by declaration order
        ordered_targets = self._order_targets_by_declaration(all_phony_targets, lines)

        if check_mode:
            # In check mode, only report if there are new targets or if declarations need grouping
            has_multiple_phony = (
                sum(1 for line in lines if line.strip().startswith(".PHONY:")) > 1
            )
            changed = len(new_targets) > 0 or has_multiple_phony
            return FormatResult(
                lines=lines,
                changed=changed,
                errors=errors,
                warnings=warnings,
                check_messages=check_messages,
            )

        # Build grouped declaration
        phony_line = f".PHONY: {' '.join(ordered_targets)}"
        phony_at_top = config.get("phony_at_top", True)

        # Remove all existing .PHONY declarations first
        lines_without_phony = []
        for line in lines:
            if not line.strip().startswith(".PHONY:"):
                lines_without_phony.append(line)

        # Insert grouped declaration at the appropriate location
        if phony_at_top:
            # Use smart placement (same logic as when inserting new .PHONY)
            insert_index = MakefileParser.find_phony_insertion_point(
                lines_without_phony
            )
            formatted_lines = []
            for i, line in enumerate(lines_without_phony):
                if i == insert_index:
                    formatted_lines.append(phony_line)
                    formatted_lines.append("")  # Add blank line after
                formatted_lines.append(line)
        else:
            # Place at absolute top
            formatted_lines = [phony_line, ""] + lines_without_phony

        if new_targets:
            warnings.append(
                f"Added {len(new_targets)} missing targets to .PHONY declaration: {', '.join(new_targets)}"
            )

        return FormatResult(
            lines=formatted_lines,
            changed=True,
            errors=errors,
            warnings=warnings,
            check_messages=check_messages,
        )

    def _ungroup_phony_declarations(
        self,
        lines: list[str],
        all_phony_targets: set[str],
        new_targets: list[str],
        config: dict,
        check_mode: bool,
        errors: list[str],
        warnings: list[str],
        check_messages: list[str],
    ) -> FormatResult:
        """Split grouped .PHONY declarations into individual declarations."""
        # Find all .PHONY line indices
        phony_line_indices = []
        for i, line in enumerate(lines):
            if line.strip().startswith(".PHONY:"):
                phony_line_indices.append(i)

        if not phony_line_indices:
            return FormatResult(
                lines=lines,
                changed=False,
                errors=errors,
                warnings=warnings,
                check_messages=check_messages,
            )

        # Find target positions
        target_positions: dict[str, int] = {}
        target_pattern = re.compile(r"^([^:=]+):")

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or line.startswith("\t"):
                continue
            match = target_pattern.match(stripped)
            if match:
                target_name = match.group(1).strip().split()[0]
                if (
                    target_name in all_phony_targets
                    and target_name not in target_positions
                ):
                    target_positions[target_name] = i

        if check_mode:
            # In check mode, report if declarations need splitting
            has_grouped = any(
                len(line.strip()[7:].strip().split()) > 1
                for line in lines
                if line.strip().startswith(".PHONY:")
            )
            return FormatResult(
                lines=lines,
                changed=has_grouped or len(new_targets) > 0,
                errors=errors,
                warnings=warnings,
                check_messages=check_messages,
            )

        # Check if declarations are already individual (not grouped)
        has_grouped_declarations = any(
            len(line.strip()[7:].strip().split()) > 1
            for line in lines
            if line.strip().startswith(".PHONY:")
        )

        # If already individual and no new targets, no change needed
        if not has_grouped_declarations and not new_targets:
            return FormatResult(
                lines=lines,
                changed=False,
                errors=errors,
                warnings=warnings,
                check_messages=check_messages,
            )

        # Build new lines with individual declarations
        formatted_lines = []
        skip_indices = set(phony_line_indices)
        insertions: dict[int, str] = {}

        for target_name, target_line_index in target_positions.items():
            insertions[target_line_index] = f".PHONY: {target_name}"

        for i, line in enumerate(lines):
            if i in skip_indices:
                continue
            if i in insertions:
                formatted_lines.append(insertions[i])
            formatted_lines.append(line)

        # Only warn if we actually split grouped declarations (not if already individual)
        if has_grouped_declarations:
            warnings.append(
                f"Split grouped .PHONY declarations into {len(target_positions)} individual declarations"
            )
        elif new_targets:
            warnings.append(
                f"Added {len(new_targets)} missing targets to .PHONY declarations: {', '.join(new_targets)}"
            )

        return FormatResult(
            lines=formatted_lines,
            changed=True,
            errors=errors,
            warnings=warnings,
            check_messages=check_messages,
        )

    def _extract_phony_targets(self, lines: list[str]) -> list[str]:
        """Extract targets from existing .PHONY declarations."""
        phony_targets = []
        seen_targets = set()

        for line in lines:
            stripped = line.strip()
            if stripped.startswith(".PHONY:"):
                content = stripped[7:].strip()
                if content.endswith("\\"):
                    content = content[:-1].strip()
                targets = [t.strip() for t in content.split() if t.strip()]
                for target in targets:
                    if target not in seen_targets:
                        phony_targets.append(target)
                        seen_targets.add(target)

        return phony_targets

    def _order_targets_by_declaration(
        self, phony_targets: set[str], lines: list[str]
    ) -> list[str]:
        """Order phony targets by their declaration order in the file."""
        target_pattern = re.compile(r"^([^:=]+):")
        ordered_targets = []
        seen_targets = set()

        for line in lines:
            stripped = line.strip()
            if (
                not stripped
                or stripped.startswith("#")
                or line.startswith("\t")
                or stripped.startswith(".PHONY:")
            ):
                continue
            match = target_pattern.match(stripped)
            if match:
                target_name = match.group(1).strip().split()[0]
                if target_name in phony_targets and target_name not in seen_targets:
                    ordered_targets.append(target_name)
                    seen_targets.add(target_name)

        # Add any remaining targets
        for target in phony_targets:
            if target not in seen_targets:
                ordered_targets.append(target)

        return ordered_targets

    def _find_target_line_positions(
        self, lines: list[str], target_names: list[str]
    ) -> dict[str, int]:
        """Find the line index where each target appears."""
        target_positions: dict[str, int] = {}
        target_pattern = re.compile(r"^([^:=]+):(:?)\s*(.*)$")

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or line.startswith("\t"):
                continue
            match = target_pattern.match(stripped)
            if match:
                target_list = match.group(1).strip()
                is_double_colon = match.group(2) == ":"
                target_body = match.group(3).strip()

                if is_double_colon or "%" in target_list:
                    continue

                if re.match(r"^\s*[A-Z_][A-Z0-9_]*\s*[+:?]?=", target_body):
                    continue

                target_names_on_line = [
                    t.strip() for t in target_list.split() if t.strip()
                ]
                for target_name in target_names_on_line:
                    if (
                        target_name in target_names
                        and target_name not in target_positions
                    ):
                        target_positions[target_name] = i

        return target_positions

    def _has_phony_declaration_nearby(
        self, lines: list[str], target_line_index: int, target_name: str
    ) -> bool:
        """Check if there's already a .PHONY declaration for this target nearby."""
        start_check = max(0, target_line_index - 5)
        for i in range(start_check, target_line_index):
            line = lines[i].strip()
            if line.startswith(".PHONY:"):
                content = line[7:].strip()
                if content.endswith("\\"):
                    content = content[:-1].strip()
                targets = [t.strip() for t in content.split() if t.strip()]
                if target_name in targets:
                    return True
        return False

    def _find_first_phony_line(self, lines: list[str]) -> int:
        """Find the line number of the first .PHONY declaration."""
        for i, line in enumerate(lines):
            if line.strip().startswith(".PHONY:"):
                return i + 1  # 1-indexed
        return 1
