"""Unified PHONY declaration rule: detection, insertion, and grouping."""

import re
from collections.abc import Mapping, Sequence
from typing import Any, Optional

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.line_utils import (
    LineUtils,
    MakefileParser,
    PhonyAnalyzer,
    restore_line_breaks,
)
from ...utils.rule_context import (
    ENDEF,
    RECIPE,
    LineState,
    cleanup_readings,
    orphaned_recipe_lines,
    scan_makefile,
)


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
        # {index of a '# bake-format off' line: the lines it hides}
        hidden = context.get("disabled_region_lines") or {}

        # Always detect phony targets (for check mode)
        detected_targets = PhonyAnalyzer.detect_phony_targets_excluding_conditionals(
            lines, disabled_line_indices, block_start_index
        )
        # The order of the rules that define them, the same on every run (a
        # set has no order that survives a new process)
        ordered_detected = self._order_targets_by_declaration(
            set(detected_targets), lines
        )

        # Check if .PHONY declarations exist
        has_phony = MakefileParser.has_phony_declarations(lines)
        auto_insert_enabled = config.get("auto_insert_phony_declarations", False)
        group_phony = config.get("group_phony_declarations", True)

        # Leave the .PHONY lines as written when one holds CR, VT, FF, FS,
        # GS, RS, NEL, LS or PS inside it, for which the rules see a
        # stand-in (see protect_line_breaks; restoring changes only such a
        # line). make can read the character as part of a target name
        # ('.PHONY: b<FF> a' declares 'b<FF>'), and grouping or splitting
        # the line can move it to the end of a line, where make drops it
        # and the next run ends the line there.
        if (
            has_phony
            and not check_mode
            and any(
                line.strip().startswith(".PHONY:") and restore_line_breaks(line) != line
                for line in lines
            )
        ):
            return FormatResult(
                lines=lines,
                changed=False,
                errors=errors,
                warnings=warnings,
                check_messages=check_messages,
            )

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
                ordered_targets = ordered_detected

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
                ordered_detected,
                config,
                errors,
                warnings,
                check_messages,
                hidden,
            )

        # .PHONY exists - enhance and organize
        existing_phony_targets = self._extract_phony_targets(lines)
        existing_phony_set = set(existing_phony_targets)

        # Find missing targets
        missing_targets = [t for t in ordered_detected if t not in existing_phony_set]

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
                hidden,
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
                hidden,
            )

    def _insert_phony_declarations(
        self,
        lines: list[str],
        target_names: list[str],
        config: dict,
        errors: list[str],
        warnings: list[str],
        check_messages: list[str],
        hidden: Mapping[int, Sequence[str]],
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
            formatted_lines = self._insert_after_header(
                lines, new_phony_line, config, hidden
            )
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
        hidden: Mapping[int, Sequence[str]],
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
        removed = [
            i for i, line in enumerate(lines) if line.strip().startswith(".PHONY:")
        ]
        blanked = self._orphaned_recipe_lines(lines, removed, config, hidden)
        if blanked is None:
            # Another rule may need a line that a .PHONY line may own as its
            # empty recipe, so the .PHONY lines stay as they are.
            return FormatResult(
                lines=lines,
                changed=False,
                errors=errors,
                warnings=warnings,
                check_messages=check_messages,
            )
        lines_without_phony: list[str] = []
        # {index in lines: index in lines_without_phony}
        new_indexes: dict[int, int] = {}
        for i, line in enumerate(lines):
            if not line.strip().startswith(".PHONY:"):
                new_indexes[i] = len(lines_without_phony)
                lines_without_phony.append("" if i in blanked else line)

        # Insert grouped declaration at the appropriate location. A declaration
        # that owns whitespace-only recipe lines (blanked) moves as before.
        in_place = (
            None
            if blanked
            else self._declaration_in_place(lines, removed, phony_line, config, hidden)
        )
        if in_place is not None:
            # The declaration is already where inserting it would put it.
            formatted_lines = in_place
        elif phony_at_top:
            # Use smart placement (same logic as when inserting new .PHONY)
            formatted_lines = self._insert_after_header(
                lines_without_phony,
                phony_line,
                config,
                {
                    new_indexes[index]: region
                    for index, region in hidden.items()
                    if index in new_indexes
                },
            )
            if phony_line not in formatted_lines:
                # No place before a rule or variable: the rules of these
                # targets are hidden by '# bake-format off' or not in this
                # file. The declaration still tells make that the targets
                # are phony (GNU make manual 4.6, lines 2053-2056), so it
                # goes at the end instead of being lost.
                formatted_lines = formatted_lines + [phony_line]
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
        hidden: Mapping[int, Sequence[str]],
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
        blanked = self._orphaned_recipe_lines(lines, phony_line_indices, config, hidden)
        if blanked is None:
            # Another rule may need a line that a .PHONY line may own as its
            # empty recipe, so the .PHONY lines stay as they are.
            return FormatResult(
                lines=lines,
                changed=False,
                errors=errors,
                warnings=warnings,
                check_messages=check_messages,
            )
        insertions: dict[int, str] = {}

        for target_name, target_line_index in target_positions.items():
            insertions[target_line_index] = f".PHONY: {target_name}"

        for i, line in enumerate(lines):
            if i in skip_indices:
                # The targets of this declaration that have no rule in the
                # visible lines (hidden by '# bake-format off', or not in
                # this file) get no individual declaration, so theirs stays
                # here: make needs it to treat them as phony (GNU make
                # manual 4.6, lines 2053-2056).
                declared = self._phony_line_targets(line)
                kept = [t for t in declared if t not in target_positions]
                if kept == declared:
                    formatted_lines.append(line)
                elif kept:
                    formatted_lines.append(f".PHONY: {' '.join(kept)}")
                continue
            if i in insertions:
                formatted_lines.append(insertions[i])
            formatted_lines.append("" if i in blanked else line)

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

    @staticmethod
    def _insert_after_header(
        lines: list[str],
        phony_line: str,
        config: dict,
        hidden: Mapping[int, Sequence[str]],
    ) -> list[str]:
        """
        Insert the .PHONY line after the header of the file.

        The line goes where MakefileParser.find_phony_insertion_point finds,
        followed by a blank line. Inside a define body no blank line is added:
        there it would be part of the variable's value (GNU make manual 6.8,
        lines 4795-4799), and it would stay behind when a later run moves the
        .PHONY line. After a line of only whitespace, which can be an empty
        recipe that WhitespaceRule keeps (5.1, lines 2890-2891), a blank line
        goes before the .PHONY line as well, where blank lines are normalized:
        removing the .PHONY line on a later run leaves a blank line there.
        Blank lines are ignored (lines 2884-2886).
        """
        insert_index = MakefileParser.find_phony_insertion_point(lines)
        if insert_index >= len(lines):
            return list(lines)
        if PhonyRule._inside_define_body(lines, insert_index, hidden):
            block = [phony_line]
        elif (
            insert_index > 0
            and lines[insert_index - 1].isspace()
            and config.get("normalize_empty_lines", True)
        ):
            block = ["", phony_line, ""]
        else:
            block = [phony_line, ""]
        return lines[:insert_index] + block + lines[insert_index:]

    @staticmethod
    def _declaration_in_place(
        lines: list[str],
        removed: list[int],
        phony_line: str,
        config: dict,
        hidden: Mapping[int, Sequence[str]],
    ) -> Optional[list[str]]:
        """
        Return lines with the .PHONY line rewritten where it is, or None.

        Grouping removes every .PHONY line and inserts the grouped line,
        followed by a blank line, at the top of the file or after its header
        (see _insert_after_header). On the next run the blank line that the
        previous run put after the declaration stayed behind, and the line
        went in again before or after it (find_phony_insertion_point passes
        over a blank line unless it ends the header comments). So below the
        header the second run added a blank line before the declaration,
        even as the first line of a file that began with it, and with
        normalize_empty_lines off every run added one more blank line. When
        removing the only .PHONY line and the empty line after it, then
        inserting the grouped line, gives back the same lines, the
        declaration is already where it goes: only its text is replaced, and
        the next run changes nothing.

        Inserting it again would only add a blank line before or after it.
        make ignores blank lines (GNU make manual 3.1, lines 733-734; 5.1,
        lines 2884-2886) except in define bodies, where they are part of the
        value (6.8, lines 4795-4799 and 4806-4809), and the insertion adds
        none there. After a line that ends with a backslash, the blank line
        decides whether make reads the .PHONY line as part of that line (3.1,
        lines 730-733; 3.1.1, lines 762-769), so the declaration is inserted
        again there, as before, unless the insertion puts it right back after
        that line: then it would only gain a blank line below it.
        """
        if len(removed) != 1:
            return None
        index = removed[0]
        if index + 1 >= len(lines) or lines[index + 1] != "":
            return None
        # rstrip: until S7, WhitespaceRule strips the whitespace after a
        # dangling backslash, so the line continues in the output.
        if index > 0 and LineUtils.ends_with_continuation(lines[index - 1].rstrip()):
            without = lines[:index] + lines[index + 1 :]
            if MakefileParser.find_phony_insertion_point(without) != index:
                return None
        in_place = lines[:index] + [phony_line] + lines[index + 1 :]
        rest = lines[:index] + lines[index + 2 :]
        if not config.get("phony_at_top", True):
            return in_place if [phony_line, ""] + rest == in_place else None
        # Neither removed line is a '# bake-format off' line; the ones after
        # them move up by two.
        rest_hidden = {
            position if position < index else position - 2: region
            for position, region in hidden.items()
        }
        inserted = PhonyRule._insert_after_header(rest, phony_line, config, rest_hidden)
        return in_place if inserted == in_place else None

    @staticmethod
    def _inside_define_body(
        lines: list[str], index: int, hidden: Mapping[int, Sequence[str]]
    ) -> bool:
        """Check if make may read a line put before lines[index] in a define body."""
        if not any("define" in line for line in lines) and not any(
            "define" in line for region in hidden.values() for line in region
        ):
            return False
        state = scan_makefile(lines, hidden)[index]
        return (
            state.may_be_define_body or state.kind == ENDEF or ENDEF in state.readings
        )

    @staticmethod
    def _orphaned_recipe_lines(
        lines: list[str],
        removed: list[int],
        config: dict,
        hidden: Mapping[int, Sequence[str]],
    ) -> Optional[set[int]]:
        """
        Find the whitespace-only recipe lines that the removed .PHONY lines leave.

        They become blank lines (see orphaned_recipe_lines). None means that
        one of them may be the empty recipe of another rule, so that the
        .PHONY lines stay as they are (GNU make manual 5.1, lines 2881-2891;
        5.9, lines 4040-4055). The lines are read as WhitespaceRule reads
        them, so that the next run decides the same way.
        """
        if not removed:
            return set()
        strip_dangling = config.get("remove_trailing_whitespace", True)
        readings = cleanup_readings(lines, hidden, strip_dangling)
        if any(
            PhonyRule._owns_commands(read, states, removed) for read, states in readings
        ):
            return None
        return orphaned_recipe_lines(readings, removed)

    @staticmethod
    def _owns_commands(
        lines: Sequence[str], states: Sequence[LineState], removed: list[int]
    ) -> bool:
        """
        Check if make may read a command line as part of a removed .PHONY rule.

        A line that starts with the recipe prefix after a '.PHONY:' line, in
        its rule context, is a recipe line of .PHONY (GNU make manual 5.1,
        lines 2878-2884). Moving the '.PHONY:' line would leave that line
        without its rule: make then reads it with the rule before it, as a
        command of another target, or as makefile syntax, or stops with
        "recipe commences before first target" (lines 11292-11297). So the
        '.PHONY:' lines stay as they are. Lines of only whitespace are left
        to orphaned_recipe_lines, which knows when they may go.
        """
        targets = set(removed)
        for index, state in enumerate(states):
            if RECIPE not in state.readings or not lines[index].strip(" \t"):
                continue
            owners: frozenset[int]
            if state.recipe_owners is not None:
                owners = state.recipe_owners
            elif state.rule_line is not None:
                owners = frozenset({state.rule_line})
            else:
                owners = frozenset()
            if owners & targets:
                return True
        return False

    @staticmethod
    def _phony_line_targets(line: str) -> list[str]:
        """Return the targets named on one '.PHONY:' line, in order."""
        content = line.strip()[7:].strip()
        if content.endswith("\\"):
            content = content[:-1].strip()
        return [t.strip() for t in content.split() if t.strip()]

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

        # Add the remaining targets: first those that existing .PHONY lines
        # declare, in their declared order, then any others. A set gives no
        # stable order, and a declaration whose targets have no visible rule
        # must come back unchanged.
        for target in self._extract_phony_targets(lines):
            if target in phony_targets and target not in seen_targets:
                ordered_targets.append(target)
                seen_targets.add(target)
        for target in sorted(phony_targets):
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

                # Skip target-specific variable assignments of any form (GNU
                # make manual 6.11, lines 4938-4951). The upper-case pattern
                # also skips lines such as 'endif # clean: OPT = -O0'.
                if re.match(
                    r"^\s*[A-Z_][A-Z0-9_]*\s*[+:?]?=", target_body
                ) or LineUtils.is_target_specific_variable(stripped):
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
