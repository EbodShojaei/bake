"""Assignment alignment rule for Makefiles.

This rule aligns variable assignment operators in consecutive blocks of assignments,
making the Makefile more readable.
"""

import re
from collections.abc import Collection
from typing import Any, Optional

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.line_utils import LineUtils
from ...utils.rule_context import (
    define_body_lines,
    scan_makefile,
    significant_whitespace_lines,
)


class AssignmentAlignmentRule(FormatterPlugin):
    """Aligns assignment operators (=, :=, +=, ?=, !=) in consecutive variable assignments."""

    # Pattern to match variable assignments
    # Captures: variable_name, operator, value
    ASSIGNMENT_PATTERN = re.compile(
        r"^([A-Za-z_][A-Za-z0-9_]*)\s*(:=|\+=|\?=|!=|=)\s*(.*)"
    )

    def __init__(self) -> None:
        # Run after target_spacing (priority 18) to ensure VPATH normalization works correctly
        super().__init__("assignment_alignment", priority=19)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Align assignment operators in consecutive blocks of variable assignments."""
        align_assignments = config.get("align_variable_assignments", False)
        align_across_comments = config.get("align_across_comments", False)

        # If alignment is disabled, return lines unchanged
        if not align_assignments:
            return FormatResult(
                lines=lines,
                changed=False,
                errors=[],
                warnings=[],
                check_messages=[],
            )

        formatted_lines = list(lines)
        changed = False
        errors: list[str] = []
        warnings: list[str] = []
        check_messages: list[str] = []

        # Find and process assignment blocks. A define body is the value of a
        # variable, so its lines are left as they are (GNU make manual 6.8,
        # lines 4795-4799).
        hidden = context.get("disabled_region_lines") or {}
        remove_trailing_whitespace = config.get("remove_trailing_whitespace", True)
        body_lines = define_body_lines(
            lines, hidden, strip_dangling=remove_trailing_whitespace
        )
        # The trailing whitespace of a value is part of it (GNU make manual
        # 6.2.2, lines 4273-4288). WhitespaceRule judges it when it removes
        # trailing whitespace; otherwise only whitespace that make reads is
        # kept here, and the whitespace after a final backslash, which does
        # not continue the line (3.1.1, lines 762-769).
        value_lines: Optional[set[int]] = None
        if not remove_trailing_whitespace:
            value_lines = significant_whitespace_lines(
                lines, scan_makefile(lines, hidden), as_syntax=True
            )
            value_lines.update(
                index
                for index, line in enumerate(lines)
                if LineUtils.has_dangling_backslash(line)
            )
        blocks = self._find_assignment_blocks(
            lines, align_across_comments, body_lines, value_lines
        )

        for block in blocks:
            block_changed = self._align_block(formatted_lines, block)
            if block_changed:
                changed = True
                if check_mode:
                    start_line = block[0]["line_index"] + 1
                    end_line = block[-1]["line_index"] + 1
                    check_messages.append(
                        f"Lines {start_line}-{end_line}: Variable assignments would be aligned"
                    )

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=check_messages,
        )

    def _find_assignment_blocks(
        self,
        lines: list[str],
        align_across_comments: bool,
        body_lines: Collection[int] = (),
        value_lines: Optional[Collection[int]] = None,
    ) -> list[list[dict]]:
        """Find consecutive blocks of variable assignments.

        Args:
            lines: List of lines to analyze
            align_across_comments: If True, include comment lines in blocks
            body_lines: The indexes of the lines of define bodies, which end a
                block and are never aligned
            value_lines: The indexes of the lines whose trailing whitespace
                is kept, or None to keep it on every line

        Returns:
            List of blocks, where each block is a list of assignment info dicts
        """
        blocks: list[list[dict]] = []
        current_block: list[dict] = []
        in_continuation = False

        for i, line in enumerate(lines):
            stripped = line.strip()

            if i in body_lines:
                in_continuation = False
                if current_block:
                    blocks.append(current_block)
                    current_block = []
                continue

            # Track line continuations
            if in_continuation:
                if not stripped.endswith("\\"):
                    in_continuation = False
                continue

            # Skip recipe lines (lines starting with tab)
            if line.startswith("\t"):
                if current_block:
                    blocks.append(current_block)
                    current_block = []
                continue

            # Track conditional blocks - don't align across them
            if stripped.startswith(
                ("ifdef", "ifndef", "ifeq", "ifneq", "if ", "else", "endif")
            ):
                if current_block:
                    blocks.append(current_block)
                    current_block = []
                continue

            # Track if we're entering a target (colon without assignment)
            if (
                ":" in stripped
                and not re.search(r":=|\+=|\?=|!=", stripped)
                and re.match(r"^[A-Za-z_][A-Za-z0-9_.-]*\s*:", stripped)
            ):
                # It's a target definition, not a URL or path
                if current_block:
                    blocks.append(current_block)
                    current_block = []
                continue

            # Handle empty lines - they always break blocks
            if not stripped:
                if current_block:
                    blocks.append(current_block)
                    current_block = []
                continue

            # Handle comment lines
            if stripped.startswith("#"):
                if align_across_comments and current_block:
                    # Include comment in the block as a pass-through
                    current_block.append(
                        {
                            "line_index": i,
                            "is_comment": True,
                            "original": line,
                        }
                    )
                elif current_block:
                    # Comment breaks the block
                    blocks.append(current_block)
                    current_block = []
                continue

            # Check for variable assignment. The value keeps its trailing
            # whitespace, which make keeps too (GNU make manual 6.2.2, lines
            # 4273-4288).
            if value_lines is None or i in value_lines:
                match = self.ASSIGNMENT_PATTERN.match(line.lstrip())
            else:
                match = self.ASSIGNMENT_PATTERN.match(stripped)
            if match:
                var_name = match.group(1)
                operator = match.group(2)
                value = match.group(3)

                current_block.append(
                    {
                        "line_index": i,
                        "is_comment": False,
                        "var_name": var_name,
                        "operator": operator,
                        "value": value,
                        "original": line,
                    }
                )

                # Check for line continuation
                if stripped.endswith("\\"):
                    in_continuation = True
            else:
                # Non-assignment line breaks the block
                if current_block:
                    blocks.append(current_block)
                    current_block = []

        # Don't forget the last block
        if current_block:
            blocks.append(current_block)

        # Filter out blocks with fewer than 2 actual assignments
        return [
            block
            for block in blocks
            if sum(1 for item in block if not item.get("is_comment", False)) >= 2
        ]

    def _align_block(self, lines: list[str], block: list[dict]) -> bool:
        """Align assignment operators in a block.

        Args:
            lines: The full list of lines (will be modified in place)
            block: List of assignment info dicts for this block

        Returns:
            True if any changes were made
        """
        # Find the maximum variable name length (only from actual assignments)
        max_var_len = max(
            len(item["var_name"]) for item in block if not item.get("is_comment", False)
        )

        changed = False

        for item in block:
            if item.get("is_comment", False):
                # Keep comments as-is
                continue

            line_index = item["line_index"]
            var_name = item["var_name"]
            operator = item["operator"]
            value = item["value"]

            # Calculate padding needed
            padding = max_var_len - len(var_name)

            # Build the aligned line
            if value.strip():
                new_line = f"{var_name}{' ' * padding} {operator} {value}"
            else:
                new_line = f"{var_name}{' ' * padding} {operator}"

            if lines[line_index] != new_line:
                lines[line_index] = new_line
                changed = True

        return changed
