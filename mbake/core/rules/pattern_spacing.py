"""Pattern rule spacing rule for Makefiles."""

import re
from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.line_utils import LineUtils
from ...utils.rule_context import (
    RecipeTextLines,
    dangling_backslash_repairs,
    define_body_lines,
)


class PatternSpacingRule(FormatterPlugin):
    """Handles spacing in pattern rules and static pattern rules."""

    def __init__(self) -> None:
        super().__init__("pattern_spacing", priority=17)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Normalize spacing in pattern rules."""
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        space_after_colon = config.get("space_after_colon", True)

        # A backslash that whitespace follows does not continue the line (GNU
        # make manual 3.1.1, lines 762-769). That whitespace stays, except on
        # the lines of dangling_backslash_repairs, which WhitespaceRule makes
        # continue anyway when it removes trailing whitespace.
        hidden = context.get("disabled_region_lines") or {}
        repair = config.get("remove_trailing_whitespace", True)
        repairs: set[int] = set()
        if repair:
            repairs = dangling_backslash_repairs(lines, hidden)
        # make passes the text of a recipe's continuation lines to the shell,
        # also where it looks like a pattern rule (GNU make manual 5.1.1,
        # lines 2917-2925), so they are left as they are.
        recipe_text = RecipeTextLines(lines, hidden, repair)
        # A define body is the value of a variable, so its lines are left as
        # they are (GNU make manual 6.8, lines 4795-4799).
        body_lines = define_body_lines(lines, hidden, strip_dangling=repair)

        for index, line in enumerate(lines):
            # Skip empty lines, comments, recipe lines and define bodies
            stripped = line.strip()
            if (
                not stripped
                or stripped.startswith("#")
                or line.startswith("\t")
                or index in body_lines
                # A directive or a line of nothing but references and
                # function calls is no rule: the colon in 'vpath %.c src:lib'
                # or 'ifneq (,$(filter %.o:%.c,$(X)))' is text that make reads
                # as written (GNU make manual 4.5.2, lines 1823-1830; 7.2, lines 5386-5400).
                or LineUtils.directive_word(line) is not None
                or LineUtils.is_reference_only(stripped)
            ):
                formatted_lines.append(line)
                continue

            # Process pattern rule spacing
            keep_trailing = (
                LineUtils.has_dangling_backslash(line) and index not in repairs
            )
            new_line = self._format_pattern_rule(line, space_after_colon, keep_trailing)
            if new_line != line and index in recipe_text:
                new_line = line
            if new_line != line:
                changed = True
                formatted_lines.append(new_line)
            else:
                formatted_lines.append(line)

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=[],
        )

    def _format_pattern_rule(
        self, line: str, space_after_colon: bool, keep_trailing: bool = False
    ) -> str:
        """Format spacing in pattern rules.

        With keep_trailing, the whitespace at the end of the line stays.
        """
        # Handle static pattern rules with two colons: targets: pattern: prerequisites
        if re.search(r".*:\s*%.*\s*:\s*", line) and not re.search(r"[=]", line):
            static_pattern_match = re.match(
                r"^(\s*)([^:]+):\s*([^:]+)\s*:\s*(.*)$", line
            )
            if static_pattern_match:
                leading_whitespace = static_pattern_match.group(1)
                targets_part = static_pattern_match.group(2).rstrip()
                pattern_part = static_pattern_match.group(3).strip()
                prereqs_part = static_pattern_match.group(4).lstrip()
                if not keep_trailing:
                    prereqs_part = prereqs_part.rstrip()

                new_line = (
                    leading_whitespace
                    + f"{targets_part}: {pattern_part}: {prereqs_part}"
                )
                return new_line

        # Handle simple pattern rules: %.o: %.c
        elif re.search(r"%.*:", line) and line.count(":") == 1:
            pattern_match = re.match(r"^(\s*)([^:]+):(.*)$", line)
            if pattern_match:
                leading_whitespace = pattern_match.group(1)
                pattern_part = pattern_match.group(2).rstrip()
                prereqs_part = pattern_match.group(3)

                if space_after_colon:
                    if prereqs_part.startswith(" "):
                        prereqs_part = " " + prereqs_part.lstrip()
                    elif prereqs_part:
                        prereqs_part = " " + prereqs_part
                else:
                    prereqs_part = prereqs_part.lstrip()

                new_line = leading_whitespace + pattern_part + ":" + prereqs_part
                return new_line

        return line
