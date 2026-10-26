"""Special target validation and formatting rule for Makefiles.

Line numbers refer to the GNU make 4.4.1 manual.
"""

import re
from typing import Any, Optional

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.line_utils import LineUtils
from .suffix_validation import is_suffix_rule_target, read_makefile, suffix_list

# The special targets of GNU make 4.4.1, those of section 4.9 (lines
# 2229-2429) with .NOTINTERMEDIATE of make 4.4 (lines 2279-2287), and .WAIT,
# which a makefile may also define as a target (5.4.1, lines 3351-3352 and
# 3376-3378). Like any target, each may appear in several rules: make merges
# the prerequisites of all of them (4.11, lines 2545-2548).
_SPECIAL_TARGETS = frozenset(
    {
        ".PHONY",
        ".SUFFIXES",
        ".DEFAULT",
        ".PRECIOUS",
        ".INTERMEDIATE",
        ".NOTINTERMEDIATE",
        ".SECONDARY",
        ".SECONDEXPANSION",
        ".DELETE_ON_ERROR",
        ".IGNORE",
        ".LOW_RESOLUTION_TIME",
        ".SILENT",
        ".EXPORT_ALL_VARIABLES",
        ".NOTPARALLEL",
        ".ONESHELL",
        ".POSIX",
        ".WAIT",
    }
)

# The special targets that get a warning without prerequisites: .PHONY only
# makes its prerequisites phony (lines 2236-2240). Without prerequisites,
# .IGNORE and .SILENT apply to every target (lines 2339-2344, 2383-2388).
_NEEDS_PREREQUISITES = frozenset({".PHONY"})

# A rule line that starts with a target of a dot and capitals, followed by
# its ':'
_SPECIAL_TARGET_RULE = re.compile(r"(\.[A-Z_]+):")


class SpecialTargetValidationRule(FormatterPlugin):
    """Validates special target usage and syntax."""

    def __init__(self) -> None:
        # Before RecipeValidationRule (priority 8), which leaves out the
        # lines it reports in check mode: this rule reads the lines as make
        # reads them, by their own numbers, in both modes
        super().__init__("special_target_validation", priority=7)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Validate special target declarations.

        Only rules count: '.DEFAULT_GOAL:=all' assigns a variable (GNU make
        manual 6.5, lines 4577-4579), as do the assignments of the other
        special variables (6.14), whatever the spacing. A target that starts
        with a dot is never the default goal (lines 1440-1447), so make reads
        an unknown one, such as '.KEEP_STATE', as an ordinary target that
        runs only when asked for: that gets a warning.
        """
        warnings: list[str] = []

        if any(line.startswith(".") for line in lines):
            hidden = context.get("disabled_region_lines") or {}
            reading = read_makefile(lines, hidden)
            # The suffix list, computed when a name is not a special target:
            # a known suffix is a suffix rule (lines 2431-2438)
            suffixes: Optional[frozenset[str]] = None
            suffixes_read = False
            for rule in reading.rules:
                if rule.line_index is None:
                    continue
                match = _SPECIAL_TARGET_RULE.match(rule.text)
                if match is None:
                    continue
                name = match.group(1)
                if name in _SPECIAL_TARGETS:
                    if name in _NEEDS_PREREQUISITES and not self._has_prerequisites(
                        rule.text, match.end()
                    ):
                        warnings.append(
                            LineUtils.format_error_message(
                                f"Special target '{name}' typically requires "
                                "prerequisites",
                                rule.line_index + 1,
                                config,
                                "Warning",
                            )
                        )
                    continue
                if not suffixes_read:
                    suffixes = suffix_list(reading)
                    suffixes_read = True
                if suffixes is None or is_suffix_rule_target(name, suffixes):
                    continue
                warnings.append(
                    LineUtils.format_error_message(
                        f"Unknown special target '{name}'",
                        rule.line_index + 1,
                        config,
                        "Warning",
                    )
                )

        return FormatResult(
            lines=list(lines),
            changed=False,
            errors=[],
            warnings=warnings,
            check_messages=[],
        )

    @staticmethod
    def _has_prerequisites(text: str, end: int) -> bool:
        """Check if a rule line has prerequisites after the ':' that ends at end.

        They end at the comment (GNU make manual 3.1, lines 730-737) and at a
        ';' that starts the recipe (4.2, lines 1488 and 1499-1503); a second
        ':' makes a double-colon rule (4.13).
        """
        comment = LineUtils.find_comment_start(text)
        rest = (text if comment is None else text[:comment])[end:]
        if rest.startswith(":"):
            rest = rest[1:]
        semicolon = LineUtils.find_unquoted_char(rest, ";")
        if semicolon is not None:
            rest = rest[:semicolon]
        return bool(rest.strip())
