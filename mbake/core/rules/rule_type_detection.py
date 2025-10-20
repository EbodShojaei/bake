"""Rule type detection and classification for Makefiles."""

import re
from enum import Enum
from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin


class RuleType(Enum):
    EXPLICIT = "explicit"
    PATTERN = "pattern"
    SUFFIX = "suffix"
    STATIC_PATTERN = "static_pattern"
    DOUBLE_COLON = "double_colon"
    SPECIAL_TARGET = "special_target"


class RuleTypeDetectionRule(FormatterPlugin):
    """Detects and classifies different types of Makefile rules."""

    def __init__(self) -> None:
        super().__init__("rule_type_detection", priority=5)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Detect and classify rule types."""
        rule_types = {}

        for i, line in enumerate(lines):
            stripped = line.strip()
            if ":" in stripped and not line.startswith("\t"):
                rule_type = self._classify_rule(stripped, lines)
                rule_types[i] = rule_type

        # Store rule types in context for other rules to use
        context["rule_types"] = rule_types

        return FormatResult(
            lines=lines, changed=False, errors=[], warnings=[], check_messages=[]
        )

    def _classify_rule(self, line: str, all_lines: list[str]) -> RuleType:
        """Classify the type of rule."""
        # Special targets
        if line.startswith(".") and ":" in line:
            return RuleType.SPECIAL_TARGET

        # Double-colon rules
        if "::" in line:
            return RuleType.DOUBLE_COLON

        # Static pattern rules (targets: pattern: prerequisites)
        if re.search(r".*:\s*%.*\s*:\s*", line):
            return RuleType.STATIC_PATTERN

        # Pattern rules (%.o: %.c)
        if "%" in line and ":" in line:
            return RuleType.PATTERN

        # Suffix rules (.a.b:)
        if re.match(r"^\.[^:]+\.\w+:", line):
            return RuleType.SUFFIX

        # Default to explicit rule
        return RuleType.EXPLICIT
