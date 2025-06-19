"""Makefile formatting rules."""

from .assignment_spacing import AssignmentSpacingRule
from .conditionals import ConditionalRule
from .continuation import ContinuationRule
from .pattern_spacing import PatternSpacingRule
from .phony import PhonyRule
from .shell import ShellFormattingRule
from .tabs import TabsRule
from .target_spacing import TargetSpacingRule
from .whitespace import WhitespaceRule

__all__ = [
    "TabsRule",
    "AssignmentSpacingRule",
    "TargetSpacingRule",
    "PatternSpacingRule",
    "WhitespaceRule",
    "ContinuationRule",
    "PhonyRule",
    "ConditionalRule",
    "ShellFormattingRule",
]
