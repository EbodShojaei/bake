"""Formatting rules for Makefiles."""

from .assignment_spacing import AssignmentSpacingRule
from .conditionals import ConditionalRule
from .continuation import ContinuationRule
from .duplicate_targets import DuplicateTargetRule
from .pattern_spacing import PatternSpacingRule
from .phony import PhonyRule
from .phony_detection import PhonyDetectionRule
from .phony_insertion import PhonyInsertionRule
from .shell import ShellFormattingRule
from .tabs import TabsRule
from .target_spacing import TargetSpacingRule
from .whitespace import WhitespaceRule

__all__ = [
    "AssignmentSpacingRule",
    "ConditionalRule",
    "ContinuationRule",
    "DuplicateTargetRule",
    "PatternSpacingRule",
    "PhonyRule",
    "PhonyDetectionRule",
    "PhonyInsertionRule",
    "ShellFormattingRule",
    "TabsRule",
    "TargetSpacingRule",
    "WhitespaceRule",
]
