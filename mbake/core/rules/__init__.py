"""Formatting rules for Makefiles."""

from .assignment_spacing import AssignmentSpacingRule
from .conditionals import ConditionalRule
from .continuation import ContinuationRule
from .duplicate_targets import DuplicateTargetRule
from .final_newline import FinalNewlineRule
from .pattern_spacing import PatternSpacingRule
from .phony import PhonyRule
from .phony_detection import PhonyDetectionRule
from .phony_insertion import PhonyInsertionRule
from .recipe_validation import RecipeValidationRule
from .rule_type_detection import RuleTypeDetectionRule
from .shell import ShellFormattingRule
from .special_target_validation import SpecialTargetValidationRule
from .suffix_validation import SuffixValidationRule
from .tabs import TabsRule
from .target_spacing import TargetSpacingRule
from .target_validation import TargetValidationRule
from .whitespace import WhitespaceRule

__all__ = [
    "AssignmentSpacingRule",
    "ConditionalRule",
    "ContinuationRule",
    "DuplicateTargetRule",
    "FinalNewlineRule",
    "PatternSpacingRule",
    "PhonyRule",
    "PhonyDetectionRule",
    "PhonyInsertionRule",
    "RecipeValidationRule",
    "RuleTypeDetectionRule",
    "ShellFormattingRule",
    "SpecialTargetValidationRule",
    "SuffixValidationRule",
    "TabsRule",
    "TargetSpacingRule",
    "TargetValidationRule",
    "WhitespaceRule",
]
