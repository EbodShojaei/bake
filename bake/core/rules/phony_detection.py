"""Plugin for enhancing existing .PHONY declarations with additional detected targets."""

from bake.plugins.base import FormatResult, FormatterPlugin
from bake.utils.line_utils import MakefileParser, PhonyAnalyzer


class PhonyDetectionRule(FormatterPlugin):
    """Enhance existing .PHONY declarations with additional detected phony targets."""

    def __init__(self) -> None:
        super().__init__("phony_detection", priority=41)

    def format(self, lines: list[str], config: dict) -> FormatResult:
        """Enhance existing .PHONY declarations with additional detected targets."""
        errors: list[str] = []
        warnings: list[str] = []
        changed = False

        # Only run if auto-insertion is enabled (same setting controls both features)
        if not config.get("auto_insert_phony_declarations", False):
            return FormatResult(
                lines=lines, changed=False, errors=errors, warnings=warnings
            )

        # Check if .PHONY already exists
        if not MakefileParser.has_phony_declarations(lines):
            return FormatResult(
                lines=lines, changed=False, errors=errors, warnings=warnings
            )

        # Get existing phony targets
        existing_phony_targets = MakefileParser.extract_phony_targets(lines)

        # Detect phony targets using the same dynamic analysis as PhonyInsertionRule
        detected_targets = self._detect_phony_targets_dynamically(lines)

        # Only add newly detected targets that weren't already in .PHONY
        new_targets = detected_targets - existing_phony_targets

        if not new_targets:
            return FormatResult(
                lines=lines, changed=False, errors=errors, warnings=warnings
            )

        # Update .PHONY line with new targets
        all_targets = existing_phony_targets | new_targets
        sorted_targets = sorted(all_targets)
        new_phony_line = f".PHONY: {' '.join(sorted_targets)}"

        # Replace existing .PHONY line
        formatted_lines = []
        for line in lines:
            if line.strip().startswith(".PHONY:"):
                formatted_lines.append(new_phony_line)
                changed = True
            else:
                formatted_lines.append(line)

        return FormatResult(
            lines=formatted_lines, changed=changed, errors=errors, warnings=warnings
        )

    def _detect_phony_targets_dynamically(self, lines: list[str]) -> set[str]:
        """Dynamically detect phony targets by analyzing their recipes."""
        targets = MakefileParser.parse_targets_and_recipes(lines)
        phony_targets = set()

        for target_name, recipe_lines in targets:
            if PhonyAnalyzer.is_target_phony(target_name, recipe_lines):
                phony_targets.add(target_name)

        return phony_targets
