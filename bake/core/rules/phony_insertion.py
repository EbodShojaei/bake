"""Plugin for automatically inserting .PHONY declarations when missing."""

from bake.plugins.base import FormatResult, FormatterPlugin
from bake.utils.line_utils import MakefileParser, PhonyAnalyzer


class PhonyInsertionRule(FormatterPlugin):
    """Auto-insert .PHONY declarations when missing and enabled."""

    def __init__(self) -> None:
        super().__init__("phony_insertion", priority=39)

    def format(self, lines: list[str], config: dict) -> FormatResult:
        """Insert .PHONY declarations for detected phony targets."""
        if not config.get("auto_insert_phony_declarations", False):
            return FormatResult(lines=lines, changed=False, errors=[], warnings=[])

        errors: list[str] = []
        warnings: list[str] = []
        changed = False

        # Check if .PHONY already exists
        if MakefileParser.has_phony_declarations(lines):
            return FormatResult(
                lines=lines, changed=False, errors=errors, warnings=warnings
            )

        # Detect phony targets using dynamic analysis
        detected_targets = self._detect_phony_targets_dynamically(lines)

        if not detected_targets:
            return FormatResult(
                lines=lines, changed=False, errors=errors, warnings=warnings
            )

        # Insert .PHONY declaration at the top
        phony_at_top = config.get("phony_at_top", True)
        sorted_targets = sorted(detected_targets)
        new_phony_line = f".PHONY: {' '.join(sorted_targets)}"

        if phony_at_top:
            insert_index = MakefileParser.find_phony_insertion_point(lines)
            formatted_lines = []

            for i, line in enumerate(lines):
                if i == insert_index:
                    formatted_lines.append(new_phony_line)
                    formatted_lines.append("")  # Add blank line after
                    changed = True
                formatted_lines.append(line)
        else:
            # Add at the beginning
            formatted_lines = [new_phony_line, ""] + lines
            changed = True

        warnings.append(
            f"Auto-inserted .PHONY declaration for {len(detected_targets)} targets: {', '.join(sorted_targets)}"
        )

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
