"""Main Makefile formatter that orchestrates all formatting rules."""

import logging
from dataclasses import dataclass
from pathlib import Path

from ..config import Config
from ..plugins.base import FormatterPlugin
from .rules import (
    AssignmentSpacingRule,
    ConditionalRule,
    ContinuationRule,
    PatternSpacingRule,
    PhonyRule,
    ShellFormattingRule,
    TabsRule,
    TargetSpacingRule,
    WhitespaceRule,
)


@dataclass
class FormatterResult:
    """Result of formatting operation with content string."""

    content: str
    changed: bool
    errors: list[str]
    warnings: list[str]


logger = logging.getLogger(__name__)


class MakefileFormatter:
    """Main formatter class that applies all formatting rules."""

    def __init__(self, config: Config):
        """Initialize formatter with configuration."""
        self.config = config
        self.rules = self._initialize_rules()

    def _initialize_rules(self) -> list[FormatterPlugin]:
        """Initialize all formatting rules in proper order."""
        rules = [
            TabsRule(),
            ShellFormattingRule(),
            AssignmentSpacingRule(),
            PatternSpacingRule(),
            TargetSpacingRule(),
            ContinuationRule(),
            ConditionalRule(),
            PhonyRule(),
            WhitespaceRule(),
        ]

        # Sort by priority (lower number = higher priority)
        return sorted(rules, key=lambda r: r.priority)

    def register_rule(self, rule: FormatterPlugin) -> None:
        """Register a custom formatting rule."""
        self.rules.append(rule)
        self.rules.sort()
        logger.info(f"Registered custom rule: {rule.name}")

    def format_file(
        self, file_path: Path, check_only: bool = False
    ) -> tuple[bool, list[str]]:
        """Format a Makefile.

        Args:
            file_path: Path to the Makefile
            check_only: If True, only check formatting without modifying

        Returns:
            Tuple of (changed, errors)
        """
        if not file_path.exists():
            return False, [f"File not found: {file_path}"]

        try:
            # Read file
            with open(file_path, encoding="utf-8") as f:
                original_content = f.read()

            # Split into lines, preserving line endings
            lines = original_content.splitlines()

            # Apply formatting
            formatted_lines, errors = self.format_lines(lines)

            # Check if content changed
            formatted_content = "\n".join(formatted_lines)
            if (
                self.config.formatter.ensure_final_newline
                and not formatted_content.endswith("\n")
            ):
                formatted_content += "\n"

            changed = formatted_content != original_content

            if check_only:
                return changed, errors

            if changed:
                # Write formatted content back
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(formatted_content)

                if self.config.verbose:
                    logger.info(f"Formatted {file_path}")
            else:
                if self.config.verbose:
                    logger.info(f"No changes needed for {file_path}")

            return changed, errors

        except Exception as e:
            error_msg = f"Error processing {file_path}: {e}"
            logger.error(error_msg)
            return False, [error_msg]

    def format_lines(self, lines: list[str]) -> tuple[list[str], list[str]]:
        """Apply all formatting rules to lines.

        Args:
            lines: List of lines to format

        Returns:
            Tuple of (formatted_lines, errors)
        """
        current_lines = lines[:]
        all_errors = []

        # Convert config to dict for rules
        config_dict = self.config.to_dict()["formatter"]

        for rule in self.rules:
            try:
                if self.config.debug:
                    logger.debug(f"Applying rule: {rule.name}")

                result = rule.format(current_lines, config_dict)
                current_lines = result.lines
                all_errors.extend(result.errors)

                if result.warnings and self.config.verbose:
                    for warning in result.warnings:
                        logger.warning(f"{rule.name}: {warning}")

                if result.changed and self.config.debug:
                    logger.debug(f"Rule {rule.name} made changes")

            except Exception as e:
                error_msg = f"Error in rule {rule.name}: {e}"
                logger.error(error_msg)
                all_errors.append(error_msg)

        # Final cleanup
        current_lines = self._final_cleanup(current_lines, config_dict)

        return current_lines, all_errors

    def _final_cleanup(self, lines: list[str], config: dict) -> list[str]:
        """Apply final cleanup steps."""
        if not lines:
            return lines

        cleaned_lines = []

        # Normalize empty lines
        if config.get("normalize_empty_lines", True):
            max_empty = config.get("max_consecutive_empty_lines", 2)
            empty_count = 0

            for line in lines:
                if line.strip() == "":
                    empty_count += 1
                    if empty_count <= max_empty:
                        cleaned_lines.append(line)
                else:
                    empty_count = 0
                    cleaned_lines.append(line)
        else:
            cleaned_lines = lines

        # Remove trailing empty lines at end of file
        while cleaned_lines and cleaned_lines[-1].strip() == "":
            cleaned_lines.pop()

        return cleaned_lines

    def validate_file(self, file_path: Path) -> list[str]:
        """Validate a Makefile against formatting rules.

        Args:
            file_path: Path to the Makefile

        Returns:
            List of validation errors
        """
        if not file_path.exists():
            return [f"File not found: {file_path}"]

        try:
            with open(file_path, encoding="utf-8") as f:
                lines = f.read().splitlines()

            return self.validate_lines(lines)

        except Exception as e:
            return [f"Error reading {file_path}: {e}"]

    def validate_lines(self, lines: list[str]) -> list[str]:
        """Validate lines against formatting rules.

        Args:
            lines: List of lines to validate

        Returns:
            List of validation errors
        """
        all_errors = []
        config_dict = self.config.to_dict()["formatter"]

        for rule in self.rules:
            try:
                errors = rule.validate(lines, config_dict)
                all_errors.extend(errors)
            except Exception as e:
                all_errors.append(f"Error in rule {rule.name}: {e}")

        return all_errors

    def format(self, content: str) -> FormatterResult:
        """Format content string and return result.

        Args:
            content: Makefile content as string

        Returns:
            FormatterResult with formatted content
        """
        lines = content.splitlines()
        formatted_lines, errors = self.format_lines(lines)

        # Join lines back to content
        formatted_content = "\n".join(formatted_lines)
        if (
            self.config.formatter.ensure_final_newline
            and not formatted_content.endswith("\n")
        ):
            formatted_content += "\n"

        changed = formatted_content != content

        return FormatterResult(
            content=formatted_content, changed=changed, errors=errors, warnings=[]
        )
