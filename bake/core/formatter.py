"""Main Makefile formatter that orchestrates all formatting rules."""

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Union

from ..config import Config
from ..plugins.base import FormatterPlugin
from ..utils import FormatDisableHandler
from .rules import (
    AssignmentSpacingRule,
    ConditionalRule,
    ContinuationRule,
    DuplicateTargetRule,
    FinalNewlineRule,
    PatternSpacingRule,
    PhonyDetectionRule,
    PhonyInsertionRule,
    PhonyRule,
    RecipeValidationRule,
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
        self.format_disable_handler = FormatDisableHandler()

        # Initialize all formatting rules with correct priority order
        self.rules: list[FormatterPlugin] = [
            # Error detection rules (run first on original line numbers)
            DuplicateTargetRule(),  # priority 5 - detect before any line modifications
            RecipeValidationRule(),  # priority 8 - validate recipe tabs before formatting
            # Basic formatting rules (high priority)
            WhitespaceRule(),  # priority 10
            TabsRule(),  # priority 20
            ShellFormattingRule(),  # priority 25
            AssignmentSpacingRule(),  # priority 30
            TargetSpacingRule(),  # priority 35
            PatternSpacingRule(),  # priority 37
            # PHONY-related rules (run in sequence)
            PhonyInsertionRule(),  # priority 39 - auto-insert first
            PhonyRule(),  # priority 40 - group/organize
            PhonyDetectionRule(),  # priority 41 - enhance after grouping
            # Advanced rules
            ContinuationRule(),  # priority 50
            ConditionalRule(),  # priority 55
            # Final cleanup rules (run last)
            FinalNewlineRule(),  # priority 70 - check final newline
        ]

        # Sort rules by priority
        self.rules.sort(key=lambda rule: rule.priority)

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
            tuple of (changed, errors)
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
            formatted_lines, errors = self.format_lines(
                lines, check_only, original_content
            )

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

    def format_lines(
        self,
        lines: Sequence[str],
        check_only: bool = False,
        original_content: Union[str, None] = None,
    ) -> tuple[list[str], list[str]]:
        """Format makefile lines and return formatted lines and errors."""
        # Convert to list for easier manipulation
        original_lines = list(lines)

        # Find regions where formatting is disabled
        disabled_regions = self.format_disable_handler.find_disabled_regions(
            original_lines
        )

        # Convert config to dict for rules
        config_dict = self.config.to_dict()["formatter"]
        # Add global config for rules that need it
        config_dict["_global"] = {
            "gnu_error_format": self.config.gnu_error_format,
            "wrap_error_messages": self.config.wrap_error_messages,
        }

        # Prepare context for rules that need original file information
        context: dict[str, Any] = {}
        if original_content is not None:
            context["original_content_ends_with_newline"] = original_content.endswith(
                "\n"
            )
            context["original_line_count"] = len(lines)

        formatted_lines = original_lines.copy()
        all_errors = []

        for rule in self.rules:
            result = rule.format(
                formatted_lines, config_dict, check_mode=check_only, **context
            )

            if result.changed:
                formatted_lines = result.lines

            # Always add any explicit errors from the rule (like duplicate targets)
            # Apply centralized formatting to these errors too
            for error in result.errors:
                # Check if error already has line number format (like "5: Error: ...")
                if ":" in error and error.split(":")[0].isdigit():
                    # Error already has line number, just apply formatting consistency
                    line_num = int(error.split(":")[0])
                    message = ":".join(
                        error.split(":")[2:]
                    ).strip()  # Remove "line: Error: " prefix
                    formatted_error = self._format_error(message, line_num, config_dict)
                    all_errors.append(formatted_error)
                else:
                    # Error without line number
                    all_errors.append(error)

            # In check mode, add check messages from rules as errors for CLI reporting
            if check_only:
                all_errors.extend(result.check_messages)

        # Apply final cleanup
        formatted_lines = self._final_cleanup(formatted_lines, config_dict)

        # Restore original content for disabled regions
        if disabled_regions:
            formatted_lines = self.format_disable_handler.apply_disabled_regions(
                original_lines, formatted_lines, disabled_regions
            )

        # Sort all errors by line number for consistent reporting
        if check_only:
            all_errors = self._sort_errors_by_line_number(all_errors)

        return formatted_lines, all_errors

    def _format_error(self, message: str, line_num: int, config: dict) -> str:
        """Format an error message with consistent GNU or traditional format."""
        gnu_format = config.get("_global", {}).get("gnu_error_format", True)

        if gnu_format:
            return f"{line_num}: Error: {message}"
        else:
            return f"Error: {message} (line {line_num})"

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

    def validate_lines(self, lines: Sequence[str]) -> list[str]:
        """Validate lines against formatting rules.

        Args:
            lines: Sequence of lines to validate

        Returns:
            List of validation errors
        """
        all_errors = []
        config_dict = self.config.to_dict()["formatter"]
        lines_list = list(lines)

        for rule in self.rules:
            try:
                errors = rule.validate(lines_list, config_dict)
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
        formatted_lines, errors = self.format_lines(lines, check_only=False)

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

    def _sort_errors_by_line_number(self, errors: list[str]) -> list[str]:
        """Sort errors by line number for consistent reporting."""

        def extract_line_number(error: str) -> int:
            try:
                # Extract line number from format "filename:line: Error: ..." or "line: Error: ..."
                if ":" in error:
                    parts = error.split(":")
                    for part in parts:
                        if part.strip().isdigit():
                            return int(part.strip())
                return 0  # Default if no line number found
            except (ValueError, IndexError):
                return 0

        return sorted(errors, key=extract_line_number)
