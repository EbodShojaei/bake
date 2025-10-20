"""Main Makefile formatter that orchestrates all formatting rules."""

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Union

from ..config import Config
from ..plugins.base import FormatterPlugin
from ..utils import FormatDisableHandler, FormatRegion
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
    RuleTypeDetectionRule,
    ShellFormattingRule,
    SpecialTargetValidationRule,
    SuffixValidationRule,
    TabsRule,
    TargetSpacingRule,
    TargetValidationRule,
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

        # Complete rule system with all formatting rules
        self.rules: list[FormatterPlugin] = [
            # Rule type detection (run first)
            RuleTypeDetectionRule(),  # Detect rule types
            # Error detection rules
            DuplicateTargetRule(),  # Detect duplicate targets
            TargetValidationRule(),  # Validate target syntax
            RecipeValidationRule(),  # Validate recipe syntax
            SpecialTargetValidationRule(),  # Validate special targets
            SuffixValidationRule(),  # Validate suffix rules
            # Basic formatting rules
            WhitespaceRule(),  # Clean up whitespace
            TabsRule(),  # Ensure proper recipe tabs
            ShellFormattingRule(),  # Format shell commands
            AssignmentSpacingRule(),  # Format variable assignments
            TargetSpacingRule(),  # Format target lines
            PatternSpacingRule(),  # Format pattern rules
            # PHONY-related rules
            PhonyInsertionRule(),  # Auto-insert missing .PHONY
            PhonyRule(),  # Group and organize .PHONY
            PhonyDetectionRule(),  # Detect phony targets
            # Advanced rules
            ContinuationRule(),  # Handle line continuations
            ConditionalRule(),  # Format conditionals
            # Final cleanup
            FinalNewlineRule(),  # Ensure final newline
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
            formatted_lines, errors, warnings = self.format_lines(
                lines, check_only, original_content
            )

            # Check if content changed
            formatted_content = "\n".join(formatted_lines)

            # Find disabled regions to check if content is mostly disabled
            disabled_regions = self.format_disable_handler.find_disabled_regions(lines)

            # Check if the file is mostly or entirely in disabled regions
            total_lines = len(lines)
            disabled_line_count = 0
            for region in disabled_regions:
                disabled_line_count += region.end_line - region.start_line

            # If most content is disabled, preserve original newline behavior
            mostly_disabled = disabled_line_count >= (
                total_lines - 1
            )  # -1 to account for the format disable comment itself

            # Only add final newline if ensure_final_newline is true AND content isn't mostly disabled
            should_add_newline = (
                self.config.formatter.ensure_final_newline
                and not formatted_content.endswith("\n")
                and not mostly_disabled
            )

            if should_add_newline and formatted_lines:
                formatted_content += "\n"
            elif mostly_disabled:
                # For mostly disabled files, preserve original newline behavior exactly
                original_ends_with_newline = original_content.endswith("\n")
                if original_ends_with_newline and not formatted_content.endswith("\n"):
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
    ) -> tuple[list[str], list[str], list[str]]:
        """Format makefile lines and return formatted lines and errors."""
        # Convert to list for easier manipulation
        original_lines = list(lines)

        # Find regions where formatting is disabled
        disabled_regions = self.format_disable_handler.find_disabled_regions(
            original_lines
        )

        config_dict = self.config.to_dict()["formatter"]
        config_dict["_global"] = {
            "gnu_error_format": self.config.gnu_error_format,
            "wrap_error_messages": self.config.wrap_error_messages,
        }

        context: dict[str, Any] = {}
        if original_content is not None:
            context["original_content_ends_with_newline"] = original_content.endswith(
                "\n"
            )
            context["original_line_count"] = len(lines)

        # Simplified formatting - apply rules directly to lines
        formatted_lines = original_lines.copy()
        all_errors = []
        all_warnings = []

        # Apply formatting rules in priority order
        for rule in self.rules:
            if self.config.debug:
                logger.debug(f"Applying rule: {rule.name}")

            try:
                # Handle format disable regions
                if disabled_regions:
                    # Only format lines not in disabled regions
                    lines_to_format = []
                    line_mapping = {}

                    for i, line in enumerate(formatted_lines):
                        if not self._is_line_disabled(i, disabled_regions):
                            lines_to_format.append(line)
                            line_mapping[len(lines_to_format) - 1] = i

                    if lines_to_format:
                        result = rule.format(
                            lines_to_format, config_dict, check_only, **context
                        )

                        # Process errors and warnings
                        for error in result.errors:
                            formatted_error = self._format_error(error, 0, config_dict)
                            all_errors.append(formatted_error)

                        for warning in result.warnings:
                            all_warnings.append(warning)

                        # Merge formatted lines back
                        for formatted_index, original_index in line_mapping.items():
                            if formatted_index < len(result.lines):
                                formatted_lines[original_index] = result.lines[
                                    formatted_index
                                ]
                else:
                    # No disabled regions, format normally
                    result = rule.format(
                        formatted_lines, config_dict, check_only, **context
                    )
                    formatted_lines = result.lines

                    # Process errors and warnings
                    for error in result.errors:
                        formatted_error = self._format_error(error, 0, config_dict)
                        all_errors.append(formatted_error)

                    for warning in result.warnings:
                        all_warnings.append(warning)

            except Exception as e:
                error_msg = f"Error in rule {rule.name}: {e}"
                logger.error(error_msg)
                all_errors.append(error_msg)

        return formatted_lines, all_errors, all_warnings

    def _is_line_disabled(
        self, line_index: int, disabled_regions: list[FormatRegion]
    ) -> bool:
        """Check if a line is in a disabled region."""
        for region in disabled_regions:
            if region.start_line <= line_index < region.end_line:
                return True
        return False

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
        formatted_lines, errors, warnings = self.format_lines(lines, check_only=False)

        # Join lines back to content
        formatted_content = "\n".join(formatted_lines)

        # Only add final newline if ensure_final_newline is true AND
        # the final line is not a format disable comment (which should be preserved exactly)
        should_add_newline = (
            self.config.formatter.ensure_final_newline
            and not formatted_content.endswith("\n")
        )

        if should_add_newline and formatted_lines:
            # Check if the final line is a format disable comment
            final_line = formatted_lines[-1]
            if self.format_disable_handler.is_format_disabled_line(final_line):
                # For format disable comments, preserve original file's newline behavior
                original_ends_with_newline = content.endswith("\n")
                if original_ends_with_newline:
                    formatted_content += "\n"
            else:
                # Regular line, apply ensure_final_newline setting
                formatted_content += "\n"

        changed = formatted_content != content

        return FormatterResult(
            content=formatted_content, changed=changed, errors=errors, warnings=warnings
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
