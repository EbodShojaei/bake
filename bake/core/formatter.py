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
    ) -> tuple[list[str], list[str]]:
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

        # --- PATCH START ---
        # Split lines into blocks: outside and inside define/endef
        formatted_lines = []
        all_errors = []
        in_define = False
        block: list[str] = []
        current_line_index = 0
        block_start_index = 0

        for line in original_lines:
            if line.strip().startswith("define ") or line.strip() == "define":
                in_define = True
                if block:
                    # Format previous block
                    block_lines, block_errors = self._format_block(
                        block,
                        check_only,
                        config_dict,
                        context,
                        disabled_regions,
                        original_lines,
                        block_start_index,
                    )
                    formatted_lines.extend(block_lines)
                    all_errors.extend(block_errors)
                    block = []
                formatted_lines.append(line)
                current_line_index += 1
                block_start_index = current_line_index
                continue
            if line.strip() == "endef":
                in_define = False
                formatted_lines.append(line)
                current_line_index += 1
                block_start_index = current_line_index
                continue
            if in_define:
                # Do not format lines inside define/endef
                formatted_lines.append(line)
            else:
                block.append(line)
            current_line_index += 1

        if block:
            block_lines, block_errors = self._format_block(
                block,
                check_only,
                config_dict,
                context,
                disabled_regions,
                original_lines,
                block_start_index,
            )
            formatted_lines.extend(block_lines)
            all_errors.extend(block_errors)
        # --- PATCH END ---

        return formatted_lines, all_errors

    def _format_block(
        self,
        block_lines: list[str],
        check_only: bool,
        config_dict: dict,
        context: dict,
        disabled_regions: list[FormatRegion],
        original_lines: list[str],
        block_start_index: int,
    ) -> tuple[list[str], list[str]]:
        lines = block_lines.copy()
        errors: list[str] = []

        # Create a mapping of lines in disabled regions
        disabled_line_indices = set()
        for region in disabled_regions:
            for i in range(region.start_line, region.end_line):
                disabled_line_indices.add(i)

        # Check if this entire block is within a disabled region
        block_disabled_lines = []
        for i, _line in enumerate(block_lines):
            line_index = block_start_index + i
            if line_index in disabled_line_indices:
                block_disabled_lines.append(i)

        # If entire block is disabled, skip formatting
        if len(block_disabled_lines) == len(block_lines):
            return block_lines, errors

        # Apply formatting rules in priority order
        for rule in self.rules:
            if self.config.debug:
                logger.debug(f"Applying rule: {rule.name}")

            try:
                # Handle format disable regions - only format lines not in disabled regions
                if disabled_line_indices:
                    lines_to_format: list[str] = []
                    line_mapping = {}  # Track original line indices

                    # Group consecutive non-disabled lines into segments
                    segments = []
                    current_segment: list[str] = []
                    for line_index, line in enumerate(lines):
                        global_line_index = block_start_index + line_index
                        if global_line_index not in disabled_line_indices:
                            # This line is not disabled
                            if not current_segment:
                                pass  # Start new segment
                            current_segment.append(line)
                            line_mapping[len(lines_to_format)] = line_index
                            lines_to_format.append(line)
                        else:
                            # This line is disabled
                            if current_segment:
                                segments.append(
                                    (
                                        current_segment.copy(),
                                        len(lines_to_format) - len(current_segment),
                                    )
                                )
                                current_segment = []

                    # Don't forget the last segment
                    if current_segment:
                        segments.append(
                            (
                                current_segment.copy(),
                                len(lines_to_format) - len(current_segment),
                            )
                        )

                    if lines_to_format:
                        # Format only the non-disabled lines
                        result = rule.format(
                            lines_to_format, config_dict, check_only, **context
                        )

                        # Process errors with proper line number formatting
                        for error in result.errors:
                            if ":" in error and error.split(":")[0].isdigit():
                                line_num = int(error.split(":")[0])
                                message = ":".join(error.split(":")[2:]).strip()
                                formatted_error = self._format_error(
                                    message, line_num, config_dict
                                )
                                errors.append(formatted_error)
                            else:
                                errors.append(error)

                        # Also collect check_messages when in check mode
                        if check_only:
                            for check_message in result.check_messages:
                                errors.append(check_message)

                        # Merge formatted lines back into original positions
                        formatted_lines_to_format = result.lines
                        new_lines = lines.copy()
                        for formatted_index, original_index in line_mapping.items():
                            if formatted_index < len(formatted_lines_to_format):
                                new_lines[original_index] = formatted_lines_to_format[
                                    formatted_index
                                ]

                        lines = new_lines
                else:
                    # No disabled regions, format normally
                    result = rule.format(lines, config_dict, check_only, **context)
                    lines = result.lines

                    # Process errors with proper line number formatting
                    for error in result.errors:
                        if ":" in error and error.split(":")[0].isdigit():
                            line_num = int(error.split(":")[0])
                            message = ":".join(error.split(":")[2:]).strip()
                            formatted_error = self._format_error(
                                message, line_num, config_dict
                            )
                            errors.append(formatted_error)
                        else:
                            errors.append(error)

                    # Also collect check_messages when in check mode
                    if check_only:
                        for check_message in result.check_messages:
                            errors.append(check_message)

            except Exception as e:
                error_msg = f"Error in rule {rule.name}: {e}"
                logger.error(error_msg)
                errors.append(error_msg)

        return lines, errors

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
