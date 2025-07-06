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
        block = []
        for line in original_lines:
            if line.strip().startswith("define ") or line.strip() == "define":
                in_define = True
                if block:
                    # Format previous block
                    block_lines, block_errors = self._format_block(block, check_only, config_dict, context)
                    formatted_lines.extend(block_lines)
                    all_errors.extend(block_errors)
                    block = []
                formatted_lines.append(line)
                continue
            if line.strip() == "endef":
                in_define = False
                formatted_lines.append(line)
                continue
            if in_define:
                # Do not format lines inside define/endef
                formatted_lines.append(line)
            else:
                block.append(line)
        if block:
            block_lines, block_errors = self._format_block(block, check_only, config_dict, context)
            formatted_lines.extend(block_lines)
            all_errors.extend(block_errors)
        # --- PATCH END ---
        return formatted_lines, all_errors

    def _format_block(self, block_lines, check_only, config_dict, context):
        lines = block_lines.copy()
        errors = []
        for rule in self.rules:
            result = rule.format(
                lines, config_dict, check_mode=check_only, **context
            )
            if result.changed:
                lines = result.lines
            for error in result.errors:
                if ":" in error and error.split(":")[0].isdigit():
                    line_num = int(error.split(":")[0])
                    message = ":".join(
                        error.split(":")[2:]
                    ).strip()
                    formatted_error = self._format_error(message, line_num, config_dict)
                    errors.append(formatted_error)
                else:
                    errors.append(error)
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
