"""Main Makefile formatter that orchestrates all formatting rules."""

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from ..config import Config
from ..plugins.base import FormatterPlugin
from .rules import (
    AssignmentSpacingRule,
    ConditionalRule,
    ContinuationRule,
    DuplicateTargetRule,
    PatternSpacingRule,
    PhonyDetectionRule,
    PhonyInsertionRule,
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

        # Initialize all formatting rules with correct priority order
        self.rules: list[FormatterPlugin] = [
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
            DuplicateTargetRule(),  # priority 60
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
            formatted_lines, errors = self.format_lines(lines, check_only)

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
        self, lines: Sequence[str], check_only: bool = False
    ) -> tuple[list[str], list[str]]:
        """Format makefile lines and return formatted lines and errors."""
        # Convert config to dict for rules
        config_dict = self.config.to_dict()["formatter"]
        # Add global config for rules that need it
        config_dict["_global"] = {
            "gnu_error_format": self.config.gnu_error_format,
            "wrap_error_messages": self.config.wrap_error_messages,
        }

        formatted_lines = list(lines)
        all_errors = []

        for rule in self.rules:
            # Store lines before this rule
            lines_before = formatted_lines.copy()

            result = rule.format(formatted_lines, config_dict)

            if result.changed:
                formatted_lines = result.lines

                # Generate centralized error messages for changed lines ONLY in check mode
                if check_only:
                    change_errors = self._generate_change_errors(
                        lines_before, result.lines, rule.name, config_dict
                    )
                    all_errors.extend(change_errors)

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

        # Apply final cleanup and track changes
        lines_before_cleanup = formatted_lines.copy()
        formatted_lines = self._final_cleanup(formatted_lines, config_dict)

        # Generate errors for final cleanup changes ONLY in check mode
        if check_only and formatted_lines != lines_before_cleanup:
            cleanup_errors = self._generate_change_errors(
                lines_before_cleanup, formatted_lines, "final_cleanup", config_dict
            )
            all_errors.extend(cleanup_errors)

        return formatted_lines, all_errors

    def _generate_change_errors(
        self,
        before_lines: list[str],
        after_lines: list[str],
        rule_name: str,
        config: dict,
    ) -> list[str]:
        """Generate error messages for line changes with proper GNU formatting."""
        errors = []

        # Find changed lines
        max_len = max(len(before_lines), len(after_lines))

        for i in range(max_len):
            before_line = before_lines[i] if i < len(before_lines) else ""
            after_line = after_lines[i] if i < len(after_lines) else ""

            if before_line != after_line:
                # Generate error message describing the change
                line_num = i + 1

                if not before_line and after_line:
                    # Line was added
                    change_desc = f"Line added by {rule_name}: '{after_line.strip()}'"
                elif before_line and not after_line:
                    # Line was removed
                    change_desc = (
                        f"Line removed by {rule_name}: '{before_line.strip()}'"
                    )
                else:
                    # Line was modified - provide better description for whitespace changes
                    before_content = before_line.strip()
                    after_content = after_line.strip()

                    if before_content == after_content:
                        # Only whitespace/indentation changed
                        before_indent = (
                            before_line[: -len(before_content)]
                            if before_content
                            else before_line
                        )
                        after_indent = (
                            after_line[: -len(after_content)]
                            if after_content
                            else after_line
                        )

                        # Describe the indentation change
                        before_desc = self._describe_indentation(before_indent)
                        after_desc = self._describe_indentation(after_indent)

                        change_desc = f"Indentation changed by {rule_name}: {before_desc} → {after_desc} for '{before_content}'"
                    else:
                        # Content changed
                        change_desc = f"Line modified by {rule_name}: '{before_content}' → '{after_content}'"

                # Apply centralized error formatting
                formatted_error = self._format_error(change_desc, line_num, config)
                errors.append(formatted_error)

        return errors

    def _format_error(self, message: str, line_num: int, config: dict) -> str:
        """Format an error message with consistent GNU or traditional format."""
        gnu_format = config.get("_global", {}).get("gnu_error_format", True)

        if gnu_format:
            return f"{line_num}: Error: {message}"
        else:
            return f"Error: {message} (line {line_num})"

    def _describe_indentation(self, indent: str) -> str:
        """Describe indentation in a human-readable way."""
        if not indent:
            return "no indentation"

        tabs = indent.count("\t")
        spaces = indent.count(" ")

        parts = []
        if tabs:
            parts.append(f"{tabs} tab{'s' if tabs != 1 else ''}")
        if spaces:
            parts.append(f"{spaces} space{'s' if spaces != 1 else ''}")

        return " + ".join(parts) if parts else "no indentation"

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
