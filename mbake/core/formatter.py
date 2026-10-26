"""Main Makefile formatter that orchestrates all formatting rules."""

import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Union

from ..config import Config
from ..plugins.base import FormatterPlugin
from ..utils import FormatDisableHandler, FormatRegion
from ..utils.line_utils import (
    normalize_newlines,
    protect_line_breaks,
    restore_line_breaks,
    split_makefile_lines,
)
from .rules import (
    AssignmentAlignmentRule,
    AssignmentSpacingRule,
    ConditionalRule,
    ContinuationRule,
    DuplicateTargetRule,
    FinalNewlineRule,
    PatternSpacingRule,
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

# Line numbers in rule messages, in each shape the rules use. Every group is a
# line number. Each pattern matches from the start of the message, so makefile
# text that a message quotes is never renumbered.
_GNU_LINE_PREFIX = re.compile(r"^(\d+)(?=:\s*(?:Warning|Error):)")
_TRADITIONAL_LINE_SUFFIX = re.compile(
    r"^(?:Warning|Error):.*\(line (\d+)\)$", re.DOTALL
)
_LINE_PREFIX = re.compile(r"^Line (\d+):")
_LINE_RANGE_PREFIX = re.compile(r"^Lines (\d+)-(\d+):")
# DuplicateTargetRule's message, in either format.
_DUPLICATE_TARGET_LINES = re.compile(
    r"^(?:\d+:\s*)?Error:\s*Duplicate target '.*' defined at lines (\d+) and (\d+)\. "
    r"Second definition will override the first\.",
    re.DOTALL,
)
_MESSAGE_LINE_NUMBER_PATTERNS = (
    _GNU_LINE_PREFIX,
    _TRADITIONAL_LINE_SUFFIX,
    _LINE_PREFIX,
    _LINE_RANGE_PREFIX,
    _DUPLICATE_TARGET_LINES,
)


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
            AssignmentAlignmentRule(),  # Align variable assignments
            TargetSpacingRule(),  # Format target lines
            PatternSpacingRule(),  # Format pattern rules
            # PHONY-related rules
            PhonyRule(),  # Unified: detect, insert, and organize .PHONY
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
    ) -> tuple[bool, list[str], list[str]]:
        """Format a Makefile.

        Args:
            file_path: Path to the Makefile
            check_only: If True, only check formatting without modifying

        Returns:
            tuple of (changed, errors, warnings)
        """
        if not file_path.exists():
            return False, [f"File not found: {file_path}"], []

        try:
            # Read the file without newline translation: make ends a line
            # only at a newline (GNU make manual 3.1.1, lines 757-758)
            with open(file_path, encoding="utf-8", newline="") as f:
                raw_content = f.read()

            lines = split_makefile_lines(raw_content)
            # Compare with the line endings normalized, as the universal
            # newline read did, so that a file whose only difference is its
            # line endings (such as CRLF) is left alone
            original_content = normalize_newlines(raw_content)

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
                return changed, errors, warnings

            if changed:
                # Write formatted content back
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(formatted_content)

                if self.config.verbose:
                    logger.info(f"Formatted {file_path}")
            else:
                if self.config.verbose:
                    logger.info(f"No changes needed for {file_path}")

            return changed, errors, warnings

        except Exception as e:
            error_msg = f"Error processing {file_path}: {e}"
            logger.error(error_msg)
            return False, [error_msg], []

    def format_lines(
        self,
        lines: Sequence[str],
        check_only: bool = False,
        original_content: Union[str, None] = None,
    ) -> tuple[list[str], list[str], list[str]]:
        """Format makefile lines and return formatted lines and errors.

        CR, VT, FF, FS, GS, RS, NEL, LS and PS inside a line are part of it
        for make (GNU make manual 3.1.1, lines 757-758). The rules see
        stand-ins for them (see protect_line_breaks), so they keep them where
        they are, and the lines and messages returned have them back.
        """
        protected = protect_line_breaks(lines)
        if protected is None:
            return self._format_lines(lines, check_only, original_content)
        formatted_lines, errors, warnings = self._format_lines(
            protected, check_only, original_content
        )
        return (
            [restore_line_breaks(line) for line in formatted_lines],
            [restore_line_breaks(error) for error in errors],
            [restore_line_breaks(warning) for warning in warnings],
        )

    def _format_lines(
        self,
        lines: Sequence[str],
        check_only: bool,
        original_content: Union[str, None],
    ) -> tuple[list[str], list[str], list[str]]:
        """Apply the rules to lines, as format_lines describes."""
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

        if disabled_regions:
            return self._format_lines_with_disabled_regions(
                original_lines, disabled_regions, config_dict, context, check_only
            )

        # Simplified formatting - apply rules directly to lines
        formatted_lines = original_lines.copy()
        all_errors = []
        all_warnings = []
        all_check_messages = []

        # Apply formatting rules in priority order
        for rule in self.rules:
            if self.config.debug:
                logger.debug(f"Applying rule: {rule.name}")

            try:
                # No disabled regions, format normally
                result = rule.format(
                    formatted_lines, config_dict, check_only, **context
                )
                formatted_lines = result.lines

                # Process errors, warnings, and check messages
                for error in result.errors:
                    formatted_error = self._format_error(error, 0, config_dict)
                    all_errors.append(formatted_error)

                for warning in result.warnings:
                    all_warnings.append(warning)

                # In check mode, also collect check_messages
                if check_only:
                    for check_msg in result.check_messages:
                        all_check_messages.append(check_msg)

            except Exception as e:
                error_msg = f"Error in rule {rule.name}: {e}"
                logger.error(error_msg)
                all_errors.append(error_msg)

        # In check mode, merge check_messages into warnings for display
        if check_only and all_check_messages:
            all_warnings.extend(all_check_messages)

        return formatted_lines, all_errors, all_warnings

    def _format_lines_with_disabled_regions(
        self,
        original_lines: list[str],
        disabled_regions: list[FormatRegion],
        config_dict: dict[str, Any],
        context: dict[str, Any],
        check_only: bool,
    ) -> tuple[list[str], list[str], list[str]]:
        """Format the lines outside '# bake-format off' regions.

        Rules see only the enabled lines, as before. After each rule, every
        region is put back right after its '# bake-format off' line instead of
        at its old index, so a rule that adds or removes lines cannot move,
        duplicate or drop lines around a region. The line changes of a rule
        that adds or removes '# bake-format' lines are skipped. Line numbers in
        the rule's messages are converted to lines of the whole file.
        """
        working, regions_by_marker = self._split_disabled_regions(
            original_lines, disabled_regions
        )
        all_errors: list[str] = []
        all_warnings: list[str] = []
        all_check_messages: list[str] = []

        # Apply formatting rules in priority order
        for rule in self.rules:
            if self.config.debug:
                logger.debug(f"Applying rule: {rule.name}")

            try:
                merged_lines, index_map, hidden_lines = self._merge_disabled_regions(
                    working, regions_by_marker
                )
                # Rules read it with context.get("disabled_region_lines") or {}:
                # {index of each '# bake-format off' line in their input: the
                # lines it hides, [] for none}. Each rule gets its own copy.
                rule_context = {**context, "disabled_region_lines": hidden_lines}
                result = rule.format(
                    list(working), config_dict, check_only, **rule_context
                )
                total_lines = len(merged_lines)

                # Process errors, warnings, and check messages
                for error in result.errors:
                    file_error = self._remap_message_lines(
                        error, index_map, total_lines
                    )
                    all_errors.append(self._format_error(file_error, 0, config_dict))

                for warning in result.warnings:
                    all_warnings.append(
                        self._remap_message_lines(warning, index_map, total_lines)
                    )

                # In check mode, also collect check_messages
                if check_only:
                    for check_msg in result.check_messages:
                        all_check_messages.append(
                            self._remap_message_lines(check_msg, index_map, total_lines)
                        )

                working = self._accept_rule_lines(rule.name, working, result.lines)

            except Exception as e:
                error_msg = f"Error in rule {rule.name}: {e}"
                logger.error(error_msg)
                all_errors.append(error_msg)

        # In check mode, merge check_messages into warnings for display
        if check_only and all_check_messages:
            all_warnings.extend(all_check_messages)

        formatted_lines = self._merge_disabled_regions(working, regions_by_marker)[0]
        return formatted_lines, all_errors, all_warnings

    def _split_disabled_regions(
        self, lines: list[str], disabled_regions: list[FormatRegion]
    ) -> tuple[list[str], dict[int, FormatRegion]]:
        """Split lines into the enabled lines and the regions they hide.

        Every region starts right after a '# bake-format off' line, which stays
        among the enabled lines. The regions are keyed by the ordinal of that
        line among all '# bake-format off' lines of the enabled lines.
        """
        regions_by_start = {region.start_line: region for region in disabled_regions}
        enabled_lines: list[str] = []
        regions_by_marker: dict[int, FormatRegion] = {}
        marker_ordinal = 0
        for index, line in enumerate(lines):
            if self._is_line_disabled(index, disabled_regions):
                continue
            enabled_lines.append(line)
            if self.format_disable_handler.disable_pattern.match(line):
                region = regions_by_start.get(index + 1)
                if region is not None:
                    regions_by_marker[marker_ordinal] = region
                marker_ordinal += 1
        return enabled_lines, regions_by_marker

    def _merge_disabled_regions(
        self, lines: list[str], regions_by_marker: dict[int, FormatRegion]
    ) -> tuple[list[str], list[int], dict[int, list[str]]]:
        """Put every disabled region back right after its '# bake-format off' line.

        Returns the merged lines, the index in the merged lines of each of
        ``lines``, and for each '# bake-format off' line of ``lines``, keyed by
        its index, the lines it hides (an empty list when it hides none).
        """
        merged_lines: list[str] = []
        index_map: list[int] = []
        hidden_lines: dict[int, list[str]] = {}
        marker_ordinal = 0
        for index, line in enumerate(lines):
            index_map.append(len(merged_lines))
            merged_lines.append(line)
            if self.format_disable_handler.disable_pattern.match(line):
                region = regions_by_marker.get(marker_ordinal)
                region_lines = region.original_lines if region is not None else []
                merged_lines.extend(region_lines)
                hidden_lines[index] = list(region_lines)
                marker_ordinal += 1
        return merged_lines, index_map, hidden_lines

    def _accept_rule_lines(
        self, rule_name: str, before: list[str], after: list[str]
    ) -> list[str]:
        """Return the enabled lines to keep after a rule ran on ``before``."""
        if after == before + [""]:
            # FinalNewlineRule's end-of-file line. For files with disabled
            # regions, format() and format_file() add the final newline.
            return before
        if self._count_markers(after) != self._count_markers(before):
            # Regions are anchored at the '# bake-format off' lines and end at
            # the next marker, so keep the previous lines.
            logger.debug(
                "Ignoring line changes from rule %s: it added or removed "
                "'# bake-format' lines",
                rule_name,
            )
            return before
        return list(after)

    def _count_markers(self, lines: Sequence[str]) -> tuple[int, int]:
        """Count the '# bake-format off' and '# bake-format on' lines."""
        handler = self.format_disable_handler
        off_count = sum(1 for line in lines if handler.disable_pattern.match(line))
        on_count = sum(1 for line in lines if handler.enable_pattern.match(line))
        return off_count, on_count

    @staticmethod
    def _remap_message_lines(
        message: str, index_map: Sequence[int], total_lines: int
    ) -> str:
        """Convert the line numbers in a rule message to lines of the file.

        Rules number the lines they were given, and those leave out the
        disabled regions; ``index_map[k]`` is the file index of line ``k + 1``.
        The last line and any line after it count from the end of the file, so
        end-of-file messages point at the real end of the file even when it
        ends inside a disabled region. Only the line numbers of the message
        shapes in _MESSAGE_LINE_NUMBER_PATTERNS change.
        """

        def to_file_line(number: int) -> int:
            if number < 1:
                return number
            if number < len(index_map):
                return index_map[number - 1] + 1
            return number - len(index_map) + total_lines

        # The patterns match different parts of a message, so the spans of
        # their groups never overlap.
        spans: list[tuple[int, int]] = []
        for pattern in _MESSAGE_LINE_NUMBER_PATTERNS:
            match = pattern.match(message)
            if match:
                spans.extend(
                    match.span(group) for group in range(1, pattern.groups + 1)
                )

        pieces: list[str] = []
        position = 0
        for start, end in sorted(spans):
            pieces.append(message[position:start])
            pieces.append(str(to_file_line(int(message[start:end]))))
            position = end
        pieces.append(message[position:])
        return "".join(pieces)

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
        # Check if message is already formatted (has line number at start)
        if re.match(r"^(\d+|Makefile:\d+):\s*(Warning|Error):", message):
            # Message is already formatted, return as-is
            return message

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
            with open(file_path, encoding="utf-8", newline="") as f:
                lines = split_makefile_lines(f.read())

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
        # The rules see stand-ins for line-break characters inside lines, as
        # in format_lines
        protected = protect_line_breaks(lines)
        lines_list = list(lines) if protected is None else protected

        for rule in self.rules:
            try:
                errors = rule.validate(lines_list, config_dict)
                all_errors.extend(errors)
            except Exception as e:
                all_errors.append(f"Error in rule {rule.name}: {e}")

        if protected is None:
            return all_errors
        return [restore_line_breaks(error) for error in all_errors]

    def format(self, content: str) -> FormatterResult:
        """Format content string and return result.

        Args:
            content: Makefile content as string

        Returns:
            FormatterResult with formatted content
        """
        lines = split_makefile_lines(content)
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
