"""Tests for GNU error format functionality."""

from bake.config import Config, FormatterConfig
from bake.core.formatter import MakefileFormatter


class TestGNUErrorFormat:
    """Test GNU standard error format."""

    def test_duplicate_target_error_format(self):
        """Test that duplicate target errors include line numbers."""
        config = Config(formatter=FormatterConfig(), gnu_error_format=True)
        formatter = MakefileFormatter(config)

        lines = [
            "# Makefile with duplicate targets",
            "default:",
            "\techo 'first default'",
            "",
            "default:",
            "\techo 'second default'",
        ]

        formatted_lines, errors = formatter.format_lines(lines)

        assert len(errors) == 1
        assert "5: Error: Duplicate target 'default'" in errors[0]
        assert "lines 2 and 5" in errors[0]

    def test_gnu_error_format_disabled(self):
        """Test that traditional error format works when GNU format is disabled."""
        config = Config(formatter=FormatterConfig(), gnu_error_format=False)
        formatter = MakefileFormatter(config)

        lines = [
            "# Makefile with duplicate targets",
            "default:",
            "\techo 'first default'",
            "",
            "default:",
            "\techo 'second default'",
        ]

        formatted_lines, errors = formatter.format_lines(lines)

        assert len(errors) == 1
        # Should still have line numbers but without the "2: Error:" prefix format
        assert "Duplicate target 'default'" in errors[0]
        assert "lines 2 and 5" in errors[0]

    def test_final_newline_error_format(self):
        """Test that final newline errors report correct line numbers."""
        config = Config(formatter=FormatterConfig(), gnu_error_format=True)
        formatter = MakefileFormatter(config)

        lines = ["target:", "\techo 'test'", "# last line without newline"]

        # Simulate original content without final newline
        original_content = "\n".join(lines)  # No final newline

        formatted_lines, errors = formatter.format_lines(
            lines, check_only=True, original_content=original_content
        )

        # Should report error at line 3 (the last line missing the newline)
        final_newline_errors = [e for e in errors if "Missing final newline" in e]
        assert len(final_newline_errors) == 1
        assert "3: Error: Missing final newline" in final_newline_errors[0]

    def test_combined_errors_line_numbers(self):
        """Test that multiple error types report correct original line numbers."""
        config = Config(formatter=FormatterConfig(), gnu_error_format=True)
        formatter = MakefileFormatter(config)

        lines = [
            "# Test file",
            "target:",
            "\techo 'first'",
            "",
            "target:",  # Duplicate at line 5
            "\techo 'second'",
            "# last line",  # Missing final newline at line 7
        ]

        # Simulate original content without final newline
        original_content = "\n".join(lines)  # No final newline

        formatted_lines, errors = formatter.format_lines(
            lines, check_only=True, original_content=original_content
        )

        # Should have both duplicate target and missing newline errors
        duplicate_errors = [e for e in errors if "Duplicate target" in e]
        newline_errors = [e for e in errors if "Missing final newline" in e]

        assert len(duplicate_errors) == 1
        assert len(newline_errors) == 1

        # Check exact line numbers
        assert "5: Error: Duplicate target 'target'" in duplicate_errors[0]
        assert "lines 2 and 5" in duplicate_errors[0]
        assert "7: Error: Missing final newline" in newline_errors[0]

    def test_real_world_input_mk_scenario(self):
        """Test the exact scenario from input.mk to ensure console output matches expectations."""
        config = Config(formatter=FormatterConfig(), gnu_error_format=True)
        formatter = MakefileFormatter(config)

        # Simulate the exact structure from input.mk
        lines = [
            "# Test duplicate target detection in conditional blocks",
            "ifneq ($(SYSTEMC_EXISTS),)",
            "default: run",
            "else",
            "default: nosc",
            "endif",
            "",
            "# More content...",
            "clean:",
            "\trm -f *.o",
            "",
            "# Real duplicate targets (should be flagged)",
            "install:",
            '\techo "First install"',
            "",
            "install:",
            '\techo "Second install"',
        ]

        # Simulate original content without final newline (17 lines total)
        original_content = "\n".join(lines)  # No final newline

        formatted_lines, errors = formatter.format_lines(
            lines, check_only=True, original_content=original_content
        )

        # Should have both duplicate target and missing newline errors
        duplicate_errors = [e for e in errors if "Duplicate target" in e]
        newline_errors = [e for e in errors if "Missing final newline" in e]

        assert len(duplicate_errors) == 1
        assert len(newline_errors) == 1

        # Check exact line numbers match what user sees in console
        assert "16: Error: Duplicate target 'install'" in duplicate_errors[0]
        assert "lines 13 and 16" in duplicate_errors[0]
        assert "17: Error: Missing final newline" in newline_errors[0]

    def test_phony_insertion_check_messages(self):
        """Test that phony insertion generates check messages in check mode."""
        config = Config(
            formatter=FormatterConfig(auto_insert_phony_declarations=True),
            gnu_error_format=True,
        )
        formatter = MakefileFormatter(config)

        lines = [
            "# Simple makefile",
            "all: main",
            "\techo 'building'",
        ]

        # Simulate original content without final newline
        original_content = "\n".join(lines)  # No final newline

        formatted_lines, errors = formatter.format_lines(
            lines, check_only=True, original_content=original_content
        )

        # Should have both phony insertion and missing newline errors
        phony_errors = [e for e in errors if "Missing .PHONY declaration" in e]
        newline_errors = [e for e in errors if "Missing final newline" in e]

        assert len(phony_errors) == 1
        assert len(newline_errors) == 1

        # Check exact messages
        assert (
            "2: Error: Missing .PHONY declaration for targets: all" in phony_errors[0]
        )
        assert "3: Error: Missing final newline" in newline_errors[0]

    def test_phony_detection_check_messages(self):
        """Test that phony detection generates check messages for missing targets in existing .PHONY."""
        config = Config(
            formatter=FormatterConfig(auto_insert_phony_declarations=True),
            gnu_error_format=True,
        )
        formatter = MakefileFormatter(config)

        lines = [
            "# Makefile with incomplete .PHONY",
            ".PHONY: clean",
            "",
            "all: main",
            "\techo 'building'",
            "",
            "clean:",
            "\trm -f *.o",
            "",
            "install:",
            "\tcp main /usr/bin/",
        ]

        # Simulate original content without final newline
        original_content = "\n".join(lines)  # No final newline

        formatted_lines, errors = formatter.format_lines(
            lines, check_only=True, original_content=original_content
        )

        # Should have phony detection and missing newline errors
        phony_errors = [
            e for e in errors if "Missing targets in .PHONY declaration" in e
        ]
        newline_errors = [e for e in errors if "Missing final newline" in e]

        assert len(phony_errors) == 1
        assert len(newline_errors) == 1

        # Check exact messages
        assert (
            "2: Error: Missing targets in .PHONY declaration: all, install"
            in phony_errors[0]
        )
        assert "11: Error: Missing final newline" in newline_errors[0]
