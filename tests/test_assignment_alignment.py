"""Tests for variable assignment alignment rule."""

from pathlib import Path

import pytest

from mbake.config import Config, FormatterConfig
from mbake.core.formatter import MakefileFormatter
from mbake.core.rules.assignment_alignment import AssignmentAlignmentRule


def create_alignment_config(
    align_assignments: bool = True, align_across_comments: bool = False
) -> Config:
    """Create config with alignment settings."""
    return Config(
        formatter=FormatterConfig(
            auto_insert_phony_declarations=False,
            ensure_final_newline=False,
            align_variable_assignments=align_assignments,
            align_across_comments=align_across_comments,
        )
    )


class TestAssignmentAlignment:
    """Test variable assignment alignment."""

    def test_alignment_disabled_by_default(self):
        """Test that alignment is disabled when align_variable_assignments=False."""
        config = create_alignment_config(align_assignments=False)
        formatter = MakefileFormatter(config)

        input_lines = [
            "CC = gcc",
            "VERY_LONG = value",
        ]

        formatted_lines, errors, warnings = formatter.format_lines(input_lines)

        # Should not change when disabled
        assert "CC = gcc" in formatted_lines
        assert "VERY_LONG = value" in formatted_lines

    def test_basic_alignment(self):
        """Test basic variable alignment."""
        rule = AssignmentAlignmentRule()
        config = {"align_variable_assignments": True, "align_across_comments": False}

        input_lines = [
            "CC = gcc",
            "CXX := g++",
            "CFLAGS = -Wall",
        ]

        result = rule.format(input_lines, config)

        assert result.changed
        assert result.lines[0] == "CC     = gcc"
        assert result.lines[1] == "CXX    := g++"
        assert result.lines[2] == "CFLAGS = -Wall"

    def test_alignment_with_different_operators(self):
        """Test alignment with various assignment operators."""
        rule = AssignmentAlignmentRule()
        config = {"align_variable_assignments": True, "align_across_comments": False}

        input_lines = [
            "V1 := something",
            "VAR2 ?= something-else",
            "LONGER_VAR3 += -more",
            "V4 != $(shell echo hi)",
            "VAR5 = regular",
        ]

        result = rule.format(input_lines, config)

        assert result.changed
        # All variables should be aligned to the longest name
        assert result.lines[0] == "V1          := something"
        assert result.lines[1] == "VAR2        ?= something-else"
        assert result.lines[2] == "LONGER_VAR3 += -more"
        assert result.lines[3] == "V4          != $(shell echo hi)"
        assert result.lines[4] == "VAR5        = regular"

    def test_comments_break_blocks(self):
        """Test that comments break alignment blocks when align_across_comments=False."""
        rule = AssignmentAlignmentRule()
        config = {"align_variable_assignments": True, "align_across_comments": False}

        input_lines = [
            "SHORT = value",
            "VERYLONGNAME = another",
            "# comment",
            "AFTER = test",
            "LONGER_AFTER = second",
        ]

        result = rule.format(input_lines, config)

        assert result.changed
        # First block should be aligned
        assert result.lines[0] == "SHORT        = value"
        assert result.lines[1] == "VERYLONGNAME = another"
        # Comment preserved
        assert result.lines[2] == "# comment"
        # Second block should be aligned separately
        assert result.lines[3] == "AFTER        = test"
        assert result.lines[4] == "LONGER_AFTER = second"

    def test_align_across_comments(self):
        """Test that comments don't break blocks when align_across_comments=True."""
        rule = AssignmentAlignmentRule()
        config = {"align_variable_assignments": True, "align_across_comments": True}

        input_lines = [
            "SHORT = value",
            "# comment in the middle",
            "VERYLONGNAME = another",
        ]

        result = rule.format(input_lines, config)

        assert result.changed
        # All should be aligned together
        assert result.lines[0] == "SHORT        = value"
        assert result.lines[1] == "# comment in the middle"
        assert result.lines[2] == "VERYLONGNAME = another"

    def test_single_assignment_not_aligned(self):
        """Test that single assignments are not modified."""
        rule = AssignmentAlignmentRule()
        config = {"align_variable_assignments": True, "align_across_comments": False}

        input_lines = [
            "CC = gcc",
            "",
            "CXX := g++",
        ]

        result = rule.format(input_lines, config)

        # Single assignments (separated by empty lines) should not change
        assert not result.changed
        assert result.lines == input_lines

    def test_recipe_lines_not_aligned(self):
        """Test that recipe lines are not aligned."""
        rule = AssignmentAlignmentRule()
        config = {"align_variable_assignments": True, "align_across_comments": False}

        input_lines = [
            "CC = gcc",
            "CXX := g++",
            "all:",
            "\t@echo done",
        ]

        result = rule.format(input_lines, config)

        # Recipe line should be unchanged
        assert result.lines[3] == "\t@echo done"

    def test_empty_value_alignment(self):
        """Test alignment with empty values."""
        rule = AssignmentAlignmentRule()
        config = {"align_variable_assignments": True, "align_across_comments": False}

        input_lines = [
            "CC = gcc",
            "EMPTY =",
            "LONGER_NAME = value",
        ]

        result = rule.format(input_lines, config)

        assert result.changed
        assert result.lines[0] == "CC          = gcc"
        assert result.lines[1] == "EMPTY       ="
        assert result.lines[2] == "LONGER_NAME = value"

    def test_alignment_fixture(self):
        """Test the alignment fixture matches expected output."""
        config = create_alignment_config(align_assignments=True)
        formatter = MakefileFormatter(config)

        input_file = Path("tests/fixtures/assignment_alignment/input.mk")
        expected_file = Path("tests/fixtures/assignment_alignment/expected.mk")

        if input_file.exists() and expected_file.exists():
            input_lines = input_file.read_text(encoding="utf-8").splitlines()
            expected_lines = expected_file.read_text(encoding="utf-8").splitlines()

            formatted_lines, errors, warnings = formatter.format_lines(input_lines)

            assert not errors
            assert formatted_lines == expected_lines

    def test_alignment_comments_fixture(self):
        """Test the alignment across comments fixture matches expected output."""
        config = create_alignment_config(
            align_assignments=True, align_across_comments=True
        )
        formatter = MakefileFormatter(config)

        input_file = Path("tests/fixtures/assignment_alignment_comments/input.mk")
        expected_file = Path("tests/fixtures/assignment_alignment_comments/expected.mk")

        if input_file.exists() and expected_file.exists():
            input_lines = input_file.read_text(encoding="utf-8").splitlines()
            expected_lines = expected_file.read_text(encoding="utf-8").splitlines()

            formatted_lines, errors, warnings = formatter.format_lines(input_lines)

            assert not errors
            assert formatted_lines == expected_lines

    def test_conditional_blocks_break_alignment(self):
        """Test that conditional blocks break alignment."""
        rule = AssignmentAlignmentRule()
        config = {"align_variable_assignments": True, "align_across_comments": False}

        input_lines = [
            "VAR1 = value1",
            "LONGNAME = value2",
            "ifdef DEBUG",
            "VAR3 = value3",
            "endif",
            "VAR4 = value4",
        ]

        result = rule.format(input_lines, config)

        # First block aligned
        assert result.lines[0] == "VAR1     = value1"
        assert result.lines[1] == "LONGNAME = value2"
        # Conditional preserved
        assert result.lines[2] == "ifdef DEBUG"
        # Inside conditional - single var, no change
        assert result.lines[3] == "VAR3 = value3"
        assert result.lines[4] == "endif"
        # After conditional - single var, no change
        assert result.lines[5] == "VAR4 = value4"
