"""Tests for reversed assignment operator detection."""

from mbake.config import Config, FormatterConfig
from mbake.core.formatter import MakefileFormatter


class TestReversedAssignmentOperators:
    """Test detection of reversed assignment operators (=?, =:, =+)."""

    def test_detect_reversed_question_mark_operator(self):
        """Test detection of =? (should be ?=)."""
        config = Config(formatter=FormatterConfig())
        formatter = MakefileFormatter(config)

        test_content = """# Correct syntax
FOO ?= bar

# Typo - reversed symbols
FOO =? bar

# Another correct syntax
BAR := hello

# Another typo
BAR =: world

# Yet another typo
BAZ =+ value
"""
        lines = test_content.strip().split("\n")
        formatted_lines, errors, warnings = formatter.format_lines(lines)

        # Should have warnings for the reversed operators
        assert len(warnings) == 3

        # Check specific warning messages
        question_warning = next((w for w in warnings if "=?" in w), None)
        assert question_warning is not None
        assert "Line 5:" in question_warning  # Line 5 has the =? typo
        assert "FOO" in question_warning
        assert "did you mean '?='" in question_warning
        assert (
            "Make will treat this as a regular assignment with '?' as part of the value"
            in question_warning
        )

        colon_warning = next((w for w in warnings if "=:" in w), None)
        assert colon_warning is not None
        assert "Line 11:" in colon_warning  # Line 11 has the =: typo
        assert "BAR" in colon_warning
        assert "did you mean ':='" in colon_warning
        assert (
            "Make will treat this as a regular assignment with ':' as part of the value"
            in colon_warning
        )

        plus_warning = next((w for w in warnings if "=+" in w), None)
        assert plus_warning is not None
        assert "Line 14:" in plus_warning  # Line 14 has the =+ typo
        assert "BAZ" in plus_warning
        assert "did you mean '+='" in plus_warning
        assert (
            "Make will treat this as a regular assignment with '+' as part of the value"
            in plus_warning
        )

    def test_no_warnings_for_correct_operators(self):
        """Test that correct operators don't generate warnings."""
        config = Config(formatter=FormatterConfig())
        formatter = MakefileFormatter(config)

        test_content = """# All correct syntax
FOO ?= bar
BAR := hello
BAZ += value
QUX = simple
QUUX != not_equal
"""
        lines = test_content.strip().split("\n")
        formatted_lines, errors, warnings = formatter.format_lines(lines)

        # Should have no warnings for correct operators
        reversed_warnings = [
            w for w in warnings if "Possible typo in assignment operator" in w
        ]
        assert len(reversed_warnings) == 0

    def test_no_warnings_for_regular_assignments_with_operators_in_value(self):
        """Test that regular assignments with operators in the value don't trigger warnings."""
        config = Config(formatter=FormatterConfig())
        formatter = MakefileFormatter(config)

        test_content = """# Regular assignment with ? in value (should not warn)
FOO = bar?baz

# Regular assignment with : in value (should not warn)
BAR = http://example.com

# Regular assignment with + in value (should not warn)
BAZ = value+extra
"""
        lines = test_content.strip().split("\n")
        formatted_lines, errors, warnings = formatter.format_lines(lines)

        # Should have no warnings for regular assignments
        reversed_warnings = [
            w for w in warnings if "Possible typo in assignment operator" in w
        ]
        assert len(reversed_warnings) == 0

    def test_detect_reversed_operators_with_various_spacing(self):
        """Test detection of reversed operators with various spacing patterns."""
        config = Config(formatter=FormatterConfig())
        formatter = MakefileFormatter(config)

        test_content = """# Different spacing patterns
FOO = ? bar
BAR = : hello
BAZ = + value
QUX =?bar
QUUX =:hello
QUUUX =+value
"""
        lines = test_content.strip().split("\n")
        formatted_lines, errors, warnings = formatter.format_lines(lines)

        # Should detect all reversed operators regardless of spacing
        reversed_warnings = [
            w for w in warnings if "Possible typo in assignment operator" in w
        ]
        assert len(reversed_warnings) == 6

    def test_no_warnings_for_recipe_lines(self):
        """Test that recipe lines (starting with tab) don't trigger warnings."""
        config = Config(formatter=FormatterConfig())
        formatter = MakefileFormatter(config)

        test_content = """test:
	FOO = ? bar
	BAR = : hello
	BAZ = + value
"""
        lines = test_content.strip().split("\n")
        formatted_lines, errors, warnings = formatter.format_lines(lines)

        # Should have no warnings for recipe lines
        reversed_warnings = [
            w for w in warnings if "Possible typo in assignment operator" in w
        ]
        assert len(reversed_warnings) == 0

    def test_no_warnings_for_comments(self):
        """Test that comment lines don't trigger warnings."""
        config = Config(formatter=FormatterConfig())
        formatter = MakefileFormatter(config)

        test_content = """# FOO = ? bar
# BAR = : hello
# BAZ = + value
"""
        lines = test_content.strip().split("\n")
        formatted_lines, errors, warnings = formatter.format_lines(lines)

        # Should have no warnings for comment lines
        reversed_warnings = [
            w for w in warnings if "Possible typo in assignment operator" in w
        ]
        assert len(reversed_warnings) == 0

    def test_warning_message_format(self):
        """Test that warning messages have the correct format."""
        config = Config(formatter=FormatterConfig())
        formatter = MakefileFormatter(config)

        test_content = """FOO =? bar
"""
        lines = test_content.strip().split("\n")
        formatted_lines, errors, warnings = formatter.format_lines(lines)

        assert len(warnings) == 1
        warning = warnings[0]

        # Check warning format
        assert warning.startswith("Line 1:")
        assert "Possible typo in assignment operator '=?'" in warning
        assert "for variable 'FOO'" in warning
        assert "did you mean '?='?" in warning
        assert (
            "Make will treat this as a regular assignment with '?' as part of the value."
            in warning
        )

    def test_multiple_reversed_operators_in_same_file(self):
        """Test detection of multiple reversed operators in the same file."""
        config = Config(formatter=FormatterConfig())
        formatter = MakefileFormatter(config)

        test_content = """FOO =? bar
BAR =: hello
BAZ =+ value
QUX =? another
QUUX =: test
"""
        lines = test_content.strip().split("\n")
        formatted_lines, errors, warnings = formatter.format_lines(lines)

        # Should detect all 5 reversed operators
        reversed_warnings = [
            w for w in warnings if "Possible typo in assignment operator" in w
        ]
        assert len(reversed_warnings) == 5

        # Check that each line number is correct
        line_numbers = []
        for warning in reversed_warnings:
            # Extract line number from warning
            line_num = int(warning.split("Line ")[1].split(":")[0])
            line_numbers.append(line_num)

        assert sorted(line_numbers) == [1, 2, 3, 4, 5]

    def test_edge_case_no_space_after_reversed_operator(self):
        """Test edge case where there's no space after the reversed operator."""
        config = Config(formatter=FormatterConfig())
        formatter = MakefileFormatter(config)

        test_content = """FOO =?bar
BAR =:hello
BAZ =+value
"""
        lines = test_content.strip().split("\n")
        formatted_lines, errors, warnings = formatter.format_lines(lines)

        # Should detect reversed operators even without space after
        reversed_warnings = [
            w for w in warnings if "Possible typo in assignment operator" in w
        ]
        assert len(reversed_warnings) == 3

    def test_mixed_correct_and_incorrect_operators(self):
        """Test mix of correct and incorrect operators."""
        config = Config(formatter=FormatterConfig())
        formatter = MakefileFormatter(config)

        test_content = """# Correct operators
FOO ?= bar
BAR := hello
BAZ += value

# Incorrect operators
QUX =? wrong
QUUX =: wrong
QUUUX =+ wrong

# More correct operators
CORRECT1 ?= test
CORRECT2 := test
CORRECT3 += test
"""
        lines = test_content.strip().split("\n")
        formatted_lines, errors, warnings = formatter.format_lines(lines)

        # Should only warn about the 3 incorrect operators
        reversed_warnings = [
            w for w in warnings if "Possible typo in assignment operator" in w
        ]
        assert len(reversed_warnings) == 3

        # Check that warnings are for the correct lines
        warning_lines = []
        for warning in reversed_warnings:
            line_num = int(warning.split("Line ")[1].split(":")[0])
            warning_lines.append(line_num)

        # Lines 7, 8, 9 should have warnings (accounting for the comment lines)
        assert sorted(warning_lines) == [7, 8, 9]
