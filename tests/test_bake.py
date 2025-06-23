"""Tests for the Makefile formatter."""

from bake.config import Config, FormatterConfig
from bake.core.formatter import MakefileFormatter
from bake.core.rules import (
    AssignmentSpacingRule,
    ContinuationRule,
    PhonyRule,
    TabsRule,
    TargetSpacingRule,
    WhitespaceRule,
)


class TestTabsRule:
    """Test the tabs formatting rule."""

    def test_converts_spaces_to_tabs(self):
        rule = TabsRule()
        config = {"tab_width": 4}
        lines = [
            "target:",
            "    echo 'hello'",  # 4 spaces
            "        echo 'world'",  # 8 spaces
        ]

        result = rule.format(lines, config)

        assert result.changed
        assert result.lines == ["target:", "\techo 'hello'", "\t\techo 'world'"]

    def test_preserves_existing_tabs(self):
        rule = TabsRule()
        config = {"tab_width": 4}
        lines = ["target:", "\techo 'hello'", "\t\techo 'world'"]

        result = rule.format(lines, config)

        assert not result.changed
        assert result.lines == lines

    def test_handles_mixed_indentation(self):
        rule = TabsRule()
        config = {"tab_width": 4}
        lines = ["target:", "  \techo 'mixed'"]  # 2 spaces + 1 tab = 6 total

        result = rule.format(lines, config)

        assert result.changed
        assert result.lines == ["target:", "\techo 'mixed'"]  # Clean up to single tab


class TestAssignmentSpacingRule:
    """Test the assignment spacing formatting rule."""

    def test_normalizes_assignment_spacing(self):
        rule = AssignmentSpacingRule()
        config = {"space_around_assignment": True}
        lines = ["VAR:=value", "VAR2= value", "VAR3 =value"]

        result = rule.format(lines, config)

        assert result.changed
        assert result.lines == ["VAR := value", "VAR2 = value", "VAR3 = value"]

    def test_removes_assignment_spacing(self):
        rule = AssignmentSpacingRule()
        config = {"space_around_assignment": False}
        lines = ["VAR := value", "VAR2 = value"]

        result = rule.format(lines, config)

        assert result.changed
        assert result.lines == ["VAR:=value", "VAR2=value"]


class TestTargetSpacingRule:
    """Test the target colon spacing formatting rule."""

    def test_normalizes_colon_spacing(self):
        rule = TargetSpacingRule()
        config = {"space_before_colon": False, "space_after_colon": True}
        lines = [
            "target :dependencies",
            "target2:  dependencies2",
            "target3 : dependencies3",
        ]

        result = rule.format(lines, config)

        assert result.changed
        assert result.lines == [
            "target: dependencies",
            "target2: dependencies2",
            "target3: dependencies3",
        ]


class TestWhitespaceRule:
    """Test the whitespace cleanup rule."""

    def test_removes_trailing_whitespace(self):
        rule = WhitespaceRule()
        config = {"remove_trailing_whitespace": True}
        lines = ["line1  ", "line2\t", "line3"]

        result = rule.format(lines, config)

        assert result.changed
        assert result.lines == ["line1", "line2", "line3"]


class TestFinalNewlineRule:
    """Test the final newline rule."""

    def test_detects_missing_final_newline(self):
        from bake.core.rules.final_newline import FinalNewlineRule

        rule = FinalNewlineRule()
        config = {"ensure_final_newline": True, "_global": {"gnu_error_format": True}}
        lines = ["line1", "line2", "line3"]

        result = rule.format(
            lines, config, check_mode=True, original_content_ends_with_newline=False
        )

        assert result.changed
        assert len(result.check_messages) == 1
        assert "3: Error: Missing final newline" in result.check_messages[0]

    def test_skips_when_disabled(self):
        from bake.core.rules.final_newline import FinalNewlineRule

        rule = FinalNewlineRule()
        config = {"ensure_final_newline": False}
        lines = ["line1", "line2", "line3"]

        result = rule.format(lines, config, check_mode=True)

        assert not result.changed
        assert len(result.check_messages) == 0

    def test_skips_when_original_has_newline(self):
        from bake.core.rules.final_newline import FinalNewlineRule

        rule = FinalNewlineRule()
        config = {"ensure_final_newline": True, "_global": {"gnu_error_format": True}}
        lines = ["line1", "line2", "line3"]

        result = rule.format(
            lines, config, check_mode=True, original_content_ends_with_newline=True
        )

        assert not result.changed
        assert len(result.check_messages) == 0


class TestContinuationRule:
    """Test the line continuation formatting rule."""

    def test_formats_simple_continuation(self):
        rule = ContinuationRule()
        config = {"normalize_line_continuations": True, "max_line_length": 120}
        lines = ["SOURCES = file1.c \\", "          file2.c \\", "          file3.c"]

        result = rule.format(lines, config)

        assert result.changed
        # Should preserve multi-line structure with proper indentation for deliberate formatting
        assert len(result.lines) == 3
        assert result.lines[0] == "SOURCES = file1.c \\"
        assert result.lines[1] == "  file2.c \\"
        assert result.lines[2] == "  file3.c"

    def test_preserves_long_continuations(self):
        rule = ContinuationRule()
        config = {"normalize_line_continuations": True, "max_line_length": 30}
        lines = ["SOURCES = very_long_filename_that_exceeds_limit.c"]

        result = rule.format(lines, config)

        # Should not change since it's already a single line
        assert not result.changed


class TestPhonyRule:
    """Test the .PHONY declaration formatting rule."""

    def test_groups_phony_declarations(self):
        rule = PhonyRule()
        config = {"group_phony_declarations": True, "phony_at_top": True}
        lines = [
            "# Comment",
            "VAR = value",
            ".PHONY: clean",
            "target1:",
            "\techo 'target1'",
            ".PHONY: install",
            "target2:",
            "\techo 'target2'",
        ]

        result = rule.format(lines, config)

        assert result.changed
        # Should group .PHONY declarations
        phony_line = None
        for line in result.lines:
            if line.startswith(".PHONY:"):
                phony_line = line
                break

        assert phony_line is not None
        assert "clean" in phony_line
        assert "install" in phony_line


class TestMakefileFormatter:
    """Test the main formatter class."""

    def test_applies_all_rules(self):
        config = Config(formatter=FormatterConfig())
        formatter = MakefileFormatter(config)

        lines = [
            "VAR:=value",
            ".PHONY: clean",
            "target:",
            "    echo 'hello'",  # 4 spaces
        ]

        formatted_lines, errors = formatter.format_lines(lines)

        assert not errors
        # Check that spacing was fixed
        assert "VAR := value" in formatted_lines
        # Check that tabs were applied
        assert any(line.startswith("\t") and "echo" in line for line in formatted_lines)

    def test_handles_file_formatting(self, tmp_path):
        config = Config(formatter=FormatterConfig())
        formatter = MakefileFormatter(config)

        # Create test file
        test_file = tmp_path / "Makefile"
        test_file.write_text("VAR:=value\ntarget:\n    echo 'hello'\n")

        changed, errors = formatter.format_file(test_file)

        assert not errors
        assert changed  # Should have made changes

        # Check file was actually modified
        content = test_file.read_text(encoding="utf-8")
        assert "VAR := value" in content
        assert "\techo 'hello'" in content

    def test_check_only_mode(self, tmp_path):
        config = Config(formatter=FormatterConfig())
        formatter = MakefileFormatter(config)

        # Create test file
        test_file = tmp_path / "Makefile"
        original_content = "VAR:=value\ntarget:\n    echo 'hello'\n"
        test_file.write_text(original_content)

        changed, errors = formatter.format_file(test_file, check_only=True)

        assert changed  # Should detect changes needed

        # Check file was NOT modified
        assert test_file.read_text(encoding="utf-8") == original_content


class TestIntegration:
    """Integration tests using fixtures."""

    def test_formats_fixture_correctly(self):
        """Test that input.mk formats to expected.mk."""
        config = Config(formatter=FormatterConfig())
        formatter = MakefileFormatter(config)

        # Load input fixture
        input_lines = [
            "# Sample Makefile",
            "VAR:=value",
            "VAR2= another_value",
            "",
            ".PHONY: clean",
            "target1: dep1 dep2",
            "    echo 'building target1'",
            "    echo 'done'",
            "",
            ".PHONY: install",
            "clean:",
            "    rm -f *.o",
            "",
            "install:",
            "    cp binary /usr/local/bin",
        ]

        expected_lines = [
            "# Sample Makefile",
            "VAR := value",
            "VAR2 = another_value",
            "",
            ".PHONY: clean install",
            "",
            "target1: dep1 dep2",
            "\techo 'building target1'",
            "\techo 'done'",
            "",
            "clean:",
            "\trm -f *.o",
            "",
            "install:",
            "\tcp binary /usr/local/bin",
        ]

        formatted_lines, errors = formatter.format_lines(input_lines)

        assert not errors
        assert formatted_lines == expected_lines
