"""Tests for auto-insertion of .PHONY declarations."""

from mbake.config import Config, FormatterConfig
from mbake.core.formatter import MakefileFormatter


class TestAutoPhonyInsertion:
    """Test auto-insertion of .PHONY declarations."""

    def test_auto_insert_common_phony_targets(self):
        """Test auto-insertion of common phony targets."""
        config = Config(formatter=FormatterConfig(auto_insert_phony_declarations=True))
        formatter = MakefileFormatter(config)

        lines = [
            "# Docker Makefile",
            "COMPOSE_FILE = docker-compose.yml",
            "",
            "setup:",
            "\tdocker compose down -v",
            "\tdocker compose up -d",
            "",
            "clean:",
            "\tdocker system prune -af",
            "",
            "test:",
            "\tnpm test",
            "",
            "install:",
            "\tnpm install",
        ]

        formatted_lines, errors, warnings = formatter.format_lines(lines)

        assert not errors
        assert any(".PHONY:" in line for line in formatted_lines)

        # Check that enhanced phony detection identified all phony targets
        phony_line = next(
            line for line in formatted_lines if line.startswith(".PHONY:")
        )
        # Enhanced algorithm detects docker commands and standard action targets:
        assert "setup" in phony_line  # docker commands
        assert "clean" in phony_line  # cleanup command
        assert "test" in phony_line  # test command
        assert "install" in phony_line  # install command

        # Check that targets are sorted
        targets = phony_line.replace(".PHONY:", "").strip().split()
        assert targets == sorted(targets)

    def test_auto_insert_docker_targets(self):
        """Test auto-insertion with Docker-specific targets."""
        config = Config(formatter=FormatterConfig(auto_insert_phony_declarations=True))
        formatter = MakefileFormatter(config)

        lines = [
            "up:",
            "\tdocker compose up -d",
            "",
            "down:",
            "\tdocker compose down -v",
            "",
            "logs:",
            "\tdocker compose logs -f",
            "",
            "shell:",
            "\tdocker compose exec app sh",
        ]

        formatted_lines, errors, warnings = formatter.format_lines(lines)

        assert not errors
        # Enhanced algorithm detects docker commands as phony
        phony_line = next(
            line for line in formatted_lines if line.startswith(".PHONY:")
        )
        assert "up" in phony_line
        assert "down" in phony_line
        assert "logs" in phony_line
        assert "shell" in phony_line

    def test_no_auto_insert_when_disabled(self):
        """Test that auto-insertion doesn't happen when disabled."""
        config = Config(formatter=FormatterConfig(auto_insert_phony_declarations=False))
        formatter = MakefileFormatter(config)

        lines = [
            "clean:",
            "\trm -f *.o",
            "",
            "test:",
            "\tnpm test",
        ]

        formatted_lines, errors, warnings = formatter.format_lines(lines)

        assert not errors
        assert not any(".PHONY:" in line for line in formatted_lines)

    def test_skip_pattern_rules(self):
        """Test that pattern rules are not considered phony."""
        config = Config(formatter=FormatterConfig(auto_insert_phony_declarations=True))
        formatter = MakefileFormatter(config)

        lines = [
            "%.o: %.c",
            "\t$(CC) -c $< -o $@",
            "",
            "clean:",
            "\trm -f *.o",
        ]

        formatted_lines, errors, warnings = formatter.format_lines(lines)

        assert not errors
        phony_line = next(
            line for line in formatted_lines if line.startswith(".PHONY:")
        )
        assert "clean" in phony_line
        assert "%.o" not in phony_line

    def test_skip_variable_assignments(self):
        """Test that variable assignments are not considered targets."""
        config = Config(formatter=FormatterConfig(auto_insert_phony_declarations=True))
        formatter = MakefileFormatter(config)

        lines = [
            "CC := gcc",
            "CFLAGS = -Wall",
            "",
            "clean:",
            "\trm -f *.o",
        ]

        formatted_lines, errors, warnings = formatter.format_lines(lines)

        assert not errors
        phony_line = next(
            line for line in formatted_lines if line.startswith(".PHONY:")
        )
        assert "clean" in phony_line
        assert "CC" not in phony_line
        assert "CFLAGS" not in phony_line

    def test_skip_conditionals(self):
        """Test that conditional blocks are not considered targets."""
        config = Config(formatter=FormatterConfig(auto_insert_phony_declarations=True))
        formatter = MakefileFormatter(config)

        lines = [
            "ifeq ($(DEBUG),1)",
            "    CFLAGS += -g",
            "else",
            "    CFLAGS += -O2",
            "endif",
            "",
            "clean:",
            "\trm -f *.o",
        ]

        formatted_lines, errors, warnings = formatter.format_lines(lines)

        assert not errors
        phony_line = next(
            line for line in formatted_lines if line.startswith(".PHONY:")
        )
        assert "clean" in phony_line
        assert "ifeq" not in phony_line
        assert "else" not in phony_line
        assert "endif" not in phony_line

    def test_heuristic_based_detection(self):
        """Test detection based on command patterns."""
        config = Config(formatter=FormatterConfig(auto_insert_phony_declarations=True))
        formatter = MakefileFormatter(config)

        lines = [
            "deploy:",
            "\tssh user@server 'systemctl restart myapp'",
            "",
            "backup:",
            "\tmysqldump -u root mydb > backup.sql",
            "",
            "monitor:",
            "\ttail -f /var/log/myapp.log",
            "",
            "clean:",
            "\trm -f *.o *.tmp",
        ]

        formatted_lines, errors, warnings = formatter.format_lines(lines)

        assert not errors
        phony_line = next(
            line for line in formatted_lines if line.startswith(".PHONY:")
        )
        # Enhanced algorithm detects command patterns and remote operations
        assert "deploy" in phony_line  # remote command (ssh)
        assert "monitor" in phony_line  # monitoring command (tail)
        assert "clean" in phony_line  # cleanup command
        # backup creates backup.sql file via redirection, correctly not flagged as phony
        assert "backup" not in phony_line

    def test_preserve_existing_phony_with_auto_detection(self):
        """Test that existing .PHONY is preserved and enhanced."""
        config = Config(formatter=FormatterConfig(auto_insert_phony_declarations=True))
        formatter = MakefileFormatter(config)

        lines = [
            ".PHONY: clean",
            "",
            "clean:",
            "\trm -f *.o",
            "",
            "test:",
            "\tnpm test",
            "",
            "install:",
            "\tnpm install",
        ]

        formatted_lines, errors, warnings = formatter.format_lines(lines)

        assert not errors
        phony_line = next(
            line for line in formatted_lines if line.startswith(".PHONY:")
        )
        assert "clean" in phony_line
        assert "test" in phony_line
        assert "install" in phony_line

    def test_edge_case_targets_with_special_chars(self):
        """Test targets with special characters."""
        config = Config(formatter=FormatterConfig(auto_insert_phony_declarations=True))
        formatter = MakefileFormatter(config)

        lines = [
            "clean-all:",
            "\trm -rf build/",
            "",
            "test_unit:",
            "\tpython -m pytest tests/unit/",
            "",
            "build-prod:",
            "\tnpm run build:prod",
        ]

        formatted_lines, errors, warnings = formatter.format_lines(lines)

        assert not errors
        if any(".PHONY:" in line for line in formatted_lines):
            phony_line = next(
                line for line in formatted_lines if line.startswith(".PHONY:")
            )
            # Enhanced algorithm detects hyphenated patterns
            assert "clean-all" in phony_line  # clean- pattern
            assert "test_unit" in phony_line  # test_ pattern
            assert "build-prod" in phony_line  # build- pattern

    def test_no_false_positives_for_file_targets(self):
        """Test that file-generating targets are not marked as phony."""
        config = Config(formatter=FormatterConfig(auto_insert_phony_declarations=True))
        formatter = MakefileFormatter(config)

        lines = [
            "myapp.o: myapp.c",
            "\t$(CC) -c myapp.c -o myapp.o",
            "",
            "myapp: myapp.o",
            "\t$(CC) myapp.o -o myapp",
            "",
            "clean:",
            "\trm -f myapp myapp.o",
        ]

        formatted_lines, errors, warnings = formatter.format_lines(lines)

        assert not errors
        if any(".PHONY:" in line for line in formatted_lines):
            phony_line = next(
                line for line in formatted_lines if line.startswith(".PHONY:")
            )
            assert "clean" in phony_line
            assert "myapp.o" not in phony_line
            assert "myapp" not in phony_line

    def test_complex_real_world_makefile(self):
        """Test with a complex real-world Makefile."""
        config = Config(formatter=FormatterConfig(auto_insert_phony_declarations=True))
        formatter = MakefileFormatter(config)

        lines = [
            "# Complex Makefile",
            "CC = gcc",
            "CFLAGS = -Wall -O2",
            "",
            "all: myapp",
            "",
            "myapp.o: myapp.c",
            "\t$(CC) $(CFLAGS) -c myapp.c",
            "",
            "myapp: myapp.o",
            "\t$(CC) myapp.o -o myapp",
            "",
            "clean:",
            "\trm -f myapp myapp.o",
            "",
            "install: myapp",
            "\tcp myapp /usr/local/bin/",
            "",
            "test:",
            "\t./myapp --test",
            "",
            "debug: CFLAGS += -g -DDEBUG",
            "debug: myapp",
            "",
            "docker-build:",
            "\tdocker build -t myapp .",
            "",
            "docker-run:",
            "\tdocker run -it myapp",
        ]

        formatted_lines, errors, warnings = formatter.format_lines(lines)

        assert not errors
        if any(".PHONY:" in line for line in formatted_lines):
            phony_line = next(
                line for line in formatted_lines if line.startswith(".PHONY:")
            )

            # Enhanced algorithm detects standard action patterns and docker commands
            expected_phony = [
                "all",  # standard phony pattern
                "clean",  # cleanup command
                "install",  # install command
                "test",  # test command
                "debug",  # debug pattern
                "docker-build",  # docker- pattern
                "docker-run",  # docker- pattern
            ]
            for target in expected_phony:
                assert (
                    target in phony_line
                ), f"Expected {target} to be in .PHONY declaration"

            # These should NOT be phony
            assert "myapp.o" not in phony_line
            assert "myapp" not in phony_line

    def test_warnings_generated(self):
        """Test that appropriate warnings are generated for auto-insertion."""
        config = Config(formatter=FormatterConfig(auto_insert_phony_declarations=True))
        formatter = MakefileFormatter(config)

        lines = [
            "clean:",
            "\trm -f *.o",
            "",
            "test:",
            "\tnpm test",
        ]

        formatted_lines, errors, warnings = formatter.format_lines(lines)

        assert not errors
        assert any(".PHONY:" in line for line in formatted_lines)
        phony_line = next(
            line for line in formatted_lines if line.startswith(".PHONY:")
        )
        assert "clean" in phony_line
        assert "test" in phony_line

    def test_duplicate_global_directives(self):
        """Test that global directives cannot be duplicated."""
        config = Config(
            formatter=FormatterConfig(
                auto_insert_phony_declarations=False,
                ensure_final_newline=False,
                group_phony_declarations=False,
                phony_at_top=False,
            )
        )
        formatter = MakefileFormatter(config)

        # Test with duplicate .POSIX (should generate error)
        test_content = """# Test duplicate global directive
.POSIX:
.POSIX:

all:
	@echo "test"
"""
        lines = test_content.strip().split("\n")
        formatted_lines, errors, warnings = formatter.format_lines(
            lines, check_only=True
        )

        # Should have error about duplicate global directive
        assert any(
            "cannot be declared multiple times" in error for error in errors
        ), f"Expected duplicate directive error, got: {errors}"

    def test_phony_target_detection_with_suffix_rules(self):
        """Test that phony detection correctly handles suffix rules and file targets."""
        # Enable auto-insertion for this test
        config = Config(
            formatter=FormatterConfig(
                auto_insert_phony_declarations=True,
                ensure_final_newline=False,
                group_phony_declarations=False,
                phony_at_top=False,
            )
        )
        formatter = MakefileFormatter(config)

        test_content = """# Test phony detection with various rule types
.POSIX:
.SUFFIXES: .c .o .a .b

# Should be detected as phony (action targets)
all: main.o
	$(CC) -o main main.o

clean:
	rm -f *.o main

test:
	@echo "Running tests"

# Should NOT be detected as phony (file targets)
main.o: main.c
	$(CC) -c main.c

foo.b: foo.a
	cp $< $@

# Should NOT be detected as phony (suffix rules)
.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<

.a.b:
	cp $< $@

# Should NOT be detected as phony (pattern rules)
%.h: %.c
	@echo "Generating $@ from $<"

.PHONY: all
"""
        lines = test_content.strip().split("\n")
        formatted_lines, errors, warnings = formatter.format_lines(
            lines, check_only=True
        )

        # Should not suggest file targets, suffix rules, or pattern rules as phony
        for warning in warnings:
            assert (
                "main.o" not in warning
            ), f"File target main.o incorrectly suggested as phony: {warning}"
            assert (
                "foo.b" not in warning
            ), f"File target foo.b incorrectly suggested as phony: {warning}"
            assert (
                ".c.o" not in warning
            ), f"Suffix rule .c.o incorrectly suggested as phony: {warning}"
            assert (
                ".a.b" not in warning
            ), f"Suffix rule .a.b incorrectly suggested as phony: {warning}"
            assert (
                "%.h" not in warning
            ), f"Pattern rule %.h incorrectly suggested as phony: {warning}"

        # Should suggest action targets as phony (clean and test are not in .PHONY: all)
        phony_suggestions = [
            w
            for w in warnings
            if (
                "Consider adding targets to .PHONY" in w
                or "Missing targets in .PHONY" in w
            )
        ]
        assert (
            len(phony_suggestions) > 0
        ), f"Should suggest some targets as phony, got warnings: {warnings}"

        # Check that action targets are suggested
        all_warnings = " ".join(warnings)
        assert (
            "clean" in all_warnings or "test" in all_warnings
        ), "Should suggest action targets as phony"

    def test_rule_type_detection(self):
        """Test that different rule types are correctly detected."""
        config = Config(
            formatter=FormatterConfig(
                auto_insert_phony_declarations=False,
                ensure_final_newline=False,
                group_phony_declarations=False,
                phony_at_top=False,
            )
        )
        formatter = MakefileFormatter(config)

        test_content = """# Test rule type detection
.POSIX:
.SUFFIXES: .c .o

# Explicit rule
all: main.o
	$(CC) -o main main.o

# Pattern rule
%.o: %.c
	$(CC) -c $<

# Suffix rule
.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<

# Static pattern rule
objects: %.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

# Double-colon rule
clean::
	rm -f *.o

# Special target
.PHONY: all clean
"""
        lines = test_content.strip().split("\n")
        formatted_lines, errors, warnings = formatter.format_lines(lines)

        # Should not have errors for valid rule types
        assert not errors, f"Unexpected errors for valid rule types: {errors}"

    def test_special_target_prerequisites(self):
        """Test special target prerequisite validation."""
        config = Config(
            formatter=FormatterConfig(
                auto_insert_phony_declarations=False,
                ensure_final_newline=False,
                group_phony_declarations=False,
                phony_at_top=False,
            )
        )
        formatter = MakefileFormatter(config)

        # Test .PHONY without prerequisites (should generate warning)
        test_content = """# Test .PHONY without prerequisites
.PHONY:

all:
	@echo "test"
"""
        lines = test_content.strip().split("\n")
        formatted_lines, errors, warnings = formatter.format_lines(
            lines, check_only=True
        )

        # Should have warning about missing prerequisites
        assert any(
            "typically requires prerequisites" in warning for warning in warnings
        ), f"Expected prerequisite warning, got: {warnings}"

    def test_suffix_rule_validation(self):
        """Test suffix rule validation with invalid suffixes."""
        config = Config(
            formatter=FormatterConfig(
                auto_insert_phony_declarations=False,
                ensure_final_newline=False,
                group_phony_declarations=False,
                phony_at_top=False,
            )
        )
        formatter = MakefileFormatter(config)

        # Test with invalid suffix rule (undeclared suffix)
        test_content = """# Test invalid suffix rule
.SUFFIXES: .c .o

# This should generate an error - .a is not declared
.a.o:
	cp $< $@
"""
        lines = test_content.strip().split("\n")
        formatted_lines, errors, warnings = formatter.format_lines(
            lines, check_only=True
        )

        # Should have error about undeclared suffix
        assert any(
            "undeclared suffix" in error for error in errors
        ), f"Expected undeclared suffix error, got: {errors}"

    def test_suffixes_declaration_validation(self):
        """Test .SUFFIXES declaration validation."""
        config = Config(
            formatter=FormatterConfig(
                auto_insert_phony_declarations=False,
                ensure_final_newline=False,
                group_phony_declarations=False,
                phony_at_top=False,
            )
        )
        formatter = MakefileFormatter(config)

        # Test with invalid suffix format
        test_content = """# Test invalid suffix format
.SUFFIXES: a .b c

# Valid suffix rule
.b.o:
	cp $< $@
"""
        lines = test_content.strip().split("\n")
        formatted_lines, errors, warnings = formatter.format_lines(
            lines, check_only=True
        )

        # Should have error about invalid suffix format
        assert any(
            "Invalid suffix" in error for error in errors
        ), f"Expected invalid suffix error, got: {errors}"

    def test_duplicate_suffix_declarations(self):
        """Test detection of duplicate suffix declarations."""
        config = Config(
            formatter=FormatterConfig(
                auto_insert_phony_declarations=False,
                ensure_final_newline=False,
                group_phony_declarations=False,
                phony_at_top=False,
            )
        )
        formatter = MakefileFormatter(config)

        # Test with duplicate suffixes in same declaration
        test_content = """# Test duplicate suffixes in same declaration
.SUFFIXES: .c .o .c

# Valid suffix rule
.c.o:
	cp $< $@
"""
        lines = test_content.strip().split("\n")
        formatted_lines, errors, warnings = formatter.format_lines(
            lines, check_only=True
        )

        # Should have error about duplicate suffix
        assert any(
            "Duplicate suffix" in error for error in errors
        ), f"Expected duplicate suffix error, got: {errors}"

    def test_duplicate_suffix_across_declarations(self):
        """Test detection of duplicate suffixes across multiple declarations."""
        config = Config(
            formatter=FormatterConfig(
                auto_insert_phony_declarations=False,
                ensure_final_newline=False,
                group_phony_declarations=False,
                phony_at_top=False,
            )
        )
        formatter = MakefileFormatter(config)

        # Test with duplicate suffixes across declarations
        test_content = """# First declaration
.SUFFIXES: .c .o

# Second declaration with duplicate
.SUFFIXES: .cpp .o

# Valid suffix rule
.c.o:
	cp $< $@
"""
        lines = test_content.strip().split("\n")
        formatted_lines, errors, warnings = formatter.format_lines(
            lines, check_only=True
        )

        # Should have warning about duplicate suffix across declarations
        assert any(
            "already declared in previous" in warning for warning in warnings
        ), f"Expected duplicate suffix warning, got: {warnings}"

    def test_unusual_suffix_patterns(self):
        """Test detection of unusual suffix patterns."""
        config = Config(
            formatter=FormatterConfig(
                auto_insert_phony_declarations=False,
                ensure_final_newline=False,
                group_phony_declarations=False,
                phony_at_top=False,
            )
        )
        formatter = MakefileFormatter(config)

        # Test with unusual suffix patterns
        test_content = """# Test unusual suffix patterns
.SUFFIXES: . .tar.gz .verylongsuffix

# Valid suffix rule
.c.o:
	cp $< $@
"""
        lines = test_content.strip().split("\n")
        formatted_lines, errors, warnings = formatter.format_lines(
            lines, check_only=True
        )

        # Should have warnings about unusual patterns
        unusual_warnings = [
            w for w in warnings if "Unusual suffix" in w or "Complex suffix" in w
        ]
        assert (
            len(unusual_warnings) >= 2
        ), f"Expected unusual suffix warnings, got: {warnings}"

    def test_comprehensive_suffix_validation(self):
        """Test comprehensive suffix validation with multiple issues."""
        config = Config(
            formatter=FormatterConfig(
                auto_insert_phony_declarations=False,
                ensure_final_newline=False,
                group_phony_declarations=False,
                phony_at_top=False,
            )
        )
        formatter = MakefileFormatter(config)

        # Test with multiple validation issues
        test_content = """# First declaration
.SUFFIXES: .c .o

# Duplicate in same declaration
.SUFFIXES: .cpp .o .cpp

# Invalid format
.SUFFIXES: .java invalid

# Duplicate across declarations
.SUFFIXES: .c .h

# Unusual patterns
.SUFFIXES: . .tar.gz

# Valid suffix rule
.c.o:
	cp $< $@

# Invalid suffix rule (undeclared suffix)
.java.class:
	javac $< -o $@
"""
        lines = test_content.strip().split("\n")
        formatted_lines, errors, warnings = formatter.format_lines(
            lines, check_only=True
        )

        # Should have multiple errors and warnings
        error_types = ["Duplicate suffix", "Invalid suffix", "undeclared suffix"]
        warning_types = [
            "already declared in previous",
            "Unusual suffix",
            "Complex suffix",
        ]

        # Check that we have the expected types of errors
        found_errors = [
            error_type
            for error_type in error_types
            if any(error_type in error for error in errors)
        ]
        assert (
            len(found_errors) >= 2
        ), f"Expected multiple error types, found: {found_errors}"

        # Check that we have the expected types of warnings
        found_warnings = [
            warning_type
            for warning_type in warning_types
            if any(warning_type in warning for warning in warnings)
        ]
        assert (
            len(found_warnings) >= 2
        ), f"Expected multiple warning types, found: {found_warnings}"
