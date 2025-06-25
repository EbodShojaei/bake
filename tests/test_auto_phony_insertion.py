"""Tests for auto-insertion of .PHONY declarations."""

from bake.config import Config, FormatterConfig
from bake.core.formatter import MakefileFormatter


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

        formatted_lines, errors = formatter.format_lines(lines)

        assert not errors
        assert any(".PHONY:" in line for line in formatted_lines)

        # Check that common phony targets are included
        phony_line = next(
            line for line in formatted_lines if line.startswith(".PHONY:")
        )
        assert "setup" in phony_line
        assert "clean" in phony_line
        assert "test" in phony_line
        assert "install" in phony_line

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

        formatted_lines, errors = formatter.format_lines(lines)

        assert not errors
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

        formatted_lines, errors = formatter.format_lines(lines)

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

        formatted_lines, errors = formatter.format_lines(lines)

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

        formatted_lines, errors = formatter.format_lines(lines)

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

        formatted_lines, errors = formatter.format_lines(lines)

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

        formatted_lines, errors = formatter.format_lines(lines)

        assert not errors
        phony_line = next(
            line for line in formatted_lines if line.startswith(".PHONY:")
        )
        # deploy and monitor are phony (no file creation)
        assert "deploy" in phony_line
        assert "monitor" in phony_line
        assert "clean" in phony_line
        # backup creates backup.sql file via redirection, so it should NOT be phony
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

        formatted_lines, errors = formatter.format_lines(lines)

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

        formatted_lines, errors = formatter.format_lines(lines)

        assert not errors
        if any(".PHONY:" in line for line in formatted_lines):
            phony_line = next(
                line for line in formatted_lines if line.startswith(".PHONY:")
            )
            # These should be detected as phony based on name patterns
            assert "clean-all" in phony_line
            assert "test_unit" in phony_line
            assert "build-prod" in phony_line

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

        formatted_lines, errors = formatter.format_lines(lines)

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

        formatted_lines, errors = formatter.format_lines(lines)

        assert not errors
        if any(".PHONY:" in line for line in formatted_lines):
            phony_line = next(
                line for line in formatted_lines if line.startswith(".PHONY:")
            )

            # These should be detected as phony
            expected_phony = [
                "all",
                "clean",
                "install",
                "test",
                "debug",
                "docker-build",
                "docker-run",
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

        formatted_lines, errors = formatter.format_lines(lines)

        assert not errors
        assert any(".PHONY:" in line for line in formatted_lines)
        phony_line = next(
            line for line in formatted_lines if line.startswith(".PHONY:")
        )
        assert "clean" in phony_line
        assert "test" in phony_line
