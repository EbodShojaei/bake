"""Tab formatting rule for Makefile recipes."""

from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils import LineUtils


class TabsRule(FormatterPlugin):
    """Ensures tabs are used for recipe indentation instead of spaces."""

    def __init__(self) -> None:
        super().__init__("tabs", priority=10)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Convert spaces to tabs for recipe lines only, preserve existing tabs and conditional indentation."""
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []
        tab_width = config.get("tab_width", 4)

        for i, line in enumerate(lines):
            stripped = line.lstrip()

            # Skip empty lines
            if not stripped:
                formatted_lines.append(line)
                continue

            # Use robust LineUtils helper to detect actual target lines
            # Only check the original line - if it's indented, it's not a target
            is_target = LineUtils.is_target_line(line)

            # Check if this is a special Makefile directive or function call (non-recipe only)
            is_special_directive = False
            special_directives = [
                "$(error",
                "$(warning",
                "$(info",
                "$(shell",
                "$(eval",
                "$(file",
                "$(call",
            ]
            if not line.startswith("\t") and any(
                stripped.startswith(d) for d in special_directives
            ):
                is_special_directive = True

            if is_target or is_special_directive:
                # Targets/directives must be flush-left. Remove any leading whitespace.
                if line.startswith((" ", "\t")):
                    formatted_lines.append(stripped)
                    changed = True
                else:
                    formatted_lines.append(line)
                continue

            # Check if this is a conditional directive (preserve 2-space indentation)
            conditional_keywords = [
                "ifeq",
                "ifneq",
                "ifdef",
                "ifndef",
                "else",
                "endif",
                "define",
                "endef",
            ]
            if any(stripped.startswith(keyword) for keyword in conditional_keywords):
                formatted_lines.append(line)
                continue

            # Check if this is a variable assignment (preserve existing indentation)
            if "=" in stripped and not stripped.startswith("#"):
                # Variable assignments in conditional blocks should preserve their indentation
                formatted_lines.append(line)
                continue

            # Check if this is a comment (preserve existing indentation unless it's a recipe comment)
            if stripped.startswith("#"):
                # Only convert to tab if this is clearly a recipe comment (previous line was a target)
                if (
                    i > 0
                    and LineUtils.is_target_line(lines[i - 1].lstrip())
                    and line.startswith(" ")
                ):
                    new_line = "\t" + stripped
                    formatted_lines.append(new_line)
                    changed = True
                    continue
                formatted_lines.append(line)
                continue

            # Now handle potential recipe lines
            if line.startswith((" ", "\t")):
                # If line already starts with tab, preserve it
                if line.startswith("\t"):
                    formatted_lines.append(line)
                    continue

                # Check if this looks like a recipe line (shell command)
                # Recipe lines typically contain shell commands, not variable assignments
                if self._looks_like_recipe_line(stripped):
                    # Convert spaces to tabs for recipe lines
                    if line.startswith(" "):
                        # Count leading spaces
                        leading_spaces = 0
                        for char in line:
                            if char == " ":
                                leading_spaces += 1
                            else:
                                break

                        # Convert spaces to tabs
                        if leading_spaces > 0:
                            # Calculate tabs needed (minimum 1 for recipe lines)
                            tabs_needed = max(1, leading_spaces // tab_width)
                            new_line = "\t" * tabs_needed + line.lstrip()
                            formatted_lines.append(new_line)
                            changed = True
                            continue

                    # Handle mixed tab/space indentation for recipe lines
                    if "\t" in line and line.startswith(" "):
                        # Clean up mixed indentation - convert to pure tabs
                        new_line = "\t" + stripped
                        formatted_lines.append(new_line)
                        changed = True
                        continue

            # All other lines (variable assignments, conditional indentation, etc.) are left as-is
            formatted_lines.append(line)

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=[],
        )

    def _looks_like_recipe_line(self, stripped_line: str) -> bool:
        """Determine if a line looks like a shell command recipe."""

        # First check if this is actually a target line - targets should not be treated as recipes
        from bake.utils.line_utils import LineUtils

        if LineUtils.is_target_line(stripped_line):
            return False

        # Common shell commands and patterns
        shell_commands = [
            "echo",
            "cp",
            "mv",
            "rm",
            "mkdir",
            "cd",
            "ln",
            "chmod",
            "chown",
            "gcc",
            "g++",
            "clang",
            "make",
            "cmake",
            "python",
            "pip",
            "npm",
            "git",
            "svn",
            "tar",
            "zip",
            "unzip",
            "wget",
            "curl",
            "ssh",
            "scp",
            "sed",
            "awk",
            "grep",
            "find",
            "sort",
            "cat",
            "head",
            "tail",
            "touch",
            "test",
            "which",
            "whereis",
            "ps",
            "kill",
            "sleep",
            "@echo",
            "@cp",
            "@mv",
            "@rm",
            "@mkdir",
            "@cd",
            "@ln",
            "@chmod",
            "@gcc",
            "@g++",
            "@clang",
            "@make",
            "@cmake",
            "@python",
            "@pip",
            "-",
            "+",
            "$(",
            "${",
            "if",
            "for",
            "while",
            "case",
            "done",
            "fi",
        ]

        # Check if line starts with common shell command patterns
        for cmd in shell_commands:
            if stripped_line.startswith(cmd):
                return True

        # Check for variable references that are typically in recipes
        # Exclude target lines which also start with $( but contain colons
        if (
            stripped_line.startswith("$(")
            and "=" not in stripped_line
            and ":" not in stripped_line
        ):
            return True

        # Check for shell operators
        shell_operators = ["&&", "||", "|", ";", ">>", ">", "<", "2>"]
        return any(op in stripped_line for op in shell_operators)
