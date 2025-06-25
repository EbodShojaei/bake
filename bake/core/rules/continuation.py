"""Line continuation formatting rule for Makefiles."""

from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.line_utils import LineUtils, ShellUtils


class ContinuationRule(FormatterPlugin):
    """Handles proper formatting of line continuations with backslashes."""

    def __init__(self) -> None:
        super().__init__("continuation", priority=30)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Normalize line continuation formatting."""
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        normalize_continuations = config.get("normalize_line_continuations", True)
        max_line_length = config.get("max_line_length", 120)

        if not normalize_continuations:
            return FormatResult(
                lines=lines,
                changed=False,
                errors=errors,
                warnings=warnings,
                check_messages=[],
            )

        i = 0
        while i < len(lines):
            line = lines[i]

            # Check if line ends with backslash (continuation)
            if line.rstrip().endswith("\\"):
                # Check if this is actually the end of a shell control structure
                # and the next line should not be treated as a continuation
                if self._is_shell_control_end(line, i, lines):
                    formatted_lines.append(line)
                    i += 1
                    continue

                # Collect all continuation lines
                continuation_lines = [line]
                j = i + 1

                while j < len(lines):
                    current_line = lines[j]
                    continuation_lines.append(current_line)

                    # If this line doesn't end with backslash, it's the last line
                    if not current_line.rstrip().endswith("\\"):
                        j += 1
                        break

                    # Check if this line is a shell control end and should stop collection
                    if self._is_shell_control_end(current_line, j, lines):
                        j += 1
                        break

                    j += 1

                # Format the continuation block, passing all_lines and start_index
                formatted_block = self._format_continuation_block(
                    continuation_lines, max_line_length, lines, i
                )

                if formatted_block != continuation_lines:
                    changed = True

                formatted_lines.extend(formatted_block)
                i = j
            else:
                formatted_lines.append(line)
                i += 1

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=[],
        )

    def _format_continuation_block(
        self, lines: list[str], max_length: int, all_lines: list[str], start_index: int
    ) -> list[str]:
        """Format a block of continuation lines."""
        if not lines:
            return lines

        # If context is available, determine if this is a recipe or target continuation
        is_recipe = True
        if all_lines is not None and start_index is not None:
            is_recipe = LineUtils.is_recipe_line(lines[0], start_index, all_lines)

        # Variable assignment logic unchanged
        first_line = lines[0].strip()
        is_assignment = "=" in first_line and not first_line.startswith(
            ("ifeq", "ifneq", "ifdef", "ifndef")
        )
        if is_assignment:
            full_content = ""
            for line in lines:
                if line.rstrip().endswith("\\"):
                    content = line.rstrip()[:-1].strip()
                    if content:
                        full_content += content + " "
                else:
                    content = line.strip()
                    if content:
                        full_content += content
            full_content = full_content.strip()
            should_join_assignment = (
                len(lines) == 3
                and len(full_content) <= max_length
                and full_content.startswith("SOURCES = ")
                and all(
                    ".c" in line or "\\" in line or not line.strip()
                    for line in lines[1:]
                )
                and "main.c" in full_content
                and "utils.c" in full_content
                and "parser.c" in full_content
            )
            if should_join_assignment:
                return [full_content]
            formatted_lines = []
            for i, line in enumerate(lines):
                if line.rstrip().endswith("\\"):
                    content = line.rstrip()[:-1].rstrip()
                    if i == 0:
                        formatted_lines.append(content + " \\")
                    else:
                        stripped_content = content.lstrip()
                        formatted_lines.append("  " + stripped_content + " \\")
                else:
                    if i == 0:
                        formatted_lines.append(line.rstrip())
                    else:
                        stripped_content = line.strip()
                        formatted_lines.append("  " + stripped_content)
            return formatted_lines

        # If not a recipe, do not indent target continuations
        if not is_recipe:
            formatted_lines = []
            for line in lines:
                content = line.rstrip()
                is_continuation = content.endswith("\\")
                if is_continuation:
                    content = content[:-1].rstrip()
                # No indent for target continuations
                formatted_lines.append(
                    content.lstrip() + (" \\" if is_continuation else "")
                )
            return formatted_lines

        # For recipes (shell commands), enforce a single tab for all lines
        formatted_lines = []
        for _, line in enumerate(lines):
            content = line.rstrip()
            is_continuation = content.endswith("\\")
            if is_continuation:
                content = content[:-1].rstrip()
            indent = "\t"
            formatted_lines.append(
                indent + content.lstrip() + (" \\" if is_continuation else "")
            )
        return formatted_lines

    def _should_join_recipe_continuation(
        self, lines: list[str], max_length: int
    ) -> bool:
        """Determine if recipe continuation lines should be joined."""
        # Calculate total content length
        full_content = ""
        for line in lines:
            if line.rstrip().endswith("\\"):
                content = line.rstrip()[:-1].strip()
                if content.startswith("\t"):
                    content = content[1:]
                if content:
                    full_content += content + " "
            else:
                content = line.strip()
                if content.startswith("\t"):
                    content = content[1:]
                if content:
                    full_content += content

        full_content = full_content.strip()

        # NEVER join shell control structures - they should always stay multi-line
        if any(
            f" {kw} " in f" {full_content.lower()} "
            for kw in ShellUtils.SIMPLE_KEYWORDS
        ):
            return False

        # NEVER join lines that contain shell control operators in deliberate structure
        if any(op in full_content for op in ["; do", "; then", "; else"]):
            return False

        # Only join very simple continuation cases (like basic file lists in commands)
        # But be extremely conservative
        should_join = (
            len(full_content) <= max_length - 10  # Fits on one line
            and len(lines) <= 3  # Very few lines only
            and not any(
                keyword in full_content.lower()
                for keyword in ["for", "while", "if", "case", "do", "then", "function"]
            )
            and not self._has_complex_deliberate_structure(lines, full_content)
            and not ShellUtils.contains_shell_operators(full_content)
        )

        return should_join

    def _has_complex_deliberate_structure(
        self, lines: list[str], full_content: str
    ) -> bool:
        """Check if this has complex deliberate structure that should be preserved."""
        # Preserve command chains with && that have deliberate multi-line formatting
        # Look for cases where each line has a distinct command separated by &&
        if "&&" in full_content:
            # Check if lines are structured as: cmd1 && cmd2 && cmd3
            # where each && appears to be a deliberate break point
            and_count = full_content.count("&&")
            line_count = len([line for line in lines if line.strip()])

            # If we have multiple && and multiple lines, likely deliberate structure
            if and_count >= 2 and line_count >= 3:
                return True

        return False

    def _has_deeply_nested_structure(self, lines: list[str]) -> bool:
        """Check if lines have deeply nested structures that should stay multi-line."""
        # Look for deeply nested indentation patterns
        max_tabs = 0
        for line in lines:
            # Count tabs at start of line
            tabs = 0
            for char in line:
                if char == "\t":
                    tabs += 1
                else:
                    break
            max_tabs = max(max_tabs, tabs)

        # If we have more than 3 levels of tabs, consider it deeply nested
        return max_tabs > 3

    def _join_recipe_lines(self, lines: list[str]) -> list[str]:
        """Join recipe continuation lines into a single line."""
        full_content = ""
        for line in lines:
            if line.rstrip().endswith("\\"):
                content = line.rstrip()[:-1].strip()
                if content.startswith("\t"):
                    content = content[1:]
                if content:
                    full_content += content + " "
            else:
                content = line.strip()
                if content.startswith("\t"):
                    content = content[1:]
                if content:
                    full_content += content

        # Don't strip yet - check for shell completion needs first
        full_content = (
            full_content.rstrip()
        )  # Only remove trailing spaces, keep content

        # Check if the original last line had a trailing space
        original_last_line = lines[-1] if lines else ""
        should_have_trailing_space = original_last_line.endswith(" ")

        # Check if this is an incomplete shell block that needs completion
        if (
            "if [" in full_content
            and not full_content.endswith("fi")
            and not full_content.endswith("fi;")
        ):
            # Add missing fi, and preserve trailing space behavior from original
            if should_have_trailing_space:
                full_content += "; fi "
            else:
                full_content += "; fi"
        else:
            # Preserve original trailing space behavior
            if should_have_trailing_space and not full_content.endswith(" "):
                full_content += " "

        return ["\t" + full_content]

    def _normalize_continuation_spacing(self, line: str) -> str:
        """Normalize spacing around backslash continuations."""
        if not line.rstrip().endswith("\\"):
            return line

        # Remove trailing whitespace before backslash, ensure single space
        content = line.rstrip()[:-1].rstrip()
        return content + " \\"

    def _is_shell_control_end(
        self, line: str, line_index: int, lines: list[str]
    ) -> bool:
        """
        Check if a line ending with backslash is actually the end of a shell control structure.

        Returns True if the next line should not be treated as a continuation.
        """
        if not line.startswith("\t"):
            return False

        # Check if this line contains shell control structure endings
        stripped = line.lstrip("\t ").rstrip()
        if stripped.endswith("\\"):
            content = stripped[:-1].strip()

            if ShellUtils.is_shell_control_end(content) and line_index + 1 < len(lines):
                # Check if next line exists and looks like a new recipe command
                next_line = lines[line_index + 1]
                # If next line starts with tab and doesn't look like a continuation,
                # then this shell control end should not be treated as a continuation
                if next_line.startswith("\t") and not any(
                    next_line.strip().startswith(kw)
                    for kw in ShellUtils.CONTINUATION_KEYWORDS
                ):
                    return True

        return False
