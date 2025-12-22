"""Line continuation formatting rule for Makefiles."""

from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin


class ContinuationRule(FormatterPlugin):
    """Handles proper formatting of line continuations with backslashes."""

    def __init__(self) -> None:
        super().__init__("continuation", priority=9)  # Run before tabs rule

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Normalize line continuation formatting."""
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        normalize_continuations = config.get("normalize_line_continuations", True)

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

                    j += 1

                # Format the continuation block
                formatted_block = self._format_continuation_block(continuation_lines)

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

    def _format_continuation_block(self, lines: list[str]) -> list[str]:
        """Format a block of continuation lines."""
        if not lines:
            return lines

        # First line is the assignment/recipe line - keep it as is
        first_line = lines[0]
        formatted_lines = [first_line]

        # If there's only one line, return early
        if len(lines) == 1:
            return formatted_lines

        # Check if this is a recipe continuation (starts with tab)
        is_recipe = first_line.startswith("\t")

        # Check if this continuation block contains shell control structures
        # If so, preserve original indentation for recipes (ShellFormattingRule will handle it)
        if is_recipe and self._contains_shell_control_structures(lines):
            # For recipe continuations with shell control structures, preserve indentation
            # Only normalize spacing around backslashes
            for line in lines[1:]:
                if line.rstrip().endswith("\\"):
                    # Remove trailing whitespace before backslash, ensure single space
                    content = line.rstrip()[:-1].rstrip()
                    formatted_lines.append(content + " \\")
                else:
                    # Last line of continuation - preserve original indentation
                    formatted_lines.append(line)
            return formatted_lines

        # Normalize indentation for variable assignments and simple recipe continuations
        # Find the indentation of the first continuation line (second line)
        first_continuation_line = lines[1]
        # Get leading whitespace (spaces/tabs) from the first continuation line
        leading_whitespace = ""
        for char in first_continuation_line:
            if char in (" ", "\t"):
                leading_whitespace += char
            else:
                break

        # Format all continuation lines (from second line onwards)
        for line in lines[1:]:
            if line.rstrip().endswith("\\"):
                # Remove trailing whitespace before backslash, ensure single space
                # Also remove leading whitespace to normalize indentation
                content = line.rstrip()[:-1].rstrip().lstrip()
                # Apply consistent indentation from first continuation line
                formatted_lines.append(leading_whitespace + content + " \\")
            else:
                # Last line of continuation - apply consistent indentation
                stripped_content = line.lstrip()
                formatted_lines.append(leading_whitespace + stripped_content)

        return formatted_lines

    def _contains_shell_control_structures(self, lines: list[str]) -> bool:
        """Check if continuation block contains shell control structure keywords."""
        # Shell control structure keywords that have semantic indentation meaning
        # These keywords should preserve their indentation relative to each other
        shell_keywords = (
            "if",
            "then",
            "else",
            "elif",
            "fi",
            "for",
            "do",
            "done",
            "while",
            "until",
            "case",
            "esac",
        )

        for line in lines:
            # Strip leading whitespace and make command prefixes for checking
            stripped = line.lstrip("\t ").lstrip("@-+ ")
            # Remove trailing backslash and whitespace for cleaner matching
            content = stripped.rstrip(" \\")

            # Check if line starts with a shell keyword (most common case)
            for keyword in shell_keywords:
                # Match keyword at start of line, followed by space, semicolon, or end of line
                if (
                    content.startswith(keyword + " ")
                    or content.startswith(keyword + ";")
                    or content == keyword
                    # Also check for keywords after shell operators (; || &&)
                    or f"; {keyword}" in content
                    or f"|| {keyword}" in content
                    or f"&& {keyword}" in content
                ):
                    return True

        return False
