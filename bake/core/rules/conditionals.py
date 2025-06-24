"""Conditional block formatting rule for Makefiles."""

from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.line_utils import LineUtils


class ConditionalRule(FormatterPlugin):
    """Handles proper indentation of conditional blocks (ifeq, ifneq, etc.)."""

    def __init__(self) -> None:
        super().__init__("conditionals", priority=7)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Format conditional block indentation."""
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        indent_level = 0
        define_stack = []  # Track nested define blocks with their indentation

        # Conditional indentation uses 2 spaces for readability
        # This is separate from recipe indentation (which uses tabs)
        # Using 2 spaces avoids confusion with tab-indented recipes (8 chars = 2 levels ≠ 1 tab)
        base_indent = "  "  # 2 spaces for conditional blocks

        # Get tab configuration for recipe detection
        use_tabs = config.get("use_tabs", True)
        tab_width = config.get("tab_width", 4)

        for line in lines:
            stripped = line.strip()
            original_line = line

            # Skip recipe lines (start with tab) - but only if we're using tabs
            # If we're using spaces, we need to be more careful
            if (
                use_tabs
                and line.startswith("\t")
                or (
                    not use_tabs
                    and line.startswith(" " * tab_width)
                    and self._looks_like_recipe_line(line, tab_width)
                )
            ):
                formatted_lines.append(line)
                continue

            # Skip empty lines and comments
            if not stripped or stripped.startswith("#"):
                formatted_lines.append(line)
                continue

            # Handle define blocks
            if stripped.startswith("define "):
                # Starting a define block
                if indent_level > 0:
                    # Define inside conditional - indent the define keyword
                    formatted_line = base_indent * indent_level + stripped
                    define_stack.append(indent_level)  # Remember the conditional level
                else:
                    # Top-level define
                    formatted_line = stripped
                    define_stack.append(0)
                formatted_lines.append(formatted_line)
                if formatted_line != original_line.rstrip():
                    changed = True
                continue
            elif stripped == "endef":
                # Ending a define block
                if define_stack:
                    define_indent_level = define_stack.pop()
                    if define_indent_level > 0:
                        # endef inside conditional - indent to match define
                        formatted_line = base_indent * define_indent_level + stripped
                    else:
                        # Top-level endef
                        formatted_line = stripped
                else:
                    # No matching define (shouldn't happen in valid Makefiles)
                    formatted_line = stripped
                formatted_lines.append(formatted_line)
                if formatted_line != original_line.rstrip():
                    changed = True
                continue
            elif define_stack:
                # Inside a define block - normalize indentation within the block
                if define_stack[-1] > 0:  # Define block is inside a conditional
                    # Content inside define block gets same indentation as define keyword
                    formatted_line = base_indent * define_stack[-1] + stripped
                    formatted_lines.append(formatted_line)
                    if formatted_line != original_line.rstrip():
                        changed = True
                else:
                    # Top-level define block - use adaptive indentation
                    if stripped:  # Don't add indentation to empty lines
                        # Find the define start to determine adaptive indentation
                        define_start = None
                        for i in range(len(formatted_lines) - 1, -1, -1):
                            if formatted_lines[i].strip().startswith("define "):
                                define_start = i
                                break

                        if define_start is not None:
                            # Get the remaining lines to analyze
                            remaining_lines = (
                                formatted_lines
                                + [line]
                                + lines[len(formatted_lines) + 1 :]
                            )
                            target_indent = LineUtils.detect_define_block_indentation(
                                remaining_lines, define_start
                            )
                            formatted_line = target_indent + stripped
                        else:
                            # Fallback if we can't find the define start
                            formatted_line = "    " + stripped

                        formatted_lines.append(formatted_line)
                        if formatted_line != original_line.rstrip():
                            changed = True
                    else:
                        formatted_lines.append(line)
                continue

            # Handle conditional keywords
            if LineUtils.is_conditional_start(stripped):
                # Conditional start: ifeq, ifneq, ifdef, ifndef
                # Indent nested conditionals relative to their parent
                formatted_line = base_indent * indent_level + stripped
                formatted_lines.append(formatted_line)
                indent_level += 1
                if formatted_line != original_line.rstrip():
                    changed = True
            elif LineUtils.is_conditional_middle(stripped):
                # Middle: else, else if
                # Indent 'else' to match the corresponding 'if'
                indent_for_else = max(indent_level - 1, 0)
                formatted_line = base_indent * indent_for_else + stripped
                formatted_lines.append(formatted_line)
                if formatted_line != original_line.rstrip():
                    changed = True
            elif LineUtils.is_conditional_end(stripped):
                # Conditional end: endif
                indent_level = max(0, indent_level - 1)
                formatted_line = base_indent * indent_level + stripped
                formatted_lines.append(formatted_line)
                if formatted_line != original_line.rstrip():
                    changed = True
            elif indent_level > 0:
                # Inside conditional block - indent content
                if self._is_target_line(stripped):
                    # Target lines should not be indented - they define new targets
                    formatted_lines.append(line)
                elif use_tabs and line.startswith("\t"):
                    # Recipe lines (start with tab) - keep as is
                    formatted_lines.append(line)
                elif (
                    not use_tabs
                    and line.startswith(" " * tab_width)
                    and self._looks_like_recipe_line(line, tab_width)
                ):
                    # Recipe lines when using spaces - keep as is
                    formatted_lines.append(line)
                else:
                    # Any other content inside conditional block should be indented
                    formatted_line = base_indent * indent_level + stripped
                    formatted_lines.append(formatted_line)
                    if formatted_line != original_line.rstrip():
                        changed = True
            else:
                # Regular line outside conditionals
                formatted_lines.append(line)

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=[],
        )

    def _is_target_line(self, line: str) -> bool:
        """Check if line is a target definition."""
        # Target lines have : for dependencies, but not := for assignments
        # Also exclude conditional statements, dot directives, and Make function calls
        if line.startswith(("ifeq", "ifneq", "ifdef", "ifndef")):
            return False

        # Exclude dot directives like .PHONY, .SUFFIXES, etc.
        if line.startswith("."):
            return False

        # Exclude Make function calls like $(error...), $(warning...), etc.
        if line.startswith("$("):
            return False

        # Check for target pattern: target: dependencies
        # But exclude variable assignments like BUILDDIR := value
        colon_pos = line.find(":")
        if colon_pos == -1:
            return False

        # If there's a = after the colon, it's likely an assignment, not a target
        return not (colon_pos < len(line) - 1 and line[colon_pos + 1] == "=")

    def _should_indent_as_content(self, line: str) -> bool:
        """Check if line should be indented as conditional content."""
        # Include directives and other makefile constructs that should be indented
        return (
            line.startswith(("include", "-include", "export", "unexport"))
            or line.startswith(".")  # Other dot directives like .PHONY, .SUFFIXES, etc.
            or line.startswith(
                "$("
            )  # Make function calls like $(error...), $(warning...), etc.
            or line.startswith(("define", "endef"))  # Define blocks
        )

    def _looks_like_recipe_line(self, line: str, tab_width: int) -> bool:
        """Check if a line looks like a recipe line when using spaces."""
        # This is a heuristic - recipe lines typically have specific patterns
        if not line.startswith(" " * tab_width):
            return False

        # Look for common recipe patterns
        content = line.strip()
        # Commands often start with common shell commands or make functions
        recipe_indicators = [
            "@",
            "$",
            "echo",
            "mkdir",
            "rm",
            "cp",
            "mv",
            "cd",
            "make",
            "gcc",
            "g++",
            "python",
            "node",
            "npm",
            "go",
            "cargo",
            "docker",
            "kubectl",
        ]

        return any(content.startswith(indicator) for indicator in recipe_indicators)
