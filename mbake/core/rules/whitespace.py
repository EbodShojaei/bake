"""Whitespace cleanup rule for Makefiles."""

from typing import Any

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.rule_context import (
    cleanup_readings,
    empty_recipes_to_keep,
    significant_whitespace_lines,
)


class WhitespaceRule(FormatterPlugin):
    """Handles trailing whitespace removal and line normalization.

    Whitespace that make reads as data is kept (line numbers refer to the GNU
    make 4.4.1 manual):
    - a recipe line of only whitespace that gives a rule an empty recipe, so
      that no implicit rule applies (5.1, lines 2890-2891; 5.9, lines
      4040-4055), as one recipe prefix (see empty_recipes_to_keep);
    - define bodies, which are variable values (6.8, lines 4795-4814);
    - the trailing whitespace of a variable value (6.2.2, lines 4273-4288),
      and of an include directive whose file names make 3.81 reads
      differently without it (see include_whitespace_lines).

    A line counts as such wherever make may read it so, in any branch of the
    conditionals above it and with make 3.81 or 4.x (see
    LineState.readings). Keeping the whitespace of a line that make reads as
    a recipe line in other branches does not change the command.
    """

    def __init__(self) -> None:
        super().__init__(
            "whitespace", priority=45
        )  # Run late to clean up after other rules

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Remove trailing whitespace and normalize empty lines."""
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        remove_trailing_whitespace = config.get("remove_trailing_whitespace", True)
        normalize_empty_lines = config.get("normalize_empty_lines", True)

        # {index of a '# bake-format off' line: the lines it hides}
        hidden = context.get("disabled_region_lines") or {}
        # The whitespace after a final backslash goes as before, so the lines
        # are read as they will be after that, the last reading. An empty
        # recipe line is kept only where make reads it so in the lines as
        # they are as well.
        readings = cleanup_readings(lines, hidden, remove_trailing_whitespace)
        read_lines, states = readings[-1]
        empty_recipes = empty_recipes_to_keep(readings)
        value_lines = significant_whitespace_lines(read_lines, states)

        prev_was_empty = False

        for index, line in enumerate(read_lines):
            original = lines[index]
            if states[index].may_be_define_body:
                # A define body is the variable's value, blank lines and
                # trailing whitespace included.
                formatted_lines.append(line)
                changed = changed or line != original
                prev_was_empty = False
                continue

            # Remove trailing whitespace if enabled
            if remove_trailing_whitespace:
                if index in empty_recipes:
                    line = empty_recipes[index]
                elif index not in value_lines:
                    line = line.rstrip()

            # Normalize consecutive empty lines if enabled
            if normalize_empty_lines:
                is_empty = not line.strip() and index not in empty_recipes
                if is_empty and prev_was_empty:
                    # Skip this empty line (already have one)
                    changed = True
                    continue
                prev_was_empty = is_empty

            changed = changed or line != original
            formatted_lines.append(line)

        # Remove extra trailing empty lines. Blank lines of a define body that
        # the end of the file cuts off go too: make stops at such a body
        # ("missing 'endef'").
        while (
            len(formatted_lines) > 1
            and formatted_lines[-1] == ""
            and formatted_lines[-2] == ""
        ):
            formatted_lines.pop()
            changed = True

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=[],
        )
