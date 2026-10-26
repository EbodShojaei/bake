"""Tab formatting rule for Makefile recipes."""

import re
from collections.abc import Mapping, Sequence
from typing import Any, NamedTuple, Optional

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.line_utils import LineUtils
from ...utils.rule_context import (
    ASSIGNMENT,
    CONDITIONAL,
    DEFINE,
    DIRECTIVE,
    ENDEF,
    FUNCTION_CALL,
    OTHER,
    RECIPE,
    RULE,
    TARGET_VARIABLE,
    LineState,
    define_body_lines,
    line_by_line_prefixes,
    scan_makefile,
    strip_dangling_backslashes,
)

# Conditional directives that format() moves to column 1 or keeps, instead of
# treating them as recipe lines.
_CONDITIONAL_PREFIXES = ("ifeq", "ifneq", "ifdef", "ifndef", "else", "endif")

# The kinds of makefile syntax that make reads a line with leading spaces as,
# whatever its rule context: assignments and target-specific variables,
# directives such as 'sinclude', 'undefine' and 'override define', conditional
# directives, automake 'if' included, and calls of functions whose result is
# empty, such as '$(info ...)' (see rule_context.scan_makefile).
_MAKEFILE_SYNTAX_KINDS = frozenset(
    {ASSIGNMENT, TARGET_VARIABLE, DIRECTIVE, DEFINE, CONDITIONAL, FUNCTION_CALL}
)


class MakeReading(NamedTuple):
    """How make reads the lines that TabsRule formats (see TabsRule.make_reading).

    Attributes:
        states: The LineState of each line from TabsRule.read_lines
        reached: For each line, whether a rule context other than that of a
            .PHONY rule may reach it
    """

    states: Sequence[LineState]
    reached: Sequence[bool]


class TabsRule(FormatterPlugin):
    """Ensures tabs are used for recipe indentation instead of spaces."""

    def __init__(self) -> None:
        super().__init__("tabs", priority=10)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Convert spaces to tabs for recipe lines only."""
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []

        # Track conditional context when indentation is enabled
        indent_conditionals = config.get("indent_nested_conditionals", False)
        tab_width = config.get("tab_width", 4)
        conditional_stack: list[str] = [] if indent_conditionals else []

        # The lines of define bodies are the value of a variable, kept as
        # written (GNU make manual 6.8, lines 4795-4799); see _lines_to_leave.
        hidden = context.get("disabled_region_lines") or {}
        strip_dangling = config.get("remove_trailing_whitespace", True)
        leave = self._lines_to_leave(lines, hidden, strip_dangling)

        # With indent_nested_conditionals, ConditionalRule gives the makefile
        # syntax inside conditionals leading spaces, so a line with leading
        # spaces is no sign of a recipe line that lacks its TAB: it is read
        # as make reads it (see converts_to_recipe).
        reading: Optional[MakeReading] = None
        if indent_conditionals:
            reading = self.make_reading(lines, hidden, strip_dangling)

        for line_index, line in enumerate(lines):
            if line_index in leave:
                formatted_lines.append(line)
                continue

            # Skip empty lines
            if not line.strip():
                formatted_lines.append(line)
                continue

            # Skip comments
            if line.strip().startswith("#"):
                formatted_lines.append(line)
                continue

            # Get active recipe prefix for this line
            active_prefix = LineUtils.get_active_recipe_prefix(lines, line_index)

            # Skip lines that start directly with the active recipe prefix (already properly formatted)
            # But only if they don't need conditional indentation
            if (
                line.startswith(active_prefix) or line.startswith(active_prefix + "\t")
            ) and not indent_conditionals:
                formatted_lines.append(line)
                continue

            stripped = line.strip()

            # Track conditional context if indentation is enabled
            if indent_conditionals:
                self._update_conditional_stack(stripped, conditional_stack)

            # Handle conditional directives - these should start at column 1 according to GNU Make syntax
            # BUT: nested conditionals inside else blocks should preserve indentation
            if line.startswith(" ") and stripped.startswith(_CONDITIONAL_PREFIXES):

                # Check if this is a nested conditional that should preserve indentation
                if self._is_nested_conditional(line_index, lines, stripped):
                    # This is a nested conditional inside an else block - preserve indentation
                    formatted_lines.append(line)
                else:
                    # This is a top-level conditional directive - move to column 1
                    new_line = stripped
                    if new_line != line:
                        changed = True
                        formatted_lines.append(new_line)
                    else:
                        formatted_lines.append(line)
            # Check if this is a recipe line (command that should be executed)
            elif self.converts_to_recipe(
                line, line_index, lines, active_prefix, reading=reading
            ):
                # Convert leading spaces to tab for recipe lines
                content = line.lstrip()
                # Apply conditional nesting indentation if enabled
                if indent_conditionals and conditional_stack:
                    # Recipe should align with the conditional directive that contains it
                    # Calculate spaces needed, accounting for the mandatory tab's visual width
                    conditional_indent = (len(conditional_stack) - 1) * tab_width
                    # Subtract tab_width to compensate for the mandatory tab's visual width
                    recipe_spaces = max(0, conditional_indent - tab_width)
                    new_line = "\t" + " " * recipe_spaces + content
                else:
                    # For recipe lines, always use exactly one tab (GNU Make requirement)
                    new_line = "\t" + content
                if new_line != line:
                    changed = True
                    formatted_lines.append(new_line)
                else:
                    formatted_lines.append(line)
            # Enhanced recipe alignment when nested conditionals are enabled
            # This ONLY processes lines that actually have alignment problems
            elif (
                config.get("indent_nested_conditionals", False)
                and self._needs_recipe_alignment(line)  # MUST have alignment problems
                and line.startswith("\t")
                and stripped  # Not empty
                and not stripped.startswith("#")  # Not a comment
                and not self._is_target_definition(stripped)  # Not a target definition
                and not self._is_variable_assignment_line(
                    stripped
                )  # Not a variable assignment
                and not stripped.startswith(
                    ("include", "-include", "vpath")
                )  # Not include/vpath
                and not self._is_variable_continuation(
                    line, line_index, lines
                )  # Not variable continuation
                and not LineUtils.is_makefile_construct(
                    stripped
                )  # Not a makefile construct
            ):
                # Clean up mixed whitespace in recipe lines when conditional indentation is enabled
                content = line.lstrip()
                # Apply conditional nesting indentation if enabled
                if indent_conditionals and conditional_stack:
                    # Recipe should align with the conditional directive that contains it
                    # Calculate spaces needed, accounting for the mandatory tab's visual width
                    conditional_indent = (len(conditional_stack) - 1) * tab_width
                    # Subtract tab_width to compensate for the mandatory tab's visual width
                    recipe_spaces = max(0, conditional_indent - tab_width)
                    new_line = "\t" + " " * recipe_spaces + content
                else:
                    # For recipe lines, always use exactly one tab (GNU Make requirement)
                    new_line = "\t" + content
                if new_line != line:
                    changed = True
                    formatted_lines.append(new_line)
                else:
                    formatted_lines.append(line)
            elif line.startswith("\t"):
                # Already starts with tab - but may need conditional nesting adjustment
                if (
                    indent_conditionals
                    and conditional_stack
                    and stripped
                    and not stripped.startswith("#")
                    and not self._is_target_definition(stripped)
                    and not self._is_variable_assignment_line(stripped)
                    and not stripped.startswith(("include", "-include", "vpath"))
                    and not self._is_variable_continuation(line, line_index, lines)
                    and not LineUtils.is_makefile_construct(stripped)
                ):
                    # This is a recipe line that needs conditional nesting indentation
                    content = (
                        line.lstrip()
                    )  # Remove all leading whitespace (tabs/spaces)
                    if conditional_stack:
                        # Recipe should align with the conditional directive that contains it
                        # Calculate spaces needed, accounting for the mandatory tab's visual width
                        conditional_indent = (len(conditional_stack) - 1) * tab_width
                        # Subtract tab_width to compensate for the mandatory tab's visual width
                        recipe_spaces = max(0, conditional_indent - tab_width)
                        new_line = "\t" + " " * recipe_spaces + content
                    else:
                        # No nesting - just use one tab
                        new_line = "\t" + content
                    if new_line != line:
                        changed = True
                        formatted_lines.append(new_line)
                    else:
                        formatted_lines.append(line)
                else:
                    # Not a recipe line or no conditional context - preserve as-is
                    formatted_lines.append(line)
            else:
                # Not a recipe line, preserve as-is
                formatted_lines.append(line)

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=[],
        )

    # A rule line whose target holds '$', '{' or '%': a template that
    # $(eval $(call ...)) turns into a rule, whose recipe lines need a TAB
    _RULE_LINE = re.compile(r"^([^\s:#=][^:#=]*?)\s*::?(?!=)")

    @classmethod
    def _lines_to_leave(
        cls,
        lines: list[str],
        hidden: Mapping[int, Sequence[str]],
        strip_dangling: bool,
    ) -> set[int]:
        """
        Return the indexes of the define-body lines that format() leaves as written.

        A define body is the value of a variable, so its lines are data, not
        recipe lines (GNU make manual 6.8, lines 4795-4799): leading spaces
        there must not become a TAB. The one exception is a body that holds a
        rule template, a rule line whose target has '$', '{' or '%': after
        $(eval $(call ...)) make reads its recipe lines as recipe lines, so
        they keep getting their TAB, as before.

        With strip_dangling, the lines are read as WhitespaceRule leaves them
        when it removes trailing whitespace: a backslash that whitespace
        followed then continues the line, which can swallow a 'define'
        line, and this rule, which runs first, must make the same choice.
        """
        body = define_body_lines(lines, hidden, strip_dangling=strip_dangling)
        if not body:
            return set()
        leave: set[int] = set()
        run: list[int] = []
        for index in sorted(body):
            if run and index != run[-1] + 1:
                leave.update(cls._body_run_to_leave(lines, run))
                run = []
            run.append(index)
        leave.update(cls._body_run_to_leave(lines, run))
        return leave

    @classmethod
    def _body_run_to_leave(cls, lines: list[str], run: list[int]) -> set[int]:
        """Return the lines of one body to leave: all of them unless it is a template."""
        for index in run:
            match = cls._RULE_LINE.match(lines[index].strip())
            if match and any(c in match.group(1) for c in "$%{"):
                return set()
        return set(run)

    def converts_to_recipe(
        self,
        line: str,
        line_index: int,
        lines: list[str],
        active_prefix: str,
        *,
        reading: Optional[MakeReading] = None,
    ) -> bool:
        """
        Check if format() turns a line that starts with spaces into a recipe line.

        format() then replaces the leading spaces with a TAB. These are the
        lines that start with a space and are not:
        - blank lines or comments;
        - conditional directives, which format() moves to column 1 or keeps;
        - target definitions or variable assignments;
        - include or vpath directives;
        - continuations of a variable definition;
        - function calls and other makefile constructs;
        - lines that start with the active .RECIPEPREFIX character.

        With a reading, which format() makes with indent_nested_conditionals,
        lines that make reads as makefile syntax keep their spaces as well
        (see _keeps_leading_spaces).

        Args:
            line: The line to check
            line_index: Index of the line in lines
            lines: All lines that format() reads
            active_prefix: The recipe prefix that format() reads at the line
            reading: make_reading of lines, or None

        Returns:
            True if format() converts the line into a recipe line
        """
        stripped = line.strip()
        converts = (
            line.startswith(" ")
            and bool(stripped)  # Not empty
            and not stripped.startswith("#")  # Not a comment
            and not stripped.startswith(_CONDITIONAL_PREFIXES)
            and not self._is_target_definition(stripped)  # Not a target definition
            # Note: we DO want to process continuation lines for tab conversion
            and not self._is_variable_assignment_line(stripped)
            and not stripped.startswith(("include", "-include", "vpath"))
            and not self._is_variable_continuation(line, line_index, lines)
            and not LineUtils.is_makefile_construct(stripped)
            and not (
                line.startswith(active_prefix) or line.startswith(active_prefix + "\t")
            )  # Not direct .RECIPEPREFIX line
        )
        if not converts or reading is None:
            return converts
        return not self._keeps_leading_spaces(reading, line_index)

    @classmethod
    def make_reading(
        cls,
        lines: list[str],
        hidden: Mapping[int, Sequence[str]],
        strip_dangling: bool,
    ) -> Optional[MakeReading]:
        """
        Return how make reads the lines, for converts_to_recipe.

        The rule contexts are those that remain where the lines of .PHONY
        The rule contexts are those that remain where the lines of .PHONY
        rules are taken out. make runs the recipe of .PHONY only when .PHONY
        itself is named as a goal, which no build does: a target that starts
        with a period is never the default goal (GNU make manual 4.1, lines
        1443-1446). With auto_insert_phony_declarations, PhonyRule may also
        move those lines. A line with leading spaces whose only rule context
        is that of .PHONY therefore keeps its spaces, which reads the same in
        every case; a TAB would make it a recipe line of .PHONY, or leave it
        without a rule context.

        Args:
            lines: The lines that the rule formats
            hidden: The lines that '# bake-format off' regions hide, as in
                context['disabled_region_lines']
            strip_dangling: The value of remove_trailing_whitespace

        Returns:
            The reading, or None where make's recipe prefix is not the one
            that the rules read (see reads_prefix_as_make)
        """
        states = cls.read_lines(lines, hidden, strip_dangling)
        if not cls.reads_prefix_as_make(lines, states):
            return None
        others = cls.read_lines_without_phony(lines, hidden, strip_dangling, states)
        return MakeReading(states, [state.rule_context for state in others])

    @classmethod
    def read_lines_without_phony(
        cls,
        lines: list[str],
        hidden: Mapping[int, Sequence[str]],
        strip_dangling: bool,
        states: Sequence[LineState],
        *,
        past_errors: bool = False,
    ) -> Sequence[LineState]:
        """
        Return read_lines of the lines with the lines of .PHONY rules blank.

        That is how make reads the lines where the rule contexts of .PHONY
        rules are left out (see make_reading).

        Args:
            lines: The lines that the rule formats
            hidden: As for read_lines
            strip_dangling: As for read_lines
            states: read_lines of the lines
            past_errors: As for read_lines

        Returns:
            The LineState of each line; states itself where no line is a
            .PHONY rule and past_errors is False
        """
        phony = [
            index for index, state in enumerate(states) if cls._declares_phony(state)
        ]
        if not phony and not past_errors:
            return states
        without_phony = list(lines)
        for index in phony:
            without_phony[index] = ""
        return cls.read_lines(
            without_phony, hidden, strip_dangling, past_errors=past_errors
        )

    @staticmethod
    def read_lines(
        lines: list[str],
        hidden: Mapping[int, Sequence[str]],
        strip_dangling: bool,
        *,
        past_errors: bool = False,
    ) -> list[LineState]:
        """
        Return how make reads the lines, as the run after this one reads them.

        With strip_dangling, the lines are read as WhitespaceRule leaves them
        when it removes trailing whitespace: a backslash that whitespace
        followed then continues the line (GNU make manual 3.1.1, lines
        762-769), and the next run reads the lines that way, so the rules
        that run before WhitespaceRule make their choices on that reading,
        as _lines_to_leave does.

        Args:
            lines: The lines that the rule formats
            hidden: The lines that '# bake-format off' regions hide, as in
                context['disabled_region_lines']
            strip_dangling: The value of remove_trailing_whitespace
            past_errors: Read on past the lines where make stops with an
                error, as rule_context.scan_makefile does with it

        Returns:
            A LineState for each line (see rule_context.scan_makefile)
        """
        if strip_dangling:
            stripped, states = strip_dangling_backslashes(lines, hidden)
            if not past_errors:
                return states
            # WhitespaceRule strips the lines that make's reading puts outside
            # define bodies; those lines are then read on past errors.
            return scan_makefile(stripped, hidden, past_errors=True)
        return scan_makefile(lines, hidden, past_errors=past_errors)

    @staticmethod
    def reads_prefix_as_make(lines: list[str], states: Sequence[LineState]) -> bool:
        """
        Check if the rules read the recipe prefix of every line as make does.

        The rules read .RECIPEPREFIX line by line (see
        rule_context.line_by_line_prefixes), as they always did: they miss a
        prefix that is set with '+=', with define or with a reference, or on
        a line that '# bake-format off' hides (GNU make manual, lines
        5158-5169). Where make's prefix differs from that reading, or make
        computes it, a choice made on make's reading of the lines would not
        match the choices of the other rules, which can move lines in or out
        of a rule context, so the choices of before are kept there.

        Args:
            lines: The lines that the rule formats
            states: read_lines of the lines

        Returns:
            True if make's prefix is known and is the line-by-line prefix at
            every line
        """
        return all(
            state.recipe_prefix_known and state.recipe_prefix == prefix
            for state, prefix in zip(states, line_by_line_prefixes(lines))
        )

    @staticmethod
    def _keeps_leading_spaces(reading: MakeReading, index: int) -> bool:
        """
        Check if a line with leading spaces must not get a TAB in their place.

        make reads a line that does not start with the recipe prefix as
        makefile syntax, whatever its leading spaces (GNU make manual 3.8,
        lines 1209-1229). A TAB in their place makes it a recipe line in a
        rule context (lines 1217-1219; 5.1, lines 2878-2884), and outside one
        make stops at it ("recipe commences before first target", lines
        11292-11297). So the line keeps its spaces when:
        - make reads it as makefile syntax that works there: an assignment,
          a target-specific variable, a directive, a define, a conditional
          directive or a call of functions whose result is empty;
        - no rule context but that of a .PHONY rule can reach it (see
          make_reading);
        - it is only variable references, such as '$(R)' or
          '$(call setup)', which make expands and reads as makefile syntax:
          they may expand to nothing or to a rule (3.8, lines 1231-1236).
        Other text in a rule context, such as 'echo hi' or '$(MAKE) -C
        sub', makes make stop with "missing separator", so it is a recipe
        line that lacks its TAB, as before. So are recipe lines, the lines
        that continue them and the recipe lines of a $(eval) template in a
        define body.

        Args:
            reading: make_reading of the lines
            index: The index of the line

        Returns:
            True if the line keeps its leading spaces
        """
        state = reading.states[index]
        if state.kind in (RECIPE, ENDEF) or state.may_be_define_body:
            return False
        if state.kind in _MAKEFILE_SYNTAX_KINDS or not reading.reached[index]:
            return True
        return state.kind == OTHER and LineUtils.is_reference_only(state.text)

    @staticmethod
    def _declares_phony(state: LineState) -> bool:
        """Check if a logical line is a rule whose one target is .PHONY."""
        if state.kind != RULE:
            return False
        code = state.text
        comment = LineUtils.find_comment_start(code)
        if comment is not None:
            code = code[:comment]
        colon = LineUtils.find_unquoted_char(code, ":")
        return colon is not None and code[:colon].split() == [".PHONY"]

    def _is_nested_conditional(
        self, line_index: int, lines: list[str], stripped: str
    ) -> bool:
        """Check if this conditional directive is nested inside another conditional block."""
        if line_index == 0:
            return False

        # Track conditional nesting depth
        conditional_depth = 0

        # Look backwards to see if we're inside a conditional block
        for i in range(line_index - 1, -1, -1):
            prev_line = lines[i]
            prev_stripped = prev_line.strip()

            # Skip empty lines and comments
            if not prev_stripped or prev_stripped.startswith("#"):
                continue

            # Check for conditional directives
            if prev_stripped.startswith("endif"):
                conditional_depth += 1
            elif prev_stripped.startswith(("ifeq", "ifneq", "ifdef", "ifndef")):
                conditional_depth -= 1

                # If we've reached depth 0, we found the matching opening conditional
                if conditional_depth < 0:
                    # We are inside a conditional block, so this could be nested
                    # But only preserve indentation for conditionals inside else blocks
                    # or for nested conditionals that have meaningful indentation
                    return True

        return False

    def _is_variable_continuation(
        self, line: str, line_index: int, lines: list[str]
    ) -> bool:
        """Check if this line is a continuation of a variable definition."""
        if line_index == 0:
            return False

        # Look at the previous line(s) to see if this is a continuation
        for i in range(line_index - 1, -1, -1):
            prev_line = lines[i]
            prev_stripped = prev_line.strip()

            # Skip empty lines and comments
            if not prev_stripped:
                break
            if prev_stripped.startswith("#"):
                continue

            # If we find a line ending with \, this could be a continuation
            if prev_stripped.endswith("\\"):
                # Check if it's a variable assignment or part of one
                # Look for the original assignment line
                for j in range(i, -1, -1):
                    check_line = lines[j].strip()
                    if not check_line or check_line.startswith("#"):
                        continue
                    if "=" in check_line and not check_line.startswith("\t"):
                        return True
                    if not check_line.endswith("\\"):
                        break
                return False
            else:
                # No backslash, so this is not a continuation
                return False

        return False

    def _is_variable_assignment_line(self, stripped: str) -> bool:
        """Check if this is a Makefile variable assignment (not a shell command with =)."""
        if "=" not in stripped:
            return False

        # Use the existing LineUtils method which properly detects Makefile variable assignments
        return LineUtils.is_variable_assignment(stripped)

    def _is_target_definition(self, stripped: str) -> bool:
        """Check if this is a target definition (not a command with colons)."""
        if ":" not in stripped:
            return False

        # Basic target pattern: target_name : prerequisites
        # The colon should be at the top level, not inside quotes, parentheses, etc.

        # Find the position of the first unquoted, unescaped colon
        in_single_quote = False
        in_double_quote = False
        paren_depth = 0
        i = 0

        while i < len(stripped):
            char = stripped[i]

            # Handle escape sequences
            if char == "\\" and i + 1 < len(stripped):
                i += 2  # Skip escaped character
                continue

            # Handle quotes
            if char == "'" and not in_double_quote:
                in_single_quote = not in_single_quote
            elif char == '"' and not in_single_quote:
                in_double_quote = not in_double_quote
            elif char == "(" and not in_single_quote and not in_double_quote:
                paren_depth += 1
            elif char == ")" and not in_single_quote and not in_double_quote:
                paren_depth -= 1
            elif (
                char == ":"
                and not in_single_quote
                and not in_double_quote
                and paren_depth == 0
            ):
                # Found an unquoted, top-level colon
                # Check if this looks like a target definition
                target_part = stripped[:i].strip()

                # Empty target part means this isn't a target definition
                if not target_part:
                    return False

                # Target names shouldn't contain spaces (unless escaped or quoted)
                # But make does allow multiple targets separated by spaces
                # So we'll be conservative and say if it contains unquoted spaces, it's likely not a target

                # Check for obvious non-target patterns
                return not (
                    target_part.startswith(("@", "-", "+"))  # Recipe prefixes
                    or "=" in target_part  # Variable assignments within
                    or target_part.endswith("\\")  # Continuation lines
                )

            i += 1

        return False

    def _needs_recipe_alignment(self, line: str) -> bool:
        """Check if line has mixed whitespace or excessive tabs that need alignment."""
        if not line:
            return False

        # Check for mixed tabs and spaces at the beginning
        leading_chars = []
        for char in line:
            if char in [" ", "\t"]:
                leading_chars.append(char)
            else:
                break

        # Mixed whitespace means we have both tabs and spaces in the leading whitespace
        has_tab = "\t" in leading_chars
        has_space = " " in leading_chars
        mixed_whitespace = has_tab and has_space

        # Check for excessive tabs (more than one leading tab)
        if line.startswith("\t"):
            tab_count = 0
            for char in line:
                if char == "\t":
                    tab_count += 1
                else:
                    break
            excessive_tabs = tab_count > 1
        else:
            excessive_tabs = False

        return mixed_whitespace or excessive_tabs

    def _update_conditional_stack(
        self, stripped_line: str, conditional_stack: list[str]
    ) -> None:
        """Update the conditional stack based on the current line."""
        if not stripped_line:
            return

        # Check for conditional directives
        if stripped_line.startswith(("ifeq", "ifneq", "ifdef", "ifndef")):
            # Opening conditional - add to stack
            conditional_type = (
                stripped_line.split()[0]
                if " " in stripped_line
                else stripped_line.split("(")[0]
            )
            conditional_stack.append(conditional_type)
        elif stripped_line.startswith("endif"):
            # Closing conditional - remove from stack
            if conditional_stack:
                conditional_stack.pop()
        # Note: 'else' doesn't change the stack depth, just the branch
