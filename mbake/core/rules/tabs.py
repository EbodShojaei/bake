"""Tab formatting rule for Makefile recipes."""

import re
from collections.abc import Container, Mapping, Sequence
from typing import Any, NamedTuple, Optional

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.line_utils import LineUtils, ShellUtils
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
    DanglingRepairs,
    LineState,
    accepted_definition,
    define_body_lines,
    ends_rule_context,
    inline_recipe_start,
    line_by_line_prefixes,
    make_kinds,
    recipe_line_follows,
    repair_dangling_backslashes,
    scan_makefile,
    stands_alone_as_syntax,
    stands_alone_without_targets,
)
from .recipe_validation import RecipeValidationRule

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
        phony_lines_move = self.phony_lines_move(config)
        strip_dangling = config.get("remove_trailing_whitespace", True)
        leave = self._lines_to_leave(lines, hidden, strip_dangling)
        # The lines whose whitespace after a final backslash goes (see
        # dangling_backslash_repairs); on other lines it keeps the backslash
        # from continuing the line (GNU make manual 3.1.1, lines 762-769).
        # Without remove_trailing_whitespace every such line stays, and the
        # line after it is read as before (see _is_variable_continuation).
        repaired = DanglingRepairs(lines, hidden, strip_dangling)
        continued_over = repaired if strip_dangling else None

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
                    if (
                        LineUtils.has_dangling_backslash(line)
                        and line_index not in repaired
                    ):
                        new_line = line.lstrip()
                    if new_line != line:
                        changed = True
                        formatted_lines.append(new_line)
                    else:
                        formatted_lines.append(line)
            # Check if this is a recipe line (command that should be executed)
            elif self.converts_to_recipe(
                line,
                line_index,
                lines,
                active_prefix,
                reading=reading,
                phony_lines_move=phony_lines_move,
                repaired=continued_over,
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
                    line, line_index, lines, phony_lines_move, continued_over
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
                    and not self._is_variable_continuation(
                        line, line_index, lines, phony_lines_move, continued_over
                    )
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

        if changed:
            formatted_lines = self._keep_shell_text(lines, formatted_lines, hidden)
            if config.get("fix_missing_recipe_tabs", True) and not config.get(
                "normalize_line_continuations", True
            ):
                formatted_lines = self._recipe_tabs_below(
                    lines, formatted_lines, hidden, strip_dangling
                )
            changed = formatted_lines != lines

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=[],
        )

    @staticmethod
    def _recipe_tabs_below(
        lines: list[str],
        formatted: list[str],
        hidden: Mapping[int, Sequence[str]],
        strip_dangling: bool,
    ) -> list[str]:
        """
        Give the lines below a new TAB the TAB that the next run gives them.

        RecipeValidationRule, which runs before this rule, reads a line at
        column 1 below a line that starts with spaces otherwise than below one
        that starts with a TAB, so below a line that this rule gives a TAB it
        may give such a line one on the next run. Without ContinuationRule
        (normalize_line_continuations off), which otherwise decides the
        indentation of continuation lines between the two rules, the line
        gets that TAB now, as RecipeValidationRule reads the lines on the next
        run: after WhitespaceRule has removed the whitespace after a final
        backslash where dangling_backslash_repairs finds it. On a
        continuation line of a recipe, RecipeValidationRule gives only the
        TAB that make removes, the recipe prefix (GNU make manual 5.1.1,
        lines 2917-2925; see RecipeValidationRule._continuation_keeps_its_start).

        Args:
            lines: The lines that format() read
            formatted: The lines that format() made of them
            hidden: The lines that '# bake-format off' regions hide
            strip_dangling: Whether remove_trailing_whitespace is on

        Returns:
            formatted, with those lines given a TAB
        """
        first = next(
            (
                index
                for index, line in enumerate(formatted)
                if line.startswith("\t") and not lines[index].startswith("\t")
            ),
            None,
        )
        if first is None:
            return formatted
        read = formatted
        if strip_dangling:
            read = repair_dangling_backslashes(formatted, hidden)[0]
        candidates = [
            index
            for index in range(first + 1, len(read))
            if read[index].strip() and read[index][:1] not in (" ", "\t")
        ]
        if not candidates:
            return formatted
        rule = RecipeValidationRule()
        facts = rule.line_facts(
            read, {index: list(region) for index, region in hidden.items()}
        )
        result = list(formatted)
        for index in candidates:
            if rule.is_missing_recipe_tab(
                read[index], index, read, facts.formatter_prefix(index), facts
            ):
                result[index] = "\t" + result[index]
        return result

    @staticmethod
    def _keep_shell_text(
        lines: list[str],
        formatted: list[str],
        hidden: Mapping[int, Sequence[str]],
    ) -> list[str]:
        """
        Undo new indentation of continuation lines that changes a command.

        make passes the continuation lines of a recipe line to the shell
        with their whitespace, without only the one recipe prefix character
        that starts them (GNU make manual 5.1.1, lines 2917-2925), and the
        same holds for the recipe after the ';' of a rule line (4.2, lines
        1499-1503). Each continuation line keeps its new indentation where
        the shell still gets the same words (see ShellUtils.keep_shell_text):
        a TAB in place of leading spaces where a blank ends the line above,
        or where the TAB is the prefix that make removes and another blank
        follows it, but not where the line above ends with a word right
        before its backslash, which the line's first word would then join
        ('do\\' and 'echo' would run 'doecho'). In a makefile where
        ShellUtils.recipes_are_shell_opaque holds, a line keeps only the
        changes that leave its text as the shell gets it. Each line is
        judged on its own, from the lines as format() read them, so a second
        run keeps the same lines.

        Args:
            lines: The lines that format() read
            formatted: The lines that format() made of them
            hidden: The lines that '# bake-format off' regions hide

        Returns:
            formatted, with those continuation lines as they were in lines
        """
        changed = [
            index
            for index in range(1, len(lines))
            if formatted[index] != lines[index]
            and LineUtils.ends_with_continuation(lines[index - 1])
        ]
        if not changed:
            return formatted
        states = scan_makefile(lines, hidden)
        result = list(formatted)
        opaque: Optional[bool] = None
        checked: set[int] = set()
        for index in changed:
            state = states[index]
            start = state.logical_start
            if not state.continuation or start in checked:
                continue
            checked.add(start)
            end = start + 1
            while (
                end < len(lines)
                and states[end].continuation
                and states[end].logical_start == start
            ):
                end += 1
            if any(hidden.get(position) for position in range(start, end - 1)):
                # Lines that '# bake-format off' hides are part of the
                # logical line: what the shell gets is not known.
                result[start + 1 : end] = lines[start + 1 : end]
                continue
            head = 0
            column = 0
            new_column = 0
            # A rule line that this rule turns into a recipe line, as before,
            # in a rule context, where the next run reads the lines as a
            # recipe line (GNU make manual 3.8, lines 1217-1219)
            becomes_recipe = result[start] != lines[start] and state.rule_context_read
            if RECIPE not in make_kinds(state) and not becomes_recipe:
                inline, position = inline_recipe_start(lines[start:end], state)
                if not inline:
                    # Makefile syntax, which make joins with one space (GNU
                    # make manual 3.1.1, lines 776-781)
                    continue
                if position is None:
                    result[start + 1 : end] = lines[start + 1 : end]
                    continue
                # The recipe starts after the ';'; a new indentation of the
                # line with the ';' is whitespace among the prerequisites.
                head, column = position
                old_line = lines[start + head]
                new_line = result[start + head]
                new_column = (
                    column
                    + len(new_line)
                    - len(new_line.lstrip())
                    - (len(old_line) - len(old_line.lstrip()))
                )
            if opaque is None:
                opaque = ShellUtils.recipes_are_shell_opaque(lines, hidden)
            old = [lines[start + head][column:], *lines[start + head + 1 : end]]
            new = [result[start + head][new_column:], *result[start + head + 1 : end]]
            kept = ShellUtils.keep_shell_text(
                old, new, state.recipe_prefix, opaque=opaque
            )
            if kept[0] != new[0] and not becomes_recipe:
                result[start + head] = lines[start + head]
            result[start + head + 1 : end] = kept[1:]
        return result

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
        followed then continues the line where dangling_backslash_repairs
        finds it, which can swallow a 'define' line, and this rule, which
        runs first, must make the same choice.
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

    @staticmethod
    def phony_lines_move(config: dict) -> bool:
        """
        Check if PhonyRule may insert, group or move '.PHONY:' lines.

        It does so only with auto_insert_phony_declarations on; otherwise it
        leaves the lines as they are.
        """
        return bool(config.get("auto_insert_phony_declarations", False))

    def converts_to_recipe(
        self,
        line: str,
        line_index: int,
        lines: list[str],
        active_prefix: str,
        *,
        reading: Optional[MakeReading] = None,
        phony_lines_move: bool = False,
        repaired: Optional[Container[int]] = None,
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
        - lines that start with the active .RECIPEPREFIX character;
        - rule lines without targets, such as '    \\;', that no recipe
          line may follow (see rule_context.stands_alone_without_targets).

        With a reading, which format() makes with indent_nested_conditionals,
        lines that make reads as makefile syntax keep their spaces as well
        (see _keeps_leading_spaces).

        Args:
            line: The line to check
            line_index: Index of the line in lines
            lines: All lines that format() reads
            active_prefix: The recipe prefix that format() reads at the line
            reading: make_reading of lines, or None
            phony_lines_move: Whether PhonyRule may insert, group or move
                '.PHONY:' lines (see phony_lines_move)
            repaired: The lines whose whitespace after a final backslash
                WhitespaceRule removes, as format() reads them (see
                rule_context.DanglingRepairs), or None where it removes
                none: _is_variable_continuation then counts every such line
                right above the line, as before

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
            and not self._is_variable_continuation(
                line, line_index, lines, phony_lines_move, repaired
            )
            and not LineUtils.is_makefile_construct(stripped)
            and not (
                line.startswith(active_prefix) or line.startswith(active_prefix + "\t")
            )  # Not direct .RECIPEPREFIX line
            and not self._starts_continued_definition(line, line_index, lines)
            and not stands_alone_without_targets(lines, line_index)
        )
        if not converts or reading is None:
            return converts
        return not self._keeps_leading_spaces(reading, line_index)

    def _starts_continued_definition(
        self, line: str, line_index: int, lines: list[str]
    ) -> bool:
        """
        Check if a line starts a rule or an assignment that it continues.

        make reads a line that does not start with the recipe prefix as
        makefile syntax, joined with the lines that it continues over (GNU
        make manual 3.1.1, lines 776-781; 3.8, lines 1209-1229): '  d \\'
        and 't3: ; echo x' are one rule, whose targets are d and t3, and
        whose recipe is 'echo x'. A TAB in place of the leading spaces would
        make the lines a recipe line of a rule above them (lines 1217-1219),
        or one that make rejects ("recipe commences before first target",
        lines 11292-11297), so the line keeps its spaces, as a rule or an
        assignment on one physical line does. That holds only where make
        reads a rule or an assignment that it accepts in the logical line
        (see rule_context.accepted_definition). Elsewhere make stops at the
        line ("missing separator", lines 11275-11281), as at 'cd dist; \\'
        and 'scp app host:/srv', whose ':' comes after the ';', or at 'cc
        main.c \\' and 'util.c # note: both', whose ':' is in the comment:
        the line is then a recipe line that lacks its TAB, as before. So is
        an assignment that a recipe line may follow (see
        rule_context.recipe_line_follows): an assignment ends the rule
        context (5.1, lines 2881-2884), so make rejects a recipe line after
        it ("recipe commences before first target"), while with the TAB both
        stay recipe lines of the rule above.
        """
        if not LineUtils.ends_with_continuation(line) or (
            line_index > 0 and LineUtils.ends_with_continuation(lines[line_index - 1])
        ):
            return False
        joined, after = LineUtils.join_logical_line(lines, line_index)
        kind = accepted_definition(joined)
        if kind is None or kind == RULE:
            return kind is not None
        return not recipe_line_follows(lines, after)

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
        followed then continues the line where dangling_backslash_repairs
        finds it (GNU make manual 3.1.1, lines 762-769), and the next run
        reads the lines that way, so the rules that run before WhitespaceRule
        make their choices on that reading, as _lines_to_leave does.

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
            stripped, states = repair_dangling_backslashes(lines, hidden)
            if not past_errors:
                return states
            # WhitespaceRule strips the lines that dangling_backslash_repairs
            # finds in make's reading; those lines are then read on past
            # errors.
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
        self,
        line: str,
        line_index: int,
        lines: list[str],
        phony_lines_move: bool = False,
        repaired: Optional[Container[int]] = None,
    ) -> bool:
        """
        Check if this line is a continuation of a variable definition.

        The lines above it are followed through comments, as before. A
        backslash that whitespace follows continues no line (GNU make manual
        3.1.1, lines 762-769). WhitespaceRule makes it continue only onto the
        line right after it, where make rejects that line on its own (see
        dangling_backslash_repairs), so such a backslash counts only on the
        line right above this one; elsewhere it ends the lines followed.

        Where make does not continue the line right above onto this one, as
        after an even run of backslashes, or after a backslash that
        whitespace follows and that stays (repaired holds the lines that
        WhitespaceRule repairs; with None every such line counts as
        repaired), this line stands on its own. It then counts as a
        continuation, which keeps its spaces, where make reads it as
        makefile syntax (see rule_context.stands_alone_as_syntax), and below
        an even run of backslashes at the end of an assignment, which ends
        the rule context (5.1, lines 2881-2884): a TAB there makes a recipe
        line that make rejects. Other text there is a recipe line that lacks
        its TAB, as dangling_backslash_repairs takes it, such as a line below
        the recipe line 'echo a=b\\\\'; below a backslash that whitespace
        follows, where no rule context reaches the line, WhitespaceRule then
        makes the backslash continue the line, as in v1.5.0.

        The lines followed include the line above the first line of the
        logical line, as before. With phony_lines_move, PhonyRule may insert,
        group or move '.PHONY:' lines, such as one right above a rule, so
        those lines are passed over: the answer is then the same before and
        after it does, and a second run changes nothing.
        """
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
            if prev_stripped.endswith("\\") and not (
                LineUtils.has_dangling_backslash(prev_line) and i + 1 < line_index
            ):
                found = self._assignment_above(i, lines, phony_lines_move)
                continues = LineUtils.ends_with_continuation(prev_line) or (
                    LineUtils.has_dangling_backslash(prev_line)
                    and (repaired is None or i in repaired)
                )
                if found and not continues:
                    joined = LineUtils.join_logical_line(lines, line_index)[0]
                    if stands_alone_as_syntax(joined):
                        return True
                    if LineUtils.has_dangling_backslash(prev_line):
                        return False
                    start = self._logical_start(lines, i, repaired)
                    prefix = LineUtils.get_active_recipe_prefix(lines, start)
                    above = LineUtils.join_logical_line(lines, start)[0]
                    return not lines[start].startswith(prefix) and ends_rule_context(
                        above
                    )
                return found
            else:
                # No backslash, so this is not a continuation
                return False

        return False

    @staticmethod
    def _logical_start(
        lines: list[str], index: int, repaired: Optional[Container[int]]
    ) -> int:
        """Return the first line of the logical line that lines[index] is
        part of, for _is_variable_continuation: a backslash that whitespace
        follows continues the line only where repaired holds it (with None,
        everywhere), as there."""
        start = index
        while start > 0:
            above = lines[start - 1]
            if not LineUtils.ends_with_continuation(above) and not (
                LineUtils.has_dangling_backslash(above)
                and (repaired is None or start - 1 in repaired)
            ):
                break
            start -= 1
        return start

    @staticmethod
    def _assignment_above(i: int, lines: list[str], phony_lines_move: bool) -> bool:
        """Check if the lines that end with a backslash, up from lines[i],
        start a variable assignment, for _is_variable_continuation."""
        for j in range(i, -1, -1):
            check_line = lines[j].strip()
            if (
                not check_line
                or check_line.startswith("#")
                or (phony_lines_move and check_line.startswith(".PHONY:"))
            ):
                continue
            if j < i and LineUtils.has_dangling_backslash(lines[j]):
                break
            if "=" in check_line and not check_line.startswith("\t"):
                return True
            if not check_line.endswith("\\"):
                break
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
