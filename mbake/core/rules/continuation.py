"""Line continuation formatting rule for Makefiles."""

from collections.abc import Mapping, Sequence
from typing import Any, Optional

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.line_utils import LineUtils, ShellUtils
from ...utils.rule_context import (
    RECIPE,
    LineState,
    dangling_backslash_repairs,
    inline_recipe_start,
    make_kinds,
    scan_makefile,
)
from .recipe_validation import RecipeValidationRule
from .tabs import TabsRule

# The warning for a final backslash that whitespace follows, on a line that
# stays as written (GNU make manual 3.1.1, lines 762-769)
DANGLING_BACKSLASH_WARNING = (
    "Backslash followed by trailing whitespace does not continue the line"
)


class _Makefile:
    """The lines that the rule formats, and what it learns about the file."""

    def __init__(
        self,
        lines: list[str],
        hidden: Mapping[int, Sequence[str]],
        states: list[LineState],
        config: Optional[dict] = None,
    ) -> None:
        self.lines = lines
        self.hidden = hidden
        self.states = states
        self.config = config or {}
        self._opaque: Optional[bool] = None
        self._posix_line: Optional[int] = None
        self._posix_known = False
        self._tabs_lines: Optional[list[str]] = None

    @property
    def opaque(self) -> bool:
        """See ShellUtils.recipes_are_shell_opaque."""
        if self._opaque is None:
            self._opaque = ShellUtils.recipes_are_shell_opaque(self.lines, self.hidden)
        return self._opaque

    def posix_at(self, index: int) -> bool:
        """
        Check if make 4.x reads the line at index in POSIX mode.

        That is so after the first line that names .POSIX as a target (GNU
        make manual 4.9, lines 2417-2423; see LineUtils.first_target_line):
        make reads the lines above it in the usual way.
        """
        if not self._posix_known:
            self._posix_line = LineUtils.first_target_line(
                self.lines, ".POSIX", self.hidden
            )
            self._posix_known = True
        return self._posix_line is not None and index > self._posix_line

    def tabs_indent(self, index: int) -> Optional[str]:
        """
        Return the new indentation that TabsRule gives the line at index.

        TabsRule runs after this rule. A block whose continuation lines all
        get the indentation of its first continuation line gets the one that
        TabsRule then gives that line, such as the TAB for its leading
        spaces, so that all of them keep the same indentation on the next
        run, also where TabsRule would not change the others on its own.

        Returns:
            The indentation, or None where TabsRule changes nothing but the
            indentation of the line
        """
        old = self.lines[index]
        if not old.startswith(" ") and not self.config.get(
            "indent_nested_conditionals", False
        ):
            # Without indent_nested_conditionals, TabsRule changes only lines
            # that start with a space.
            return None
        if self._tabs_lines is None:
            context = {"disabled_region_lines": self.hidden} if self.hidden else {}
            self._tabs_lines = (
                TabsRule().format(list(self.lines), self.config, False, **context).lines
            )
        new = self._tabs_lines[index]
        content = new.lstrip(" \t")
        if new == old or content != old.lstrip(" \t"):
            return None
        return new[: len(new) - len(content)]


class ContinuationRule(FormatterPlugin):
    """
    Handles proper formatting of line continuations with backslashes.

    A line continues on the next one where an odd number of backslashes ends
    it, with nothing after them (GNU make manual 3.1, lines 730-733; 3.1.1,
    lines 762-769). A block is such a line and the lines it continues over;
    its last line is the first one that does not continue, and it keeps its
    trailing whitespace, which can be part of a variable value (6.2.2, lines
    4273-4288).

    Outside a recipe, make turns each backslash/newline and the whitespace
    around it into one space (3.1.1, lines 776-781), so the lines after the
    first get the indentation of the second line, or the TAB that TabsRule
    gives the second line (as it does to the continuation of a comment), and
    one space before their backslash. make keeps the whitespace before the
    backslash in two cases, where only the indentation changes: below a line
    that names the .POSIX target, in make 4.x (lines 783-786), and before a
    run of three or more backslashes, which make halves into text. A line of
    a define body, the value of a variable (6.8, lines 4795-4799), stays as
    written.

    In a recipe, make passes each backslash/newline to the shell with the
    whitespace around it, and removes only the one recipe prefix character
    that starts the next line (5.1.1, lines 2917-2925). In a block that make
    may read as a recipe line, or in the lines after the ';' of a rule line
    (4.2, lines 1499-1503), which may be any of its physical lines, each
    line changes as before only where the shell still gets the same words
    (see ShellUtils.keep_shell_text): the blanks of quoted text, of a
    here-document and between two words that a backslash joins stay as
    written, and in a makefile where ShellUtils.recipes_are_shell_opaque
    holds, only the recipe prefix may come or go. A line's new indentation
    and the new blanks before its backslash are tried together and then each
    alone, as each touches only the backslash/newline on its side. A recipe
    line at column 1, without the prefix, that RecipeValidationRule never
    gives a TAB keeps its start, so that make passes on and prints its text
    as written, and so does a line that begins inside quotes or a
    here-document (see ShellUtils.keep_shell_text). The continuation lines
    get the indentation that TabsRule, which runs next, gives the first of
    them (see _Makefile.tabs_indent), so that a second run changes nothing;
    where TabsRule gives the first line of a rule a TAB, which makes it a
    recipe line, a shell control block keeps the indentation of its lines,
    as the next run does. Where make stops at the block's first line in
    every reading, the one model of scan_makefile decides whether it is a
    recipe (see rule_context.make_kinds), as it does on the next run, after
    other rules have changed the lines.

    A backslash that whitespace follows does not continue a line. Where make
    rejects the next line on its own, that whitespace goes, as it always did,
    and the line is formatted with its block (see dangling_backslash_repairs),
    unless remove_trailing_whitespace is off. Every other such line stays as
    written, with a warning; in a define body too, where the backslash and
    the whitespace are part of the value.
    """

    def __init__(self) -> None:
        super().__init__("continuation", priority=9)  # Run before tabs rule

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Normalize line continuation formatting."""
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

        hidden: Mapping[int, Sequence[str]] = context.get("disabled_region_lines") or {}
        repairs: set[int] = set()
        if config.get("remove_trailing_whitespace", True):
            repairs = dangling_backslash_repairs(lines, hidden)
        working = [
            line.rstrip() if index in repairs else line
            for index, line in enumerate(lines)
        ]
        dangling = [
            index
            for index, line in enumerate(working)
            if LineUtils.has_dangling_backslash(line)
        ]
        if not dangling and not any(
            LineUtils.ends_with_continuation(line) for line in working
        ):
            return FormatResult(
                lines=lines,
                changed=False,
                errors=errors,
                warnings=warnings,
                check_messages=[],
            )

        states = scan_makefile(working, hidden)
        warnings.extend(self._dangling_warning(index + 1, config) for index in dangling)

        makefile = _Makefile(working, hidden, states, config)
        formatted_lines: list[str] = []
        start = 0
        while start < len(working):
            # The block runs to the first line that does not continue, or to a
            # line after which '# bake-format off' hides the lines it
            # continues over.
            end = start
            while (
                end + 1 < len(working)
                and LineUtils.ends_with_continuation(working[end])
                and not hidden.get(end)
            ):
                end += 1
            block = working[start : end + 1]
            if len(block) > 1:
                block = self._format_block(block, start, makefile)
            formatted_lines.extend(block)
            start = end + 1

        return FormatResult(
            lines=formatted_lines,
            changed=formatted_lines != lines,
            errors=errors,
            warnings=warnings,
            check_messages=[],
        )

    @staticmethod
    def _dangling_warning(line_number: int, config: dict) -> str:
        """Return the warning for a kept line whose backslash whitespace follows."""
        if config.get("_global", {}).get("gnu_error_format", True):
            return f"{line_number}: Warning: {DANGLING_BACKSLASH_WARNING}"
        return f"Warning: {DANGLING_BACKSLASH_WARNING} (line {line_number})"

    def _format_block(
        self, block: list[str], start: int, makefile: _Makefile
    ) -> list[str]:
        """Return a block of two or more lines as the rule leaves it."""
        states = makefile.states[start : start + len(block)]
        last = start + len(block) - 1
        if (
            # The block continues lines that '# bake-format off' hides, or
            # goes on over them.
            states[0].continuation
            or (
                LineUtils.ends_with_continuation(block[-1])
                and bool(makefile.hidden.get(last))
            )
            or any(state.may_be_define_body for state in states)
        ):
            return block

        # make's readings decide, not the one model of scan_makefile, which
        # may also see a rule context after text that make stops at; where
        # make stops at the line itself, the one model stands for them (see
        # make_kinds), as on the next run.
        recipe = any(RECIPE in make_kinds(state) for state in states)
        prefix = states[0].recipe_prefix
        inline = False
        position: Optional[tuple[int, int]] = None
        if not recipe:
            inline, position = inline_recipe_start(block, states[0])
        first_line = block[0]
        if inline and states[0].rule_context_read and first_line[:1] == " ":
            # TabsRule gives the first line of the rule a TAB for its leading
            # spaces (see _Makefile.tabs_indent) where it takes the line for a
            # recipe line that lacks its TAB; in a rule context make then
            # reads the lines as a recipe line (GNU make manual 3.8, lines
            # 1217-1219), as the next run reads them. Where that recipe line
            # holds a shell control structure, the next run keeps the
            # indentation of its lines, so this run keeps it too.
            indent = makefile.tabs_indent(start)
            if indent is not None and indent.startswith(prefix):
                as_recipe = [indent + first_line.lstrip(" \t"), *block[1:]]
                if self._contains_shell_control_structures(as_recipe):
                    recipe = True
                    inline = False
                    position = None
                    first_line = as_recipe[0]
        if not (recipe or inline):
            # Makefile syntax: make condenses the whitespace around each
            # backslash/newline (GNU make manual 3.1.1, lines 776-781). Where
            # TabsRule, which runs next, gives the first continuation line a
            # TAB for its spaces, as it does to the continuation of a comment,
            # the others take that TAB too, as the next run gives them.
            return self._format_continuation_block(
                block, makefile.posix_at(start), indent=makefile.tabs_indent(start + 1)
            )
        if inline and position is None:
            # The ';' is not found in the lines: they stay as written.
            return block

        # The lines that are recipe text, from the first one after the line
        # that starts the recipe
        first = 1 if position is None else position[0] + 1
        indent = None
        if recipe or makefile.tabs_indent(start) is None:
            # The lines take the indentation that TabsRule gives the first
            # continuation line, as the next run reads them; that is not
            # known for a rule line that TabsRule turns into a recipe line.
            indent = makefile.tabs_indent(start + 1)
        if (
            indent is None
            and position is None
            and prefix == "\t"
            and states[0].recipe_prefix_known
            and self._quoted_start(block, makefile)
        ):
            # The first continuation line begins inside quotes at column 1,
            # so it keeps its start (see
            # RecipeValidationRule._continuation_keeps_its_start), where it
            # used to get the TAB. The lines below it take that TAB, as they
            # did, rather than its start at column 1.
            indent = prefix
        rewrites = [
            self._format_continuation_block(
                [first_line, *block[1:]],
                False,
                recipe_from=first,
                indent=indent,
                prefix=prefix,
                starts=starts,
                ends=ends,
            )
            for starts, ends in ((True, True), (True, False), (False, True))
        ]
        for rewrite in rewrites:
            rewrite[0] = block[0]
        formatted = rewrites[0]
        if formatted == block:
            return formatted

        # Recipe text: each line changes only where the shell gets the same
        # words (see ShellUtils.keep_shell_text), so the blanks of a word
        # that a backslash joins, of quoted text and of a here-document stay;
        # where the shell is not known, only where it gets the same text.
        # A line's indentation and the blanks before its backslash are tried
        # together, then each alone: each touches only the backslash/newline
        # on its side of the line.
        head = 0 if position is None else position[0]
        column = 0 if position is None else position[1]
        old = [block[head][column:], *block[head + 1 :]]
        recipe_parts = []
        for rewrite in rewrites:
            # The recipe starts after the ';', past the line's indentation.
            indent_change = len(rewrite[head]) - len(rewrite[head].lstrip())
            indent_change -= len(block[head]) - len(block[head].lstrip())
            recipe_parts.append(
                [rewrite[head][column + indent_change :], *rewrite[head + 1 :]]
            )
        kept = ShellUtils.keep_shell_text(
            old,
            recipe_parts[0],
            prefix,
            opaque=makefile.opaque,
            fallbacks=recipe_parts[1:],
        )
        indent_change = len(formatted[head]) - len(formatted[head].lstrip())
        indent_change -= len(block[head]) - len(block[head].lstrip())
        return [
            *formatted[:head],
            formatted[head][: column + indent_change] + kept[0],
            *kept[1:],
        ]

    @staticmethod
    def _quoted_start(block: list[str], makefile: _Makefile) -> bool:
        """
        Check if a recipe block's first continuation line keeps its start.

        That is a line at column 1, which RecipeValidationRule would give the
        TAB that make removes, the recipe prefix (GNU make manual 5.1.1,
        lines 2917-2925), but which begins inside quotes or a here-document
        (see ShellUtils.last_line_starts_in_quotes), so that it keeps its
        start: make 3.81 prints that TAB as part of the quoted text.
        """
        line = block[1]
        return (
            makefile.config.get("fix_missing_recipe_tabs", True)
            and block[0].startswith("\t")
            and line[:1] not in ("", " ", "\t")
            and not RecipeValidationRule.never_adds_tab(line.strip())
            and ShellUtils.last_line_starts_in_quotes(block[:2])
        )

    def _format_continuation_block(
        self,
        lines: list[str],
        keep_spacing: bool = False,
        recipe_from: Optional[int] = None,
        indent: Optional[str] = None,
        prefix: str = "\t",
        starts: bool = True,
        ends: bool = True,
    ) -> list[str]:
        """Format a block of continuation lines.

        With keep_spacing, the whitespace before each backslash stays. From
        the line at index recipe_from on, the lines are recipe text, which
        make passes to the shell as written but for one recipe prefix
        character at the start (GNU make manual 5.1.1, lines 2917-2925): a
        line there that starts at column 1, without the prefix or a blank,
        keeps its start where RecipeValidationRule never gives it a TAB
        either, so that its text, as make passes it on and prints it, stays
        as written. indent, if given, is the indentation for the continuation
        lines in place of that of the first one. Without starts, the lines
        keep their indentation, and without ends, the whitespace before their
        backslash.
        """
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
                if ends and LineUtils.ends_with_continuation(line):
                    formatted_lines.append(
                        self._space_before_backslash(line, keep_spacing)
                    )
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
        if indent is not None:
            leading_whitespace = indent

        # Format all continuation lines (from second line onwards), with the
        # indentation of the first continuation line
        for index, line in enumerate(lines[1:], 1):
            content = line.lstrip()
            if ends and LineUtils.ends_with_continuation(line):
                content = self._space_before_backslash(content, keep_spacing)
            if (
                not starts
                or recipe_from is not None
                and index >= recipe_from
                and not line.startswith((prefix, " ", "\t"))
                and RecipeValidationRule.never_adds_tab(line.strip())
            ):
                formatted_lines.append(line[: len(line) - len(line.lstrip())] + content)
            else:
                formatted_lines.append(leading_whitespace + content)

        return formatted_lines

    @staticmethod
    def _space_before_backslash(text: str, keep_spacing: bool) -> str:
        """
        Put one space before the backslash that continues text.

        make condenses the whitespace before it (GNU make manual 3.1.1, lines
        776-781). It keeps it with keep_spacing, and before a run of three or
        more backslashes, of which make keeps half as text: 'a  \\\\\\' and
        'b' give 'a  \\ b'. Such text is returned as it is.
        """
        if keep_spacing or LineUtils.count_trailing_backslashes(text) > 1:
            return text
        return text[:-1].rstrip() + " \\"

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
