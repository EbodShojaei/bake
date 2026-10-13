"""Rule for validating recipe line formatting."""

import re
from collections.abc import Mapping
from typing import Any, Optional

from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.line_utils import LineUtils

# Conditional directives keep a rule context: the lines they select can be
# recipe lines of the rule above them (GNU make manual 7.1, lines 5315-5333).
_CONDITIONAL_DIRECTIVES = frozenset(
    {"ifdef", "ifndef", "ifeq", "ifneq", "else", "endif"}
)


def _makefile_line_kind(text: str) -> Optional[str]:
    """
    Classify a logical makefile line that is cut at its comment.

    The line is read as make reads a line that is not a recipe line: joined
    with its continuation lines and cut at the comment (GNU make manual 3.8,
    lines 1209-1215). Returns:
    - 'rule' for a rule, which starts a rule context: a ':' before any
      inline recipe (4.2, lines 1488 and 1499-1503);
    - 'conditional' for a conditional directive, which keeps a rule
      context, so the lines it selects can be recipe lines (7.1, lines
      5315-5333);
    - 'syntax' for other makefile syntax, which ends a rule context (5.1,
      lines 2881-2884): assignments, target- and pattern-specific
      variables of any form (6.11, lines 4938-4951), the other directives,
      including 'override define' and 'private undefine' (Appendix A,
      lines 10847-10913; 6.7, lines 4776-4781), and lines that only call
      functions whose result is empty, such as '$(eval ...)' and
      '$(info ...)' (see LineUtils.expands_to_blanks);
    - None for any other text.

    'endef' only ends a define body (6.8, lines 4797-4799). Elsewhere make
    4.x reads it as an ordinary word, so 'endef : foo' is a rule, as for
    LineUtils.is_target_specific_variable; make 3.81 rejects such a line.
    """
    if LineUtils.is_target_specific_variable(text):
        return "syntax"
    directive = LineUtils.directive_word(text)
    if directive == "endef":
        directive = None
    if directive in _CONDITIONAL_DIRECTIVES:
        return "conditional"
    if directive is not None or LineUtils.parse_variable_assignment(text) is not None:
        return "syntax"
    recipe_start = LineUtils.find_unquoted_char(text, ";")
    targets = text if recipe_start is None else text[:recipe_start]
    if LineUtils.find_unquoted_char(targets, ":") is not None:
        return "rule"
    if LineUtils.expands_to_blanks(text):
        return "syntax"
    return None


def _read_hidden_lines(region: list[str], depth: int, recipe_prefix: str) -> int:
    """
    Read lines that '# bake-format off' hides from the rule into make's model.

    Returns the depth of nested define bodies after the lines, given the depth
    before them (see RecipeValidationRule._is_inside_define_block). A line
    that starts with the recipe prefix never nests or ends a body (GNU make
    manual 6.8, lines 4823-4827). Outside a body such a line may be a recipe
    line, which cannot be told here, so it starts no body either.
    """
    start = 0
    while start < len(region):
        text, end = LineUtils.join_logical_line(region, start)
        if not region[start].startswith(recipe_prefix):
            if depth > 0:
                directive = LineUtils.define_body_directive(text)
                if directive == "define":
                    depth += 1
                elif directive == "endef":
                    depth -= 1
            else:
                comment = LineUtils.find_comment_start(text)
                if comment is not None:
                    text = text[:comment]
                if LineUtils.directive_word(text) == "define":
                    depth = 1
        start = end
    return depth


class _LineFacts:
    """
    Facts about a list of lines, each worked out once.

    RecipeValidationRule asks the same questions about the same lines for
    each line it checks, so format() keeps one of these for its lines.
    """

    def __init__(
        self, lines: list[str], hidden: Optional[Mapping[int, list[str]]] = None
    ) -> None:
        """
        Args:
            lines: The lines that the rule formats
            hidden: {index of a '# bake-format off' line: the lines that it
                hides from the rule}
        """
        self.lines = lines
        self.hidden = {
            index: region for index, region in (hidden or {}).items() if region
        }
        self.hidden_after = frozenset(self.hidden)
        # starts[i] is the index of the first physical line of the logical
        # line that lines[i] is part of (GNU make manual 3.1.1, lines 776-781)
        self.starts: list[int] = []
        for index in range(len(lines)):
            if index > 0 and LineUtils.ends_with_continuation(lines[index - 1]):
                self.starts.append(self.starts[-1])
            else:
                self.starts.append(index)
        self.define_masks: dict[str, list[bool]] = {}
        # make's model of define bodies: {recipe prefix: {start of a logical
        # line: the depth of the define bodies that it is in}}
        self.body_depths: dict[str, dict[int, int]] = {}
        # {recipe prefix: {start of a logical line: whether a rule context
        # may reach it}}
        self.rule_contexts: dict[str, dict[int, bool]] = {}
        self.recipe_contexts: dict[int, bool] = {}
        self._joined: dict[int, str] = {}
        self._texts: dict[int, str] = {}
        self._kinds: dict[int, Optional[str]] = {}
        self._defines: dict[int, bool] = {}

    def hides_lines(self, first: int, last: int) -> bool:
        """Check if hidden lines follow any of the lines first to last."""
        return bool(self.hidden_after) and any(
            index in self.hidden_after for index in range(first, last + 1)
        )

    def end(self, start: int) -> int:
        """Return the index just past the logical line that starts at start."""
        end = start + 1
        while end < len(self.lines) and self.starts[end] != end:
            end += 1
        return end

    def joined(self, start: int) -> str:
        """Return the logical line that starts at start, as make joins it."""
        text = self._joined.get(start)
        if text is None:
            text = LineUtils.join_logical_line(self.lines, start)[0]
            self._joined[start] = text
        return text

    def text(self, start: int) -> str:
        """Return joined(start) cut at its comment (GNU 730-742)."""
        text = self._texts.get(start)
        if text is None:
            text = self.joined(start)
            comment = LineUtils.find_comment_start(text)
            if comment is not None:
                text = text[:comment]
            self._texts[start] = text
        return text

    def kind(self, start: int) -> Optional[str]:
        """Return _makefile_line_kind for the logical line at start."""
        if start not in self._kinds:
            self._kinds[start] = _makefile_line_kind(self.text(start))
        return self._kinds[start]

    def is_define(self, start: int) -> bool:
        """Check if the logical line at start is a 'define' directive.

        The line is read as makefile syntax, which is how make reads a line
        that starts with the recipe prefix outside a rule context.
        """
        found = self._defines.get(start)
        if found is None:
            found = any(
                "define" in line for line in self.lines[start : self.end(start)]
            ) and (LineUtils.directive_word(self.text(start)) == "define")
            self._defines[start] = found
        return found


class RecipeValidationRule(FormatterPlugin):
    """Validates that recipe lines have the required leading tab."""

    def __init__(self) -> None:
        super().__init__("recipe_validation", priority=8)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        """Validate and fix recipe lines that are missing required tabs."""
        formatted_lines = []
        changed = False
        errors: list[str] = []
        warnings: list[str] = []
        check_messages: list[str] = []

        fix_missing_tabs = config.get("fix_missing_recipe_tabs", True)
        # {index of a '# bake-format off' line: the lines it hides}
        hidden = context.get("disabled_region_lines") or {}
        facts = _LineFacts(lines, hidden)

        for i, line in enumerate(lines):
            line_num = i + 1

            # Get active recipe prefix for this line
            active_prefix = LineUtils.get_active_recipe_prefix(lines, i)

            # Check if this should be a recipe line but is missing a tab
            if self._is_missing_recipe_tab(line, i, lines, active_prefix, facts):
                error_msg = "Missing required tab separator in recipe line"

                if check_mode:
                    gnu_format = config.get("_global", {}).get("gnu_error_format", True)
                    if gnu_format:
                        check_messages.append(f"{line_num}: Error: {error_msg}")
                    else:
                        check_messages.append(f"Error: {error_msg} (line {line_num})")
                else:
                    if fix_missing_tabs:
                        # Fix by replacing leading spaces with a tab
                        stripped_content = line.lstrip(" \t")
                        fixed_line = "\t" + stripped_content
                        formatted_lines.append(fixed_line)
                        changed = True
                    else:
                        # Report as error but don't fix
                        gnu_format = config.get("_global", {}).get(
                            "gnu_error_format", True
                        )
                        if gnu_format:
                            errors.append(f"{line_num}: Error: {error_msg}")
                        else:
                            errors.append(f"Error: {error_msg} (line {line_num})")
                        formatted_lines.append(line)
            else:
                formatted_lines.append(line)

        return FormatResult(
            lines=formatted_lines,
            changed=changed,
            errors=errors,
            warnings=warnings,
            check_messages=check_messages,
        )

    def _is_missing_recipe_tab(
        self,
        line: str,
        line_index: int,
        all_lines: list[str],
        active_prefix: str,
        facts: Optional[_LineFacts] = None,
    ) -> bool:
        """
        Check if a line should be a recipe line but is missing the required tab.

        Args:
            line: The line to check
            line_index: Index of the line in the file
            all_lines: All lines in the file
            active_prefix: The active recipe prefix character
            facts: The facts about all_lines that format() keeps, if any

        Returns:
            True if this line should be a recipe but is missing a tab
        """
        if facts is None or facts.lines is not all_lines:
            facts = _LineFacts(all_lines)
        stripped = line.strip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("#"):
            return False

        # Skip lines that already start with the active recipe prefix (correctly formatted)
        if LineUtils.is_recipe_line_with_prefix(line, active_prefix):
            return False

        # Skip lines that already start with tab (correctly formatted) or space (continuations/intentional indent)
        if line.startswith(("\t", " ")):
            return False

        # Skip variable assignments and directives
        if (
            "=" in stripped
            or stripped.startswith(
                (
                    "include",
                    "-include",
                    "export",
                    "unexport",
                    "define",
                    "ifeq",
                    "ifneq",
                    "ifdef",
                    "ifndef",
                    "if ",
                    "else",
                    "endif",
                    "endef",
                )
            )
            or stripped in self._get_special_make_targets()
        ):
            return False

        # Skip other makefile syntax, which make reads as such even right
        # after a recipe line
        if self._starts_makefile_syntax(facts, line_index):
            return False

        # Skip content inside define blocks
        if self._is_inside_define_block(facts, line_index, active_prefix):
            return False

        # Skip target lines themselves (they shouldn't start with tabs)
        if ":" in stripped and not (
            "=" in stripped and stripped.find("=") < stripped.find(":")
        ):
            return False

        # Check if this should be a recipe line based on context
        return self._should_be_recipe_line(facts, line_index)

    def _get_special_make_targets(self) -> set[str]:
        """Get all special Makefile targets."""
        return {
            ".PHONY",
            ".SUFFIXES",
            ".PRECIOUS",
            ".INTERMEDIATE",
            ".SECONDARY",
            ".DELETE_ON_ERROR",
            ".IGNORE",
            ".SILENT",
            ".EXPORT_ALL_VARIABLES",
            ".NOTPARALLEL",
            ".ONESHELL",
            ".POSIX",
            ".LOW_RESOLUTION_TIME",
            ".SECOND_EXPANSION",
            ".SECONDEXPANSION",
            ".VARIABLES",
            ".MAKE",
            ".WAIT",
            ".INCLUDE_DIRS",
            ".LIBPATTERNS",
        }

    def _starts_makefile_syntax(self, facts: _LineFacts, line_index: int) -> bool:
        """
        Check if a line starts makefile syntax that make never reads as a recipe.

        make reads a line that does not start with the recipe prefix as
        makefile syntax (GNU make manual 3.8, lines 1209-1229; 5.1, lines
        2878-2884). See _makefile_line_kind for the lines that count.

        A line that continues the previous line belongs to that logical line,
        so it never starts makefile syntax.
        """
        if facts.starts[line_index] != line_index:
            return False
        return facts.kind(line_index) is not None

    def _is_inside_define_block(
        self, facts: _LineFacts, line_index: int, recipe_prefix: str = "\t"
    ) -> bool:
        """
        Check if the current line is inside a define block.

        Two models are combined, and the line is inside a body when either
        says so.

        In make's model, make reads logical lines (GNU make manual 3.1.1,
        lines 776-781). A body starts after a 'define' directive, which may
        have the modifiers 'export', 'unexport', 'override' and 'private'
        (6.7, lines 4776-4781; 6.8, lines 4795-4799). A line that starts with
        the recipe prefix is a recipe line in a rule context (3.8, lines
        1217-1219), so it only starts a body where the lines above show that
        there is no rule context (see _may_be_in_rule_context). Inside a
        body, make only looks for a bare 'define', which nests, and for
        'endef', on a logical line that does not start with the recipe prefix
        (lines 4797-4799 and 4823-4827; see LineUtils.define_body_directive).
        The lines that '# bake-format off' hides from the rule are read too.

        The line model is the one used before, so that no line it kept
        unrepaired gets a TAB now: a physical line whose text starts with
        'define ' opens a define, and a line that is just 'endef' ends the
        innermost one. Like '\\tdefine X', a 'define' directive with modifiers
        that starts with the recipe prefix and no other line, such as
        '\\toverride define X', also opens one, but only where no define is
        open in either model. Where such a line is a recipe line, no 'endef'
        belongs to it, so it only counts when an 'endef' ends it.
        """
        return self._define_body_mask(facts, recipe_prefix)[line_index]

    def _define_body_mask(self, facts: _LineFacts, recipe_prefix: str) -> list[bool]:
        """Return, for each line, whether _is_inside_define_block holds."""
        mask = facts.define_masks.get(recipe_prefix)
        if mask is not None:
            return mask
        lines = facts.lines
        # make's model: the depth of nested define bodies at each logical line
        depths = facts.body_depths.setdefault(recipe_prefix, {})
        in_body = [False] * len(lines)
        depth = 0
        # The line model: the open defines, each as the index of its line and
        # whether it is a recipe-prefixed define with modifiers
        line_model: list[tuple[int, bool]] = []
        # For each line, the number of defines open in the line model, and the
        # index of the recipe-prefixed define with modifiers among them, if any
        open_defines = [0] * len(lines)
        prefixed_defines: list[Optional[int]] = [None] * len(lines)
        ended: set[int] = set()
        start = 0
        while start < len(lines):
            end = facts.end(start)
            depths[start] = depth
            for index in range(start, end):
                in_body[index] = depth > 0
                open_defines[index] = len(line_model)
                if line_model and line_model[0][1]:
                    prefixed_defines[index] = line_model[0][0]
                line = lines[index]
                stripped = line.strip()
                if stripped.startswith("define "):
                    line_model.append((index, False))
                elif (
                    index == start
                    and depth == 0
                    and not line_model
                    and line.startswith(recipe_prefix)
                    and facts.is_define(start)
                ):
                    line_model.append((index, True))
                elif stripped == "endef" and line_model:
                    opened, prefixed = line_model.pop()
                    if prefixed:
                        ended.add(opened)

            first_prefixed = lines[start].startswith(recipe_prefix)
            if depth == 0:
                if facts.is_define(start) and (
                    not first_prefixed
                    or not self._may_be_in_rule_context(facts, start, recipe_prefix)
                ):
                    depth = 1
            elif not first_prefixed:
                directive = LineUtils.define_body_directive(facts.joined(start))
                if directive == "define":
                    depth += 1
                elif directive == "endef":
                    depth -= 1
            for index in range(start, end):
                region = facts.hidden.get(index)
                if region:
                    depth = _read_hidden_lines(region, depth, recipe_prefix)
            start = end

        mask = []
        for index in range(len(lines)):
            count = open_defines[index]
            # A recipe-prefixed define with modifiers that no 'endef' ends is
            # a recipe line, so only the defines opened after it count.
            prefixed_define = prefixed_defines[index]
            if prefixed_define is not None and prefixed_define not in ended:
                count -= 1
            mask.append(in_body[index] or count > 0)
        facts.define_masks[recipe_prefix] = mask
        return mask

    def _ends_define_body(
        self, facts: _LineFacts, start: int, recipe_prefix: str
    ) -> bool:
        """Check if the logical line at start ends a body in make's model."""
        return (
            facts.body_depths.get(recipe_prefix, {}).get(start, 0) > 0
            and not facts.lines[start].startswith(recipe_prefix)
            and LineUtils.define_body_directive(facts.joined(start)) == "endef"
        )

    def _may_be_in_rule_context(
        self, facts: _LineFacts, start: int, recipe_prefix: str
    ) -> bool:
        """
        Check if make may be in a rule context at a logical line outside bodies.

        A rule starts a rule context. Recipe lines, blank lines, lines of just
        a comment and conditional directives keep it (GNU make manual 5.1,
        lines 2881-2886; 7.1, lines 5315-5333), and other makefile syntax ends
        it (lines 2882-2884), such as an assignment, a target-specific
        variable, a directive or the 'endef' that ends a define body. This
        follows the manual: make 3.81 keeps a rule context at 'define' and
        'override' lines.

        The answer is False only when the lines above show that there is no
        rule context: the start of the file or such syntax, with only blank
        lines, comments and the start of conditionals in between. A line that
        starts with the recipe prefix is a recipe line where a rule context
        reaches it. Elsewhere make reads it as makefile syntax (3.8, lines
        1217-1219), and it never starts a rule context: make rejects a rule
        or other text there ("recipe commences before first target", lines
        11292-11297). Text that is no makefile syntax may expand to a rule
        (3.8, lines 1231-1236). make reads a branch after 'else' only when it
        ignored the branches before (7.1, lines 5345-5358; 7.2, lines
        5399-5421), so the lines above the conditional decide there. After
        'endif' the answer depends on the branch that make took, so it is
        True. It is also True where lines that '# bake-format off' hides from
        the rule come between, since they may hold a rule.
        """
        if recipe_prefix not in facts.body_depths:
            self._define_body_mask(facts, recipe_prefix)
        known = facts.rule_contexts.setdefault(recipe_prefix, {})
        # A walk may need the answer for a recipe-prefixed line above first,
        # so the answers are worked out from the top down, without recursion.
        pending = [start]
        while pending:
            current = pending[-1]
            if current in known:
                pending.pop()
                continue
            answer, needed = self._walk_to_rule_context(
                facts, current, recipe_prefix, known
            )
            if answer is None:
                pending.append(needed)
            else:
                known[current] = answer
                pending.pop()
        return known[start]

    def _walk_to_rule_context(
        self, facts: _LineFacts, start: int, recipe_prefix: str, known: dict[int, bool]
    ) -> tuple[Optional[bool], int]:
        """
        Look above a logical line for _may_be_in_rule_context.

        Returns (answer, -1), or (None, line) when the answer depends on the
        recipe-prefixed logical line that starts at 'line', which is not in
        known yet.
        """
        index = start - 1
        while index >= 0:
            line_start = facts.starts[index]
            if facts.hides_lines(line_start, index):
                return True, -1
            index = line_start - 1
            prefixed = facts.lines[line_start].startswith(recipe_prefix)
            if prefixed:
                reached = known.get(line_start)
                if reached is None:
                    return None, line_start
                if reached:
                    # A recipe line in the rule context
                    return True, -1
            words = facts.text(line_start).split(None, 1)
            if not words:
                # A blank line or a line of just a comment
                continue
            if words[0] == "endef" and self._ends_define_body(
                facts, line_start, recipe_prefix
            ):
                return False, -1
            kind = facts.kind(line_start)
            if kind != "conditional":
                return not prefixed and kind != "syntax", -1
            if words[0] == "endif":
                return True, -1
            if words[0] == "else":
                opener = self._conditional_opener(facts, line_start, recipe_prefix)
                if opener is None:
                    return True, -1
                index = opener - 1
        return False, -1

    def _conditional_opener(
        self, facts: _LineFacts, else_start: int, recipe_prefix: str
    ) -> Optional[int]:
        """
        Find the conditional directive that an 'else' line belongs to.

        Nested conditionals are skipped, and 'else ifeq ...' continues the
        same conditional (GNU make manual 7.2, lines 5399-5421). Returns
        None when the lines in between leave it open: a conditional that
        starts with the recipe prefix may be a recipe line (5.1, lines
        2902-2905), make does not read the lines of a define body as
        directives (6.8, lines 4795-4799), an automake 'if' has an 'else' and
        an 'endif' that look like make's, and the rule does not see the lines
        that '# bake-format off' hides.
        """
        depth = 0
        index = else_start - 1
        while index >= 0:
            line_start = facts.starts[index]
            if facts.hides_lines(line_start, index):
                return None
            index = line_start - 1
            words = facts.text(line_start).split(None, 1)
            if not words:
                continue
            if words[0] == "endef" and self._ends_define_body(
                facts, line_start, recipe_prefix
            ):
                return None
            kind = facts.kind(line_start)
            if words[0] == "if" and kind is None:
                return None
            if kind != "conditional":
                continue
            if facts.lines[line_start].startswith(recipe_prefix):
                return None
            if words[0] == "endif":
                depth += 1
            elif words[0] != "else":
                if depth == 0:
                    return line_start
                depth -= 1
        return None

    def _should_be_recipe_line(self, facts: _LineFacts, line_index: int) -> bool:
        """Check if a line should be a recipe line based on context."""
        all_lines = facts.lines
        # Look backward to find what this line belongs to. The answer only
        # depends on where the search is, so it is kept for each line passed.
        passed: list[int] = []
        result = False
        i = line_index - 1
        while i >= 0:
            known = facts.recipe_contexts.get(i)
            if known is not None:
                result = known
                break
            passed.append(i)
            if facts.hides_lines(i, i):
                # Lines that '# bake-format off' hides from the rule follow
                # line i and may hold a rule, as for _may_be_in_rule_context.
                result = True
                break
            prev_line = all_lines[i]
            prev_stripped = prev_line.strip()

            # Skip empty lines and comments (comments should not break context)
            if not prev_stripped:
                break
            if prev_stripped.startswith("#"):
                i -= 1
                continue

            # If we find another indented line, check if it's a recipe line
            if prev_line.startswith(("\t", " ")):
                # If previous line is also missing a tab, continue looking backward
                if not prev_line.startswith("\t"):
                    i -= 1
                    continue
                # A line that starts with a tab is a recipe line in a rule
                # context, and then this line should also be a recipe line
            elif not self._is_target_line(facts, i):
                # If we find a non-target, non-recipe line, this is not a recipe
                break

            # The recipe or target line may only continue a makefile line or
            # a comment, which make reads as one logical line from its first
            # physical line (GNU make manual 3.8, lines 1209-1218). Then that
            # logical line decides.
            start = facts.starts[i]
            if all_lines[start].startswith("\t"):
                # A line that starts with a TAB is a recipe line only in a
                # rule context. Elsewhere make reads it as makefile syntax
                # (lines 1217-1219), and after it make rejects a TAB line
                # that is not makefile syntax ("recipe commences before
                # first target", lines 11292-11297), so a TAB never helps.
                result = self._may_be_in_rule_context(facts, start, "\t")
                break
            if start == i:
                result = True
                break
            verdict = self._continued_line_verdict(facts, start)
            if verdict is not None:
                result = verdict
                break
            i = start - 1

        for position in passed:
            facts.recipe_contexts[position] = result
        return result

    def _continued_line_verdict(self, facts: _LineFacts, start: int) -> Optional[bool]:
        """
        Decide what a continued line that is not a recipe line means below it.

        Returns True for a rule, so the line below can belong to its recipe,
        and False for other makefile syntax, which ends a rule context (see
        _makefile_line_kind). make reads a line that starts with spaces the
        same way. Returns None to keep looking above the logical line: for a
        comment, a conditional directive, or other text, which is itself a
        recipe line that lacks its tab when it follows a rule.
        """
        if facts.lines[start].startswith("#"):
            return None
        kind = facts.kind(start)
        if kind == "rule":
            return True
        if kind == "syntax":
            return False
        return None

    def _is_target_line(self, facts: _LineFacts, line_index: int) -> bool:
        """Check if a line is a target definition."""
        stripped = facts.lines[line_index].strip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith("#"):
            return False

        # Skip variable assignments
        if "=" in stripped and (
            ":" not in stripped
            or ":=" in stripped
            or "+=" in stripped
            or "?=" in stripped
        ):
            return False

        # Skip export variable assignments
        if stripped.startswith("export ") and "=" in stripped:
            return False

        # Skip function calls and other constructs
        if stripped.startswith("$(") and stripped.endswith(")"):
            return False

        # Skip lines that are clearly not target definitions
        if stripped.startswith("@") or "$(" in stripped:
            return False

        # Check for target pattern: name: prerequisites
        target_pattern = re.compile(r"^([^:=]+):(:?)\s*(.*)$")
        match = target_pattern.match(stripped)
        if match:
            target_name = match.group(1).strip()
            target_body = match.group(3).strip()

            # Skip comment-only targets (documentation targets)
            if target_body.startswith("##"):
                return False

            # Skip target-specific variable assignments
            if re.match(r"^\s*[A-Z_][A-Z0-9_]*\s*[+:?]?=", target_body):
                return False

            # Skip other makefile syntax with a ':', which does not start a
            # rule context: target-specific variables of any form (GNU make
            # manual 6.11, lines 4938-4951) and directives such as
            # 'vpath %.c src:lib' (4.5.2, lines 1826-1829). A line that
            # continues another one is part of that logical line instead.
            if (
                facts.starts[line_index] == line_index
                and facts.kind(line_index) == "syntax"
            ):
                return False

            # Skip template placeholders
            return not re.fullmatch(r"\$[({][^})]+[})]", target_name)

        return False
