"""Rule for detecting duplicate targets in Makefiles."""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from itertools import islice
from typing import Any, Optional

from ...constants.makefile_targets import DECLARATIVE_TARGETS
from ...plugins.base import FormatResult, FormatterPlugin
from ...utils.line_utils import ConditionalTracker, LineUtils
from ...utils.rule_context import (
    is_automake_conditional,
    line_by_line_prefixes,
    recipe_prefixes,
)
from .recipe_validation import RecipeValidationRule
from .tabs import TabsRule

# The directives that open a conditional (GNU make manual 7.2, lines
# 5386-5397).
_CONDITIONAL_OPENERS = frozenset({"ifdef", "ifndef", "ifeq", "ifneq"})

# Some of the ways make may read the conditionals of a makefile: for some
# conditionals, the branches that make may take there, as pairs of the id of
# the conditional and the ids of those branches. A conditional that is not
# named may take any branch, so the empty set stands for every reading.
_Readings = frozenset[tuple[int, frozenset[int]]]

# Every reading
_EVERY: _Readings = frozenset()

# At most this many sets of readings are kept for the rule context or the
# recipe of one rule; later ones are dropped. Each conditional after a rule
# can double their number. Dropping a set can only lose a report, never add
# one: the rule then counts as read in fewer readings.
_MAX_READINGS = 32

# At most this many rules keep a rule context that may be open after an
# 'endif', the latest ones. A conditional without 'else' after a rule keeps
# that rule's context open in the readings that take none of its branches
# (GNU make manual 5.1, lines 2881-2886; 7.1, lines 5315-5333), so every
# such conditional adds one; the earlier rules' contexts stay open only in
# readings that skip every later rule. Forgetting them can only lose a
# report, never add one, and keeps long generated makefiles fast.
_MAX_OPEN_RULES = 64

# A rule with a recipe is compared with at most this many earlier rules with
# a recipe for the same target, the latest first. Rules in different branches
# never meet (see ConditionalTracker.are_mutually_exclusive), so a makefile of
# many conditionals for one target would otherwise compare every pair. Like
# _MAX_OPEN_RULES, this can only lose a report.
_MAX_EARLIER_RULES = 256

# A drive letter, which make on MS-Windows reads as part of a path such as
# 'C:/out/a.o' (GNU make manual, lines 1700-1707)
_DRIVE_LETTER = re.compile(r"[A-Za-z]")


@dataclass(eq=False)
class _Rule:
    """A rule, with what the scan found out about its recipe."""

    # The number of the rule line among the lines the rule checks, or 0 for
    # a line that '# bake-format off' hides
    line_number: int
    # The branch ids of the conditionals around the rule line, outermost
    # first, as ConditionalTracker gives them
    context: tuple[int, ...]
    # The target to compare with the other rules, or None for a rule that is
    # never compared
    target: Optional[str]
    # The readings in which make reads a recipe for the rule, one set for
    # each recipe line or inline recipe that the scan found
    recipes: list[_Readings] = field(default_factory=list)
    # The position of the rule among all rules of the scan
    order: int = 0
    # The number of lines before the rule that may change a variable (see
    # _RecipeScan.changes)
    changes: int = 0

    def add_recipe(self, readings: _Readings) -> None:
        """Record that make reads a recipe for the rule in readings."""
        if self.target is None or readings in self.recipes or _EVERY in self.recipes:
            return
        if not readings:
            self.recipes[:] = [readings]
            return
        if len(self.recipes) < _MAX_READINGS:
            self.recipes.append(readings)


# A rule whose rule context may be open, and the readings in which it is.
# Those only name conditionals that have ended: the rule context is open in
# the branch of every open conditional that the scan is in.
_Open = tuple[_Rule, _Readings]


@dataclass
class _Conditional:
    """An open conditional, as the scan follows it."""

    # The id of the conditional
    id: int
    # The rules whose rule context may be open before the conditional
    before: list[_Open]
    # For each branch read so far: its id, and the rules whose rule context
    # may be open at its end
    ends: list[tuple[int, list[_Open]]] = field(default_factory=list)
    # True after a plain 'else', so that make always reads one of the branches
    complete: bool = False


class DuplicateTargetRule(FormatterPlugin):
    """
    Detects targets whose recipe a later rule overrides.

    A target may appear in several rules: make merges their prerequisites
    (GNU make manual 4.11, lines 2545-2548). Only a second recipe for the same
    target replaces the first, and make warns about it (lines 2550-2552;
    "overriding recipe for target", lines 11331-11337). So an error is
    reported only when make may read two single-colon explicit rules for one
    target that both have a recipe. Double-colon rules may each have one
    (4.13, lines 2721-2737).
    """

    def __init__(self) -> None:
        super().__init__("duplicate_targets", priority=5)
        # Used as predicates only, so that a line counts as a recipe line
        # exactly when the formatter makes it one.
        self._tabs = TabsRule()
        self._recipe_validation = RecipeValidationRule()

    def format(
        self,
        lines: list[str],
        config: dict[str, Any],
        check_mode: bool = False,
        **context: Any,
    ) -> FormatResult:
        """Format lines by detecting duplicate targets."""
        # {index of a '# bake-format off' line: the lines it hides}
        hidden = context.get("disabled_region_lines") or {}
        errors = self._detect_duplicates(lines, config, hidden)
        # This rule doesn't modify content, just reports errors
        return FormatResult(
            lines=lines, changed=False, errors=errors, warnings=[], check_messages=[]
        )

    def _detect_duplicates(
        self,
        lines: list[str],
        config: dict[str, Any],
        hidden: Optional[Mapping[int, list[str]]] = None,
    ) -> list[str]:
        """Detect rules that override the recipe of an earlier rule."""
        return _RecipeScan(self, lines, config, hidden or {}).run()

    def _is_template_placeholder(self, target_name: str) -> bool:
        """Check if target is a template placeholder like $(1), $(2), $(VAR), etc."""
        return bool(re.fullmatch(r"\$[({][^})]+[})]", target_name))

    def _format_error_message(self, message: str, line_num: int, config: dict) -> str:
        """Format error message according to configuration."""
        gnu_error_format = config.get("_global", {}).get("gnu_error_format", True)

        if gnu_error_format:
            return f"{line_num}: Error: {message}"
        else:
            return f"Error: {message} (line {line_num})"


class _RecipeScan:
    """
    Read the lines once, from the top, and compare the rules that have recipes.

    The model of rule contexts is exact for the text: a rule starts a rule
    context, recipe lines, blank lines, comments and conditional directives
    keep it, and any other line ends it (GNU make manual 5.1, lines
    2878-2886; 7.1, lines 5315-5333). As in GNU make 4.x, that includes
    assignments, target-specific variables, other directives, 'define' with
    or without modifiers, and lines that only call functions such as
    '$(eval ...)'. A line that starts with the recipe prefix is a recipe line
    in a rule context, even a TAB-only line, which is an empty recipe (lines
    2890-2891), or a conditional (lines 2902-2905).

    make reads one branch of each conditional, or none when no condition
    holds and there is no plain 'else' (7.2, lines 5399-5421), and the rule
    context it is in depends on the branches it read. So the scan follows
    each rule whose rule context may be open, with the readings in which it
    is: a branch after 'else' starts with the rule contexts from before the
    conditional, and after 'endif' a rule context is open in the readings
    that take a branch at whose end it was open. A recipe line belongs to
    the rule whose rule context is open in the readings that read the line,
    so each rule gets the readings in which make reads a recipe for it. Two
    rules are compared only when one reading has the recipes of both
    (lines 2550-2552). Every branch of every conditional counts as possible,
    whatever its condition, so two conditionals that test the same variable
    count as unrelated. As before, rules whose lines are in different
    branches of one conditional, or in different conditionals at the same
    depth, are not compared either (see
    ConditionalTracker.are_mutually_exclusive): such conditionals often
    test the same variable.

    The formatter turns some lines into recipe lines: TabsRule replaces the
    spaces of the lines that TabsRule.converts_to_recipe accepts with a TAB,
    and RecipeValidationRule adds a TAB to those that
    RecipeValidationRule.is_missing_recipe_tab accepts, when
    fix_missing_recipe_tabs is on. Such a line counts as a recipe line too,
    where the TAB is the recipe prefix, so the errors for the formatted
    lines are the same.

    The lines that '# bake-format off' hides are read in place. A rule among
    them has no line number to report, so it is never compared.
    """

    def __init__(
        self,
        rule: DuplicateTargetRule,
        lines: list[str],
        config: dict[str, Any],
        hidden: Mapping[int, list[str]],
    ) -> None:
        self.rule = rule
        self.lines = lines
        self.config = config
        self.fix_tabs = config.get("fix_missing_recipe_tabs", True)
        # The lines with the hidden lines in place. visible[k] is the index in
        # lines of merged[k], or None for a hidden line.
        self.merged: list[str] = []
        self.visible: list[Optional[int]] = []
        for index, line in enumerate(lines):
            self.merged.append(line)
            self.visible.append(index)
            for hidden_line in hidden.get(index, ()):
                self.merged.append(hidden_line)
                self.visible.append(None)
        # The recipe prefix of each line. scan_makefile(lines, hidden) reads
        # the hidden lines at the same places, so these are its prefixes,
        # with those of the hidden lines (GNU make manual, lines 5158-5169).
        self.prefixes = recipe_prefixes(self.merged, {})
        # The recipe prefix of each line as TabsRule and RecipeValidationRule
        # read it (see line_by_line_prefixes)
        self.formatter_prefixes = line_by_line_prefixes(lines)
        # What RecipeValidationRule works out about the lines, once per call
        self.facts = rule._recipe_validation.line_facts(lines, hidden)
        # How TabsRule reads the lines with indent_nested_conditionals, where
        # it leaves the lines that make reads as makefile syntax alone (see
        # TabsRule.converts_to_recipe)
        self.tabs_reading = (
            rule._tabs.make_reading(
                lines, hidden, config.get("remove_trailing_whitespace", True)
            )
            if config.get("indent_nested_conditionals", False)
            else None
        )
        # The open conditionals, outermost first, and the branch of each that
        # the scan is in
        self.conditionals: list[_Conditional] = []
        self.branches: list[int] = []
        # The readings that read the current line
        self.path: _Readings = _EVERY
        self.next_conditional = 0
        self.next_branch = 0
        # Every rule, in the order of the lines
        self.rules: list[_Rule] = []
        # The rules whose rule context may be open at the current line
        self.open: list[_Open] = []
        self.define_depth = 0
        # The number of lines so far that may change the value of a variable:
        # assignments, directives such as 'define' and 'include', and other
        # text such as '$(eval ...)'. make expands the targets of a rule when
        # it reads the rule (GNU make manual 3.7, lines 1193-1203), so two
        # rules for '$(DIR)/app' may name different files once DIR changes.
        self.changes = 0

    def run(self) -> list[str]:
        """Read all lines and return the errors, in the order of the lines."""
        start = 0
        while start < len(self.merged):
            # A logical line (GNU make manual 3.1.1, lines 776-781). A recipe
            # line keeps its backslash/newlines, but its continuation lines
            # are the same physical lines (5.1.1, lines 2910-2920).
            text, end = LineUtils.join_logical_line(self.merged, start)
            self._read(start, text)
            start = end
        return self._compare()

    def _read(self, start: int, text: str) -> None:
        """Read the logical line text that starts at merged[start]."""
        prefix = self.prefixes[start]
        prefixed = self.merged[start].startswith(prefix)
        if self.define_depth > 0:
            # A define body is the value of a variable. make only looks for a
            # bare 'define', which nests, and for the 'endef' that ends the
            # body, on lines that do not start with the recipe prefix (GNU
            # make manual 6.8, lines 4795-4799 and 4823-4827).
            if not prefixed:
                directive = LineUtils.define_body_directive(text)
                if directive == "define":
                    self.define_depth += 1
                elif directive == "endef":
                    self.define_depth -= 1
            return
        if self.open and (prefixed or self._becomes_recipe_line(start)):
            for rule, readings in self.open:
                rule.add_recipe(_both(readings, self.path))
            return

        comment = LineUtils.find_comment_start(text)
        code = text if comment is None else text[:comment]
        if not code.strip():
            # A blank line or a line of just a comment keeps a rule context
            # (GNU make manual 5.1, lines 2884-2886).
            return
        if LineUtils.is_target_specific_variable(code):
            # It ends a rule context and starts none (6.11, lines 4938-4951).
            self.open = []
            return
        directive = LineUtils.directive_word(code)
        if directive in _CONDITIONAL_OPENERS or directive in ("else", "endif"):
            self._read_conditional(code.split())
            return
        if directive is not None and directive != "endef":
            # 'endef' outside a define body is an ordinary word for make 4.x.
            self.open = []
            self.changes += 1
            if directive == "define":
                self.define_depth = 1
            return
        if LineUtils.parse_variable_assignment(code) is not None:
            self.open = []
            self.changes += 1
            return
        # A rule has a ':' before any inline recipe (GNU make manual 4.2,
        # lines 1488 and 1499-1503).
        semicolon = LineUtils.find_unquoted_char(code, ";")
        head = code if semicolon is None else code[:semicolon]
        colon = LineUtils.find_unquoted_char(head, ":")
        if colon is not None:
            rule = _Rule(
                line_number=self._line_number(start),
                context=tuple(self.branches),
                target=self._tracked_target(
                    start, prefix, text, head, colon, rescanned=semicolon is None
                ),
            )
            if semicolon is not None or LineUtils.has_semicolon_on_second_scan(
                head[colon + 1 :]
            ):
                # An inline recipe, which make reads with the rule line
                rule.add_recipe(self.path)
            rule.order = len(self.rules)
            rule.changes = self.changes
            self.rules.append(rule)
            self.open = [(rule, _EVERY)]
            return
        if is_automake_conditional(code):
            self._read_conditional(["if"])
            return
        # Other text, such as '$(eval ...)'
        self.open = []
        self.changes += 1

    def _becomes_recipe_line(self, start: int) -> bool:
        """
        Check if the formatter turns the line at merged[start] into a recipe line.

        The formatter adds a TAB, so this only counts where make reads the
        TAB as the recipe prefix. It never changes the lines that
        '# bake-format off' hides.
        """
        index = self.visible[start]
        if index is None or self.prefixes[start] != "\t":
            return False
        prefix = self.formatter_prefixes[index]
        line = self.lines[index]
        if line.startswith(" "):
            return self.rule._tabs.converts_to_recipe(
                line, index, self.lines, prefix, reading=self.tabs_reading
            )
        if not self.fix_tabs:
            return False
        return self.rule._recipe_validation.is_missing_recipe_tab(
            line, index, self.lines, prefix, self.facts
        )

    def _read_conditional(self, words: list[str]) -> None:
        """
        Follow a conditional directive, which keeps a rule context.

        Each branch gets an id of its own, also each 'else ifeq ...' of a
        chain, which shares one 'endif' (GNU make manual 7.2, lines
        5399-5419). make reads a branch only when it read none of the
        branches before, so a branch after 'else' starts with the rule
        contexts from before the conditional.

        Args:
            words: The words of the directive line, without its comment
        """
        if words[0] == "endif":
            if self.conditionals:
                conditional = self.conditionals.pop()
                ends = [*conditional.ends, (self.branches.pop(), self.open)]
                if not conditional.complete:
                    # make may read none of the branches
                    ends.append((self.next_branch, conditional.before))
                    self.next_branch += 1
                self.open = _latest_rules(_after_conditional(conditional.id, ends))
        elif words[0] == "else":
            if self.conditionals:
                conditional = self.conditionals[-1]
                conditional.ends.append((self.branches[-1], self.open))
                self.open = list(conditional.before)
                if len(words) == 1 or words[1] not in _CONDITIONAL_OPENERS:
                    conditional.complete = True
                self.branches[-1] = self.next_branch
                self.next_branch += 1
        else:
            self.conditionals.append(
                _Conditional(id=self.next_conditional, before=list(self.open))
            )
            self.next_conditional += 1
            self.branches.append(self.next_branch)
            self.next_branch += 1
        self.path = frozenset(
            (conditional.id, frozenset((branch,)))
            for conditional, branch in zip(self.conditionals, self.branches)
        )

    def _line_number(self, start: int) -> int:
        """Return the line number of merged[start], or 0 for a hidden line."""
        index = self.visible[start]
        return 0 if index is None else index + 1

    def _tracked_target(
        self,
        start: int,
        prefix: str,
        text: str,
        head: str,
        colon: int,
        rescanned: bool,
    ) -> Optional[str]:
        """
        Return the target of a rule line to compare with other rules, or None.

        Only a rule with one explicit target counts. Not compared are:
        double-colon rules (GNU make manual 4.13, lines 2721-2737), pattern
        rules and static pattern rules (10.5, lines 8006-8007; 4.12),
        grouped targets ('&:', 4.10), template placeholders such as '$(1)',
        .PHONY and .SUFFIXES, '##' documentation lines, lines that start with
        a TAB or the recipe prefix, as before, lines whose targets make cuts
        at a ';' (see LineUtils.has_semicolon_on_second_scan) and lines that
        '# bake-format off' hides. A drive letter is part of the target, as
        for make on MS-Windows (lines 1700-1707), so 'C:/out/a.o: a.c' has
        the target 'C:/out/a.o'.

        Args:
            start: The index in merged of the rule line
            prefix: The recipe prefix at the line
            text: The logical line
            head: The logical line cut at its comment and inline recipe
            colon: The index of the first ':' of head
            rescanned: Whether the line has no inline recipe after an
                unquoted ';', so that make scans its targets again
        """
        first = self.merged[start]
        if self.visible[start] is None or first.startswith(("\t", prefix)):
            return None
        if _DRIVE_LETTER.fullmatch(head[:colon].strip()) and head[
            colon + 1 : colon + 2
        ] in ("/", "\\"):
            after_drive = LineUtils.find_unquoted_char(head, ":", colon + 1)
            if after_drive is not None:
                colon = after_drive
        target = head[:colon].strip()
        prerequisites = head[colon + 1 :]
        if (
            not target
            or len(target.split()) != 1
            or prerequisites.startswith(":")
            or "%" in target
            or "%" in prerequisites
            or text[colon + 1 :].lstrip().startswith("##")
            or target in DECLARATIVE_TARGETS
            or self.rule._is_template_placeholder(target)
            or target.endswith("&")
            or (rescanned and LineUtils.has_semicolon_on_second_scan(target))
        ):
            return None
        return target

    def _compare(self) -> list[str]:
        """Compare each rule that has a recipe with the rules before it."""
        errors: list[str] = []
        # {(target, changes): each earlier rule with a recipe}
        history: dict[tuple[str, int], list[_Rule]] = {}
        for rule in self.rules:
            if rule.target is None or not rule.recipes:
                continue
            # A target with a reference names the same file only while the
            # variables it refers to keep their values, so it is compared
            # only with rules before which no line could change one (GNU
            # make manual 3.7, lines 1193-1203).
            key = (rule.target, rule.changes if "$" in rule.target else 0)
            earlier = history.setdefault(key, [])
            # The latest earlier rule whose recipe make may read together
            # with the recipe of this one; that is the recipe that this rule
            # overrides (see the class docstring).
            for previous in islice(reversed(earlier), _MAX_EARLIER_RULES):
                if not ConditionalTracker.are_mutually_exclusive(
                    previous.context, rule.context
                ) and _read_together(previous, rule):
                    message = (
                        f"Duplicate target '{rule.target}' defined at lines "
                        f"{previous.line_number} and {rule.line_number}. "
                        "Second definition will override the first."
                    )
                    errors.append(
                        self.rule._format_error_message(
                            message, rule.line_number, self.config
                        )
                    )
                    break
            earlier.append(rule)
        return errors


def _both(first: _Readings, second: _Readings) -> _Readings:
    """
    Return the readings in both sets.

    first names only conditionals that have ended and second only open ones,
    so they never name the same conditional.
    """
    return first | second


def _read_together(first: _Rule, second: _Rule) -> bool:
    """Check if one reading reads a recipe of both rules."""
    return any(
        _intersects(one, other) for one in first.recipes for other in second.recipes
    )


def _intersects(first: _Readings, second: _Readings) -> bool:
    """Check if a reading is in both sets."""
    branches = dict(first)
    return all(
        bool(branches[conditional] & taken)
        for conditional, taken in second
        if conditional in branches
    )


def _after_conditional(
    conditional: int, ends: list[tuple[int, list[_Open]]]
) -> list[_Open]:
    """
    Return the rules whose rule context may be open after 'endif'.

    Args:
        conditional: The id of the conditional
        ends: For each branch, also the one of reading none of them: its id
            and the rules whose rule context may be open at its end

    Returns:
        Each such rule, with the readings in which its rule context is open
    """
    every = frozenset(branch for branch, _ in ends)
    found: dict[tuple[int, _Readings], tuple[_Rule, _Readings, set[int]]] = {}
    for branch, entries in ends:
        for rule, readings in entries:
            key = (id(rule), readings)
            if key in found:
                found[key][2].add(branch)
            else:
                found[key] = (rule, readings, {branch})
    result: list[_Open] = []
    # {id of a rule: the number of its entries in result}
    per_rule: dict[int, int] = {}
    for rule, readings, branches in found.values():
        if frozenset(branches) != every:
            # Open only in the readings that take one of those branches
            readings = readings | {(conditional, frozenset(branches))}
        if per_rule.get(id(rule), 0) >= _MAX_READINGS:
            continue
        per_rule[id(rule)] = per_rule.get(id(rule), 0) + 1
        result.append((rule, readings))
    return list(dict.fromkeys(result))


def _latest_rules(entries: list[_Open]) -> list[_Open]:
    """
    Keep the entries of the latest _MAX_OPEN_RULES rules, in their order.

    The latest rules are those that come last in the file (_Rule.order).
    """
    rules: dict[int, _Rule] = {}
    for rule, _ in entries:
        rules.setdefault(id(rule), rule)
    if len(rules) <= _MAX_OPEN_RULES:
        return entries
    latest = sorted(rules.values(), key=lambda rule: rule.order)[-_MAX_OPEN_RULES:]
    keep = {id(rule) for rule in latest}
    return [(rule, readings) for rule, readings in entries if id(rule) in keep]
