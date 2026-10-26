"""A line-by-line model of how GNU make reads a makefile.

scan_makefile() reads the lines once, from the top, and gives every line a
LineState: the kind of line make reads it as, and the state make reads it in.
Only the text is modelled, never variable values or the branch that make takes
at a conditional, so the model may say a rule context can reach a line where
make finds none: rule_context is an over-approximation, and False means that
no rule context reaches the line.

Line numbers refer to the GNU make 4.4.1 manual:
- make reads logical lines (3.1.1, lines 776-781). A line that starts with
  the recipe prefix is a recipe line in a rule context; elsewhere it is
  makefile syntax (3.8, lines 1209-1219; 5.1, lines 2878-2905).
- A rule starts a rule context, which lasts until other makefile syntax ends
  it; blank lines, comments and conditional directives keep it (5.1, lines
  2881-2886; 7.1, lines 5315-5333). A line that starts with the recipe prefix
  outside a rule context never starts one: make rejects a rule or other text
  there ("recipe commences before first target", lines 11292-11297).
- Text that is no makefile syntax may expand to a rule (3.8, lines
  1231-1236), so it starts a rule context too.
- Where make's reading depends on more than the text, the model keeps a
  possible rule context: at 'override' and 'define' lines, which end one for
  make 4.x but not for make 3.81; at an 'include' whose file names may expand
  to nothing, which make 3.81 skips; after 'endif', which depends on the
  branch make took; and wherever RecipeValidationRule's model of rule
  contexts finds one, such as after an automake 'if'.
- A define body is the variable's value: make only looks for a nested
  'define' and for the 'endef' that ends it (6.8, lines 4795-4799 and
  4823-4827).
- The first character of the value of .RECIPEPREFIX is the recipe prefix
  (lines 5158-5169), for make 4.x; make 3.81 has no .RECIPEPREFIX. That is
  the value make stores: the text as written for '=' and for a define
  without an operator, which make expands only when the variable is used,
  so '.RECIPEPREFIX = $(X)' makes '$' the prefix; the expansion for ':=',
  '::=' and ':::='; the output of the command for '!=' (lines 1126-1181,
  4588-4592, 4816-4821).

kind, rule_context, depth, in_define and recipe_prefix follow one model of the
whole file. LineState.readings instead follows make through every branch of
every conditional, with make 3.81 and 4.x, and says each way make may read a
line, LineState.recipe_owners says each rule whose recipe it may be part of,
and LineState.skipped_as_recipe says if make may skip it as a recipe line in
a branch that it skips. That model knows where a rule context is certain, and
so where a line that starts with the recipe prefix may still be makefile
syntax.

Known limits of the one-model fields, which readings does not have:
- recipe_prefix follows every .RECIPEPREFIX assignment and define, also one
  in a branch that make may skip. Where the first character of the value
  is only known once make expands a reference or runs a command (see
  _assign_recipe_prefix), the previous prefix stays; readings counts the
  prefix as unknown there.
- A line that starts with the recipe prefix where a rule context is possible
  but not certain is a recipe line for kind, rule_context and depth, so a
  conditional directive there counts for nothing.

Known limits of both models: only the lines given are read. A .RECIPEPREFIX
that make sets while it expands '$(eval ...)' (8.10, lines 6378-6390) or
while it reads an included makefile (3.3, lines 839-849) is not seen, so the
lines after it are read with the recipe prefix before it: after
'$(eval .RECIPEPREFIX = >)', make reads 'all:' and '>@echo OK' as a rule and
its recipe, while both models read '>@echo OK' as makefile syntax.
"""

import dataclasses
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import NamedTuple, Optional

from .format_disable import FormatDisableHandler
from .line_utils import LineUtils, VariableAssignment

# The kinds of lines. A continuation line has the kind of the logical line it
# continues.
BLANK = "blank"
COMMENT = "comment"
RECIPE = "recipe"
CONDITIONAL = "conditional"
DEFINE = "define"
DEFINE_BODY = "define_body"
ENDEF = "endef"
ASSIGNMENT = "assignment"
TARGET_VARIABLE = "target_variable"
DIRECTIVE = "directive"
FUNCTION_CALL = "function_call"
RULE = "rule"
OTHER = "other"

# The whitespace that make skips (GNU make manual 3.1.1, lines 776-781).
_WHITESPACE = " \t\n\v\f\r"

# Conditional directives (GNU make manual 7.2, lines 5386-5421).
_CONDITIONAL_OPENERS = frozenset({"ifdef", "ifndef", "ifeq", "ifneq"})
_CONDITIONAL_WORDS = _CONDITIONAL_OPENERS | {"else", "endif"}

# An automake conditional, 'if NAME' or 'if !NAME'. Its 'else' and 'endif' look
# like make's. automake replaces these lines before make reads the file.
_AUTOMAKE_IF = re.compile(r"if[ \t]+!?\w+[ \t]*")

# A value that configure puts in place of '@NAME@' before make reads the file.
_SUBSTITUTION = re.compile(r"@[A-Za-z_][A-Za-z0-9_]*@")

# The text after the word 'define' of a define line, which names the variable
# and may end with an assignment operator (GNU make manual 6.8, lines
# 4795-4799 and 4816-4821).
_DEFINE_TAIL = re.compile(
    r"[ \t]*(?:(?:export|unexport|override|private)[ \t]+)*define(?:[ \t]+(.*))?",
    re.DOTALL,
)

# The directives that read other makefiles (GNU make manual 3.3, lines
# 839-859).
_INCLUDE_WORDS = frozenset({"include", "-include", "sinclude"})

# The '# bake-format off' and '# bake-format on' lines, as the formatter finds
# them.
_REGION_MARKERS = FormatDisableHandler()

# make's state of an open conditional (its 'ignoring' value in read.c): a
# branch is being read, no branch has been taken yet, or one has been.
_READ, _WAIT, _DONE = 0, 1, 2

# Above this many readings, every way of reading a line counts as possible for
# the rest of the file.
_MAX_READINGS = 256

# What _Readings._step gives for a line that make skips as a recipe line, in a
# branch that it skips (see LineState.skipped_as_recipe). It is no kind of
# line that make reads.
_SKIPPED_RECIPE = "skipped_recipe"


@dataclass(frozen=True)
class LineState:
    """How make reads one physical line, and the state it reads it in.

    The state is the one before the line takes effect. A continuation line
    has the kind, text and state of the logical line it continues.

    Attributes:
        kind: One of the kind constants of this module.
        text: The logical line. Makefile syntax and define bodies are joined
            as LineUtils.join_logical_line joins them (GNU make manual
            3.1.1, lines 776-781). A recipe line keeps its backslash/newlines
            (5.1.1, lines 2910-2920), so its physical lines are joined with
            newlines.
        rule_context: False if no rule context can reach the line, so a line
            that starts with the recipe prefix is makefile syntax there.
        rule_line: Where rule_context is True: the index of the logical line
            whose rule the line's recipe would belong to, or None where no
            rule can be in effect. A rule on lines that '# bake-format off'
            hides is represented by the index of that line. Lines that make
            reads with the same rule_line, in the same or nested branches of
            conditionals, belong to the same rule.
        depth: The number of conditionals open at the line, automake 'if'
            included.
        branches: For each open conditional, outermost first, an id of the
            conditional and the number of its branch that the line is in (0
            before its first 'else').
        recipe_prefix: The recipe prefix in effect (GNU make manual, lines
            5158-5169). Where make computes the value of .RECIPEPREFIX, the
            prefix before it (see the module docstring).
        continuation: True if the line continues the line above it.
        logical_start: The index of the first line of the logical line. When
            that line is hidden by '# bake-format off', the index of that
            line.
        readings: Every kind of line that make may read the line as, in any
            branch it may take at the conditionals above, with make 3.81 or
            4.x: RECIPE, DEFINE_BODY, ENDEF or the kind of makefile syntax
            that the line is. A branch that make skips adds nothing but
            CONDITIONAL for a conditional directive, which make reads there
            too, and a branch in which make stops with an error at the line
            adds nothing. So a line that starts with the recipe prefix where
            a rule context is possible but not certain has both RECIPE and
            the kind of makefile syntax it is, and a line in a branch whose
            define body make reads has DEFINE_BODY. Only the lines given
            count: a .RECIPEPREFIX that '$(eval ...)' or an included
            makefile sets is not seen (see the module docstring).
        recipe_owners: The rules whose recipe make may read the line as part
            of, in the readings that have RECIPE, as indexes like rule_line.
            None where the readings are not known one by one, so that the
            line may be part of the recipe of any rule above it.
        recipe_prefix_known: False where make computes the value of
            .RECIPEPREFIX, with '!=' or with ':=' of a reference, so that the
            recipe prefix that make reads is not known (see recipe_prefix).
        skipped_as_recipe: True if, in a branch that make skips, make may
            skip the line as a recipe line without a look at its text, as
            it does with a line that starts with the recipe prefix where a
            rule context is open (GNU make manual 3.8, lines 1217-1219; 6.8,
            lines 4823-4827; 7.2, lines 5511-5513). A conditional directive,
            a define or an endef there counts for nothing in that branch,
            while make reads one that starts with other whitespace, to find
            the lines that belong together. Like readings, it follows every
            branch of every conditional, with make 3.81 and 4.x.
    """

    kind: str
    text: str
    rule_context: bool
    rule_line: Optional[int]
    depth: int
    branches: tuple[tuple[int, int], ...]
    recipe_prefix: str
    continuation: bool
    logical_start: int
    readings: frozenset[str] = frozenset()
    recipe_owners: Optional[frozenset[int]] = frozenset()
    recipe_prefix_known: bool = True
    skipped_as_recipe: bool = False

    @property
    def in_define(self) -> bool:
        """True for a line of a define body, which is the value of a variable."""
        return self.kind == DEFINE_BODY

    @property
    def may_be_define_body(self) -> bool:
        """True if make may read the line as part of a define body.

        That is a line of a body in the one model of kind, or in any of the
        readings. Rules leave such lines as they are: a body is the value of a
        variable (GNU make manual 6.8, lines 4795-4799).
        """
        return self.kind == DEFINE_BODY or DEFINE_BODY in self.readings

    @property
    def is_recipe(self) -> bool:
        """True for a recipe line."""
        return self.kind == RECIPE


def scan_makefile(
    lines: Sequence[str],
    hidden: Optional[Mapping[int, Sequence[str]]] = None,
    *,
    past_errors: bool = False,
) -> list[LineState]:
    """
    Return how make reads each line, as one LineState per line.

    Args:
        lines: The physical lines of the makefile, without newlines
        hidden: The lines that '# bake-format off' regions hide from lines, as
            the formatter passes them to rules in
            context['disabled_region_lines']: {index of a '# bake-format off'
            line: the lines hidden after it}. They are read in place, so they
            count for the state of the lines after them. Without it, every
            '# bake-format off' and '# bake-format on' line counts as unknown
            content that may hold a rule.
        past_errors: Where make stops with an error at a line in a branch,
            go on with that branch as if make skipped the line, for
            readings, recipe_owners and skipped_as_recipe. A recipe line
            leaves the state as it was, so this is how make reads the lines
            below once the rules turn such a line, such as a recipe line
            that lacks its TAB, into a recipe line. Without it, such a
            branch ends at the line.

    Returns:
        A LineState for each line of lines
    """
    return _Scanner(lines, hidden, past_errors).scan()


def recipe_prefixes(
    lines: Sequence[str], hidden: Optional[Mapping[int, Sequence[str]]] = None
) -> list[str]:
    """
    Return the recipe prefix that make reads at each line.

    That is LineState.recipe_prefix of scan_makefile(lines, hidden): the
    prefix that every assignment and define of .RECIPEPREFIX above the line
    sets (GNU make manual, lines 5158-5169), with '+=', define and the lines
    that '# bake-format off' hides read as make 4.4.1 reads them. The prefix
    only changes where a line names .RECIPEPREFIX, so a makefile that never
    does keeps the TAB and is not scanned.

    Args:
        lines: The physical lines of the makefile
        hidden: As for scan_makefile

    Returns:
        The recipe prefix of each line of lines
    """
    if not _names_recipe_prefix(lines, hidden):
        return ["\t"] * len(lines)
    return [state.recipe_prefix for state in scan_makefile(lines, hidden)]


def line_by_line_prefixes(lines: Sequence[str]) -> list[str]:
    """
    Return the recipe prefix at each line as the rules used to read it.

    That is LineUtils.get_active_recipe_prefix(lines, index) for each line:
    the last line above that matches its pattern for '.RECIPEPREFIX = X' or
    '.RECIPEPREFIX := X'. It misses '+=', define, modifiers, other operators,
    values that are not one character, comments, the empty value, continued
    lines and the lines that '# bake-format off' hides, and it reads such a
    line also in a define body or as a recipe line.

    Args:
        lines: The lines that a rule reads

    Returns:
        The prefix of each line in that reading
    """
    found: list[str] = []
    prefix = "\t"
    for line in lines:
        found.append(prefix)
        if ".RECIPEPREFIX" in line:
            prefix = _line_sets_prefix(line, prefix)
    return found


def _line_sets_prefix(line: str, prefix: str) -> str:
    """
    Return the prefix after one line in the reading of line_by_line_prefixes.

    LineUtils.get_active_recipe_prefix reads the lines above an index. A line
    above that sets the prefix to a known character shows whether this line
    sets it: the result stays that character only if it does not, or if it
    sets that very character, which a second known character tells apart.
    """
    for known in ("\0", "\1"):
        value = LineUtils.get_active_recipe_prefix(
            [f".RECIPEPREFIX = {known}", line], 2
        )
        if value != known:
            return value
    return prefix


def is_automake_conditional(code: str) -> bool:
    """
    Check if a logical line opens an automake conditional.

    That is 'if NAME' or 'if !NAME'. Its 'else' and 'endif' look like make's,
    and automake replaces all three lines before make reads the file.

    Args:
        code: The logical line, cut at its comment

    Returns:
        True if the line is such an 'if'
    """
    return _AUTOMAKE_IF.fullmatch(code.strip(_WHITESPACE)) is not None


def _names_recipe_prefix(
    lines: Sequence[str], hidden: Optional[Mapping[int, Sequence[str]]]
) -> bool:
    """Check if any line, hidden lines included, names .RECIPEPREFIX."""
    regions = (hidden or {}).values()
    return any(".RECIPEPREFIX" in line for line in lines) or any(
        ".RECIPEPREFIX" in line for region in regions for line in region
    )


def define_body_lines(
    lines: Sequence[str],
    hidden: Optional[Mapping[int, Sequence[str]]] = None,
    strip_dangling: bool = False,
) -> set[int]:
    """
    Return the indexes of the lines that make may read as part of a define body.

    See LineState.may_be_define_body. Lines without the word 'define' cannot
    open a body, so a file without one is not scanned.

    Args:
        lines: The physical lines of the makefile
        hidden: As for scan_makefile
        strip_dangling: Read the lines as strip_dangling_backslashes leaves
            them, as WhitespaceRule does when it removes trailing whitespace,
            so that a rule that runs before it makes the same choice on its
            output

    Returns:
        The indexes of the lines that may be part of a define body
    """
    regions = (hidden or {}).values()
    if not any("define" in line for line in lines) and not any(
        "define" in line for region in regions for line in region
    ):
        return set()
    if strip_dangling:
        states = strip_dangling_backslashes(lines, hidden)[1]
    else:
        states = scan_makefile(lines, hidden)
    return {index for index, state in enumerate(states) if state.may_be_define_body}


def strip_dangling_backslashes(
    lines: Sequence[str],
    hidden: Optional[Mapping[int, Sequence[str]]] = None,
    states: Optional[Sequence[LineState]] = None,
) -> tuple[list[str], list[LineState]]:
    """
    Remove the whitespace after a final backslash outside define bodies.

    A backslash followed by whitespace does not continue a line (GNU make
    manual 3.1.1, lines 762-769). WhitespaceRule still removes that
    whitespace outside define bodies, as it always has, which makes the line
    continue. A line that this joins to a define line can end the body that
    the scan found, so the scan is repeated until no more lines change.

    Args:
        lines: The physical lines of the makefile
        hidden: As for scan_makefile
        states: scan_makefile(lines, hidden), if already known

    Returns:
        The lines with that whitespace removed, and scan_makefile of them
    """
    current = list(lines)
    if states is None:
        states = scan_makefile(current, hidden)
    states = list(states)
    while True:
        stripped = False
        for index, line in enumerate(current):
            if (
                LineUtils.has_dangling_backslash(line)
                and not states[index].may_be_define_body
            ):
                current[index] = line.rstrip()
                stripped = True
        if not stripped:
            return current, states
        states = scan_makefile(current, hidden)


def empty_recipe_lines(lines: Sequence[str], states: Sequence[LineState]) -> set[int]:
    """
    Find the recipe lines of only whitespace that make a recipe empty.

    A recipe of only whitespace is an empty recipe, which differs from no
    recipe: no implicit rule or .DEFAULT applies to the target (GNU make manual
    5.1, lines 2890-2891; 5.9, lines 4040-4055). Such a line is needed unless
    make always reads a command of the same rule with it, or another needed
    line: one in the same branch of every conditional around it, or outside
    them. An inline recipe after ';' counts as a command (4.2, lines
    1499-1503). Whitespace is what make skips (3.1.1, lines 776-781), so a
    line of a TAB and a no-break space is a command. A whitespace-only line
    among commands only adds an empty command line, for which make runs no
    shell. Under .ONESHELL it is different: make hands all recipe lines of a
    target to one shell, newlines included (5.3.1, lines 3094-3097), so there
    such a line is part of the script; this function does not look for
    .ONESHELL. make runs the recipe of .PHONY, whose prerequisites are the
    phony targets (4.9, lines 2234-2240), only when .PHONY itself is named
    as a goal, which no build does: it is never the default goal (4.1, lines
    1443-1446). So a line that belongs to it wherever make reads it (see
    whitespace_recipe_lines) is not needed either.

    Args:
        lines: The lines that were scanned
        states: scan_makefile(lines) or scan_makefile(lines, hidden)

    Returns:
        The indexes of the needed lines
    """
    # {rule: the branches of each line that make always reads with the recipe
    # lines of that rule in the same or nested branches}
    readers: dict[int, list[tuple[tuple[int, int], ...]]] = {}
    candidates: list[tuple[int, int, tuple[tuple[int, int], ...]]] = []
    for index, state in enumerate(states):
        if state.continuation:
            continue
        if state.kind == RULE:
            if LineUtils.find_unquoted_char(_code(state.text), ";") is not None:
                readers.setdefault(state.logical_start, []).append(state.branches)
            continue
        rule = state.rule_line
        if state.kind != RECIPE or rule is None:
            continue
        if lines[index][len(state.recipe_prefix) :].strip(_WHITESPACE):
            readers.setdefault(rule, []).append(state.branches)
        else:
            candidates.append((index, rule, state.branches))

    needed: set[int] = set()
    for index, rule, branches in candidates:
        owner = states[rule]
        if (
            owner.kind == RULE
            and branches[: len(owner.branches)] == owner.branches
            and _declares_phony(owner.text)
        ):
            # The line belongs to .PHONY wherever make reads it.
            continue
        rule_readers = readers.setdefault(rule, [])
        if any(branches[: len(known)] == known for known in rule_readers):
            continue
        needed.add(index)
        rule_readers.append(branches)
    return needed


def whitespace_recipe_lines(
    lines: Sequence[str], states: Sequence[LineState], rule: int
) -> list[int]:
    """
    Find the recipe lines of only whitespace that make may read with one rule.

    These are the lines that make may read as recipe lines of the rule at
    index rule: those that follow it with no other rule in between, in its
    branch of every conditional around it or in a branch nested in that (see
    LineState.rule_line), and the lines of only whitespace that any reading
    of make takes for recipe lines of the rule (see LineState.recipe_owners),
    such as a line after an 'endif' when make may skip the rules of the
    branches above it. If the rule line goes, make reads them with the rule
    before it, where they can make an empty recipe (GNU make manual 5.1,
    lines 2881-2891).

    A line that only such a reading takes for a recipe line, because the
    recipe prefix of the reading differs from the one model's, counts only
    when it is all whitespace, as for empty_recipes_to_keep: a line such as
    '>' may be the empty recipe of another rule in yet another reading, and
    whitespace cleanup leaves it as it is.

    Args:
        lines: The lines that were scanned
        states: scan_makefile(lines) or scan_makefile(lines, hidden)
        rule: The index of a line of kind RULE

    Returns:
        The indexes of those lines
    """
    branches = states[rule].branches
    found = []
    for index in range(rule + 1, len(states)):
        state = states[index]
        line = lines[index]
        if state.continuation:
            continue
        if (
            state.kind == RECIPE
            and state.rule_line == rule
            and state.branches[: len(branches)] == branches
            and not line[len(state.recipe_prefix) :].strip(_WHITESPACE)
        ) or (
            RECIPE in state.readings
            and (state.recipe_owners is None or rule in state.recipe_owners)
            and line
            and not line.strip(_WHITESPACE)
        ):
            found.append(index)
    return found


# The lines of a makefile, and scan_makefile of them
ScannedLines = tuple[list[str], list[LineState]]


def cleanup_readings(
    lines: Sequence[str],
    hidden: Optional[Mapping[int, Sequence[str]]] = None,
    strip_dangling: bool = False,
) -> list[ScannedLines]:
    """
    Return the readings of the lines that whitespace cleanup decides on.

    That is scan_makefile of the lines and, with strip_dangling, where
    strip_dangling_backslashes changes them, scan_makefile of the lines it
    leaves as well, last. WhitespaceRule removes the whitespace after a final
    backslash when it removes trailing whitespace, so the run after it reads
    the last reading; a backslash followed by whitespace does not continue a
    line (GNU make manual 3.1.1, lines 762-769), so the readings can differ.

    Args:
        lines: The physical lines of the makefile
        hidden: As for scan_makefile
        strip_dangling: Add the reading of strip_dangling_backslashes

    Returns:
        The readings, as (lines, states) pairs, the given lines first
    """
    states = scan_makefile(lines, hidden)
    readings = [(list(lines), states)]
    if strip_dangling:
        stripped, stripped_states = strip_dangling_backslashes(lines, hidden, states)
        if stripped != readings[0][0]:
            readings.append((stripped, stripped_states))
    return readings


def empty_recipes_to_keep(readings: Sequence[ScannedLines]) -> dict[int, str]:
    """
    Find the recipe lines of only whitespace to keep, and how to keep them.

    In one reading, those that empty_recipe_lines finds become one recipe
    prefix. A line that make may read as a recipe line where the one model of
    scan_makefile reads none, such as after a .RECIPEPREFIX assignment in a
    branch that make may skip, becomes its first character: where make reads
    the line as a recipe line, that character is the recipe prefix and the
    rest is an empty command; elsewhere the line is blank either way (GNU
    make manual 5.1, lines 2884-2891). Such a line that make reads as a
    recipe line of .PHONY only is not kept: make runs that recipe only when
    .PHONY is named as a goal, which no build does (4.1, lines 1443-1446; 4.9,
    lines 2234-2240).

    A line is kept only where every reading keeps it and reads it the same
    way: as the same kind of line, in the same rule contexts, with the same
    recipe prefix (see _same_reading). Where strip_dangling_backslashes
    changes how make reads a line, keeping it could give a rule an empty
    recipe that the makefile did not have (lines 762-769, 4040-4055), so the
    line goes, as it always did. No line below the first line that
    strip_dangling_backslashes changes is kept either: the line that the
    backslash then continues may set a variable that a conditional below
    tests, so make may take another branch there (7.1, lines 5354-5358),
    which the readings, made from the text alone, do not show. The run after
    this one reads the last reading only, and keeps the same lines.

    Args:
        readings: cleanup_readings of the lines

    Returns:
        {index: the line to keep}, as the last reading keeps it
    """
    last_lines, last_states = readings[-1]
    kept = _empty_recipes_in(last_lines, last_states)
    for lines, states in readings[:-1]:
        also = _empty_recipes_in(lines, states)
        changed = next(
            (index for index, line in enumerate(lines) if line != last_lines[index]),
            len(lines),
        )
        kept = {
            index: line
            for index, line in kept.items()
            if index < changed
            and index in also
            and _same_reading(states[index], last_states[index])
        }
    return kept


def orphaned_recipe_lines(
    readings: Sequence[ScannedLines], removed: Sequence[int]
) -> Optional[set[int]]:
    """
    Find the recipe lines of only whitespace to blank when .PHONY lines go.

    make may read such a line as an empty command of a removed '.PHONY:'
    line, in any branch of the conditionals above it (see
    whitespace_recipe_lines). Without the '.PHONY:' line, make would read it
    with the rule before, which could then get an empty recipe, so that no
    implicit rule applies to its targets (GNU make manual 5.1, lines
    2881-2891; 5.9, lines 4040-4055). The line becomes a blank line, which
    make ignores (lines 2884-2886). Where no rule context can reach the
    '.PHONY:' line, such as at the top of the file, the line stays: without
    the '.PHONY:' line make reads it as a blank line where it was its recipe
    line.

    A line that make may also read as the empty recipe of a rule other than
    .PHONY, one that empty_recipes_to_keep keeps, can neither go nor stay
    without changing what make does in some branch. The '.PHONY:' lines then
    have to stay as they are, and None is returned. Every reading has to
    find that a removed '.PHONY:' line may own such a line, so that the run
    after this one, which reads the last reading, finds it too and leaves
    the '.PHONY:' lines alone again.

    Only lines that are all whitespace become blank. A line of just a recipe
    prefix that is not whitespace, such as '>' after '.RECIPEPREFIX = >'
    (GNU make manual 5.1, lines 2878-2891; 16.2 .RECIPEPREFIX, lines
    5158-5169), is an empty command too, but whitespace cleanup leaves it as
    it is, and the lines after it would read differently without it. The
    '.PHONY:' lines then stay as well, which is stable for the same reason.

    Args:
        readings: cleanup_readings of the lines
        removed: The indexes of the '.PHONY:' lines to remove

    Returns:
        The indexes of the lines to blank, as the first reading finds them,
        or None if the '.PHONY:' lines have to stay
    """
    orphaned: set[int] = set()
    conflicts: Optional[set[int]] = None
    for number, (lines, states) in enumerate(readings):
        owned: set[int] = set()
        for index in removed:
            state = states[index]
            if state.kind == RULE and not state.continuation and state.rule_context:
                owned.update(whitespace_recipe_lines(lines, states, index))
        if any(lines[index].strip(_WHITESPACE) for index in owned):
            return None
        if number == 0:
            orphaned = owned
        clash = {index for index in owned if not recipe_of_phony_only(states, index)}
        conflicts = clash if conflicts is None else conflicts & clash
    if conflicts and conflicts & empty_recipes_to_keep(readings).keys():
        return None
    return orphaned


def _same_reading(first: LineState, second: LineState) -> bool:
    """
    Check if two readings of a file read a line the same way.

    That is the same kind of line, the same ways make may read it, the same
    rules whose recipe it may be part of, and the same recipe prefix.
    """
    return (
        first.kind == second.kind
        and first.rule_line == second.rule_line
        and first.readings == second.readings
        and first.recipe_owners == second.recipe_owners
        and first.recipe_prefix == second.recipe_prefix
    )


def _empty_recipes_in(
    lines: Sequence[str], states: Sequence[LineState]
) -> dict[int, str]:
    """Return what empty_recipes_to_keep keeps in one reading."""
    kept = {
        index: states[index].recipe_prefix
        for index in empty_recipe_lines(lines, states)
    }
    for index, state in enumerate(states):
        if (
            index in kept
            or state.continuation
            or RECIPE not in state.readings
            or lines[index].strip(_WHITESPACE)
            or (state.kind == RECIPE and state.rule_line is not None)
            or recipe_of_phony_only(states, index)
        ):
            continue
        kept[index] = lines[index][:1]
    return kept


def value_whitespace_lines(
    lines: Sequence[str], states: Sequence[LineState], as_syntax: bool = False
) -> set[int]:
    """
    Find the lines whose trailing whitespace is part of a variable value.

    make keeps the trailing whitespace of a value (GNU make manual 6.2.2,
    lines 4273-4288). That is the trailing whitespace of the last physical
    line of a line that make may read as an assignment or a target-specific
    variable, also one that starts with the recipe prefix where a rule
    context is possible but not certain (5.1, lines 2881-2884), unless:
    - the line has a comment, which the whitespace belongs to (3.1, lines
      730-742);
    - the value is empty, or the last line is only whitespace, which make
      condenses into the space of the backslash/newline before it (3.1.1,
      lines 776-781);
    - the line ends with a backslash and whitespace, which keeps the cleanup
      it had so far.

    Args:
        lines: The lines that were scanned
        states: scan_makefile(lines) or scan_makefile(lines, hidden)
        as_syntax: Read every line as makefile syntax, even where make reads
            it as a recipe line or not at all. A rule whose output later
            rules may move into or out of a rule context, such as by
            changing the indentation, decides the same way on its output.

    Returns:
        The indexes of those lines
    """
    found: set[int] = set()
    start = 0
    for index, state in enumerate(states):
        if not state.continuation:
            start = index
        kinds = state.readings | {state.kind}
        if not as_syntax and ASSIGNMENT not in kinds and TARGET_VARIABLE not in kinds:
            continue
        line = lines[index]
        if (
            line.rstrip() == line
            or not line.strip()
            or LineUtils.ends_with_continuation(line)
            or LineUtils.has_dangling_backslash(line)
        ):
            continue
        if state.kind in (ASSIGNMENT, TARGET_VARIABLE):
            text = state.text
        else:
            # A line that is a recipe line in the one model: read it as
            # makefile syntax.
            text = LineUtils.join_logical_line(lines, start)[0]
        if LineUtils.find_comment_start(text) is not None:
            continue
        if TARGET_VARIABLE in kinds or (
            as_syntax and LineUtils.is_target_specific_variable(text)
        ):
            assignment = target_variable_assignment(text)
        else:
            assignment = LineUtils.parse_variable_assignment(text)
        if assignment is not None and assignment.value.strip(_WHITESPACE):
            found.add(index)
    return found


def include_whitespace_lines(
    lines: Sequence[str], states: Sequence[LineState], as_syntax: bool = False
) -> set[int]:
    """
    Find the include directives whose trailing whitespace make 3.81 reads.

    make 4.x ignores whitespace at the end of an include directive (GNU make
    manual 3.3, lines 848-856). make 3.81 skips the directive, and keeps a
    rule context, only when the text after the directive word expands to
    nothing with the whitespace at its end (see _names_may_expand_to_nothing):
    'include $(NONE) ' ends the rule context, 'include $(NONE)' does not.
    That whitespace counts where a rule context may reach the line and the
    file names are nothing but references, and the line has no comment.

    Args:
        lines: The lines that were scanned
        states: scan_makefile(lines) or scan_makefile(lines, hidden)
        as_syntax: As for value_whitespace_lines; the whitespace then counts
            wherever the line is such a directive

    Returns:
        The indexes of the last physical lines of those directives
    """
    found: set[int] = set()
    start = 0
    for index, state in enumerate(states):
        if not state.continuation:
            start = index
        if not as_syntax and (
            DIRECTIVE not in state.readings | {state.kind} or not state.rule_context
        ):
            continue
        line = lines[index]
        if (
            line.rstrip() == line
            or not line.strip()
            or LineUtils.ends_with_continuation(line)
            or LineUtils.has_dangling_backslash(line)
        ):
            continue
        if state.kind == DIRECTIVE:
            text = state.text
        else:
            # A line that is a recipe line in the one model: read it as
            # makefile syntax.
            text = LineUtils.join_logical_line(lines, start)[0]
        if LineUtils.find_comment_start(text) is not None:
            continue
        if LineUtils.directive_word(text) not in _INCLUDE_WORDS:
            continue
        names = _include_names(text).rstrip(_WHITESPACE)
        if names and _references_only(names):
            found.add(index)
    return found


def significant_whitespace_lines(
    lines: Sequence[str], states: Sequence[LineState], as_syntax: bool = False
) -> set[int]:
    """
    Find the lines whose trailing whitespace make reads.

    These are the lines of value_whitespace_lines and include_whitespace_lines.

    Args:
        lines: The lines that were scanned
        states: scan_makefile(lines) or scan_makefile(lines, hidden)
        as_syntax: See value_whitespace_lines

    Returns:
        The indexes of those lines
    """
    return value_whitespace_lines(lines, states, as_syntax) | (
        include_whitespace_lines(lines, states, as_syntax)
    )


def recipe_of_phony_only(states: Sequence[LineState], index: int) -> bool:
    """
    Check if make reads a line as a recipe line of .PHONY only, if at all.

    make runs the recipe of .PHONY only when .PHONY itself is named as a
    goal, which no build does: it is never the default goal (GNU make manual
    4.1, lines 1443-1446; 4.9, lines 2234-2240).

    Args:
        states: scan_makefile(lines) or scan_makefile(lines, hidden)
        index: The index of the line

    Returns:
        True if every rule whose recipe the line may be part of (see
        LineState.recipe_owners) has the one target .PHONY
    """
    owners = states[index].recipe_owners
    return owners is not None and all(
        states[owner].kind == RULE and _declares_phony(states[owner].text)
        for owner in owners
    )


def target_variable_assignment(text: str) -> Optional[VariableAssignment]:
    """
    Return the assignment of a target- or pattern-specific variable line.

    The assignment follows the first ':' of the target list (GNU make manual
    6.11, lines 4938-4951), or '::' (6.12, lines 4994-4999).

    Args:
        text: A line for which LineUtils.is_target_specific_variable holds

    Returns:
        The assignment, or None if there is none after the target list
    """
    colon = LineUtils.find_unquoted_char(text, ":")
    if colon is None:
        return None
    rest = text[colon + 1 :]
    if rest.startswith(":"):
        rest = rest[1:]
    return LineUtils.parse_variable_assignment(rest)


class _PrefixValue(NamedTuple):
    """What decides the recipe prefix: the value of .RECIPEPREFIX.

    head is '' for an empty value, which means a TAB, else the first
    character of the value, or None where make computes it. make 4.x starts
    with an empty, simply expanded .RECIPEPREFIX.
    """

    head: Optional[str] = ""
    # True for a recursively expanded variable, whose value make keeps as
    # written (GNU make manual 6.2.1, lines 4167-4174)
    recursive: bool = False

    @property
    def prefix(self) -> Optional[str]:
        """The recipe prefix, or None where make computes it."""
        return "\t" if self.head == "" else self.head


def _assign_recipe_prefix(
    variable: _PrefixValue, operator: str, value: str, body: bool = False
) -> _PrefixValue:
    """
    Return the value of .RECIPEPREFIX after an assignment to it.

    The first character of the value that make stores is the recipe prefix,
    and an empty value means a TAB (GNU make manual, lines 5158-5169). GNU
    make 4.4.1 stores (lines 1126-1181, 4588-4592, 4816-4821):
    - for '=' and a define without an operator, the text as written, which
      make expands only where the variable is used: '$(X)' gives '$';
    - for ':=', '::=' and ':::=', the expansion of the text (':::=' then
      doubles each '$', which leaves the first character), so text that
      starts with a reference gives a value that is not known here, while
      '$$' gives '$';
    - for '!=', the output of the command, which is not known here;
    - for '+=', nothing new where the text or its expansion is empty, else
      the old value, a space and the new text, so only an empty value gets a
      new first character: the text as written for a recursively expanded
      variable, its expansion otherwise (lines 1169-1171);
    - for '?=', nothing new, as make always defines .RECIPEPREFIX.

    Args:
        variable: The value before the assignment
        operator: The assignment operator, '=' for a define without one
        value: The text after the operator, without its comment; for a
            define, the start of its body
        body: True for a define body, which make keeps as written, leading
            whitespace and backslashes included (lines 4795-4814); in a line,
            make skips the whitespace after the operator and reads '\\#' as
            '#' (lines 730-737)

    Returns:
        The value after the assignment
    """
    if not body:
        value = value.lstrip(_WHITESPACE)
        if value.startswith("\\#"):
            value = value[1:]
    if operator in ("=", ":=", "::=", ":::="):
        recursive = operator in ("=", ":::=")
        head = value[:1] if operator == "=" else _expansion_head(value)
        return _PrefixValue(head, recursive)
    if operator == "!=":
        # The command's output, kept as a recursively expanded value
        return _PrefixValue(None, True)
    if operator != "+=" or variable.head != "":
        # The first character of a value that is not empty stays, and one
        # that is not known stays unknown.
        return variable
    new_head = value[:1] if variable.recursive else _expansion_head(value)
    return variable if new_head == "" else variable._replace(head=new_head)


def _expansion_head(text: str) -> Optional[str]:
    """
    Return the first character of what text expands to, if known here.

    Returns '' if the expansion is empty, and None where it starts with a
    variable reference, which may expand to anything (GNU make manual 6.1,
    lines 4117-4121). '$$' is a '$', and so is a '$' that ends the text,
    which GNU make 4.4.1 keeps.
    """
    if not text.startswith("$"):
        return text[:1]
    if text == "$" or text.startswith("$$"):
        return "$"
    return None


def _define_name_and_operator(code: str) -> tuple[str, str]:
    """
    Return the variable name and the assignment operator of a define line.

    The operator is '=' when the line has none (GNU make manual 6.8, lines
    4795-4799 and 4816-4821).

    Args:
        code: A line of kind DEFINE, cut at its comment
    """
    match = _DEFINE_TAIL.fullmatch(code)
    tail = (match.group(1) or "") if match else ""
    assignment = LineUtils.parse_variable_assignment(tail)
    if assignment is not None and not assignment.modifiers:
        return assignment.name, assignment.operator
    return tail.strip(_WHITESPACE), "="


def _body_start(start: Optional[str], text: str) -> Optional[str]:
    """
    Add a logical line to the start of a define body.

    A body is its lines joined by newlines (GNU make manual 6.8, lines
    4806-4814). make joins a body line that ends in a backslash with the next
    one as it joins makefile syntax (3.1.1, lines 776-781), so the body of
    'define X', '\\', '>', 'endef' is ' >'. Only its first two characters
    count for .RECIPEPREFIX (see _expansion_head), so only those are kept.

    Args:
        start: The start of the body so far, or None before its first line
        text: The next logical line of the body, joined as make joins it

    Returns:
        The start of the body with that line
    """
    return text[:2] if start is None else (start + "\n" + text)[:2]


def _include_names(code: str) -> str:
    """Return the text after the directive word of an include directive."""
    parts = code.split(None, 1)
    return parts[1] if len(parts) > 1 else ""


def _names_may_expand_to_nothing(word: Optional[str], code: str) -> bool:
    """
    Check if an include directive may name no file once make expands it.

    Then nothing is included (GNU make manual 3.3, lines 848-849), and make
    3.81 skips the line and keeps a rule context; make 4.x ends it at any
    include directive. make 3.81 skips the line only when the text after the
    directive word and the blanks after it expands to the empty string, with
    the blanks at its end: 'include $(NONE) ' includes nothing, but it is
    not skipped.

    Args:
        word: The directive word of the line
        code: The logical line, cut at its comment
    """
    if word not in _INCLUDE_WORDS:
        return False
    names = _include_names(code)
    return not names or _references_only(names)


def _references_only(text: str) -> bool:
    """
    Check if text is nothing but variable references, which may expand to ''.

    A reference is '$(...)' or '${...}', up to the bracket that balances the
    one it opens with, or '$' and one character other than '$' (GNU make
    manual 6.1, lines 4117-4121 and 4145-4147). Any other character, a blank
    or '$$' expands to at least one character.
    """
    index = 0
    while index < len(text):
        if text[index] != "$" or index + 1 == len(text) or text[index + 1] == "$":
            return False
        opener = text[index + 1]
        if opener not in "({":
            index += 2
            continue
        closer = ")" if opener == "(" else "}"
        depth = 0
        end = index + 1
        while end < len(text):
            if text[end] == opener:
                depth += 1
            elif text[end] == closer:
                depth -= 1
                if depth == 0:
                    break
            end += 1
        if end == len(text):
            # make stops at an unterminated reference.
            return False
        index = end + 1
    return bool(text)


@dataclass
class _Conditional:
    """An open conditional, as the scanner tracks it."""

    ident: int
    # The rule context before the conditional: (open, rule)
    before: tuple[bool, Optional[int]]
    branch: int = 0
    # The rules that may be in effect at the end of each branch read so far
    ends: list[Optional[int]] = dataclasses.field(default_factory=list)
    # True if an 'else' of this conditional should not go back to the rule
    # context before it (see _Scanner._unsettle)
    unsettled: bool = False


def _code(text: str) -> str:
    """Return a logical makefile line cut at its comment (GNU 730-742)."""
    comment = LineUtils.find_comment_start(text)
    return text if comment is None else text[:comment]


def _declares_phony(text: str) -> bool:
    """Check if a rule line has the one target .PHONY (GNU 2234-2240)."""
    code = _code(text)
    colon = LineUtils.find_unquoted_char(code, ":")
    return colon is not None and code[:colon].split() == [".PHONY"]


def _classify(code: str) -> tuple[str, Optional[str]]:
    """
    Classify a logical line that make reads as makefile syntax.

    Args:
        code: The logical line, cut at its comment, that is no recipe line
            and no line of a define body

    Returns:
        The kind, and for a conditional or a directive its directive word
        ('if' for an automake conditional)
    """
    if not code.strip(_WHITESPACE):
        return BLANK, None
    if LineUtils.is_target_specific_variable(code):
        return TARGET_VARIABLE, None
    word = LineUtils.directive_word(code)
    if word in _CONDITIONAL_WORDS:
        return CONDITIONAL, word
    if word == "define":
        return DEFINE, None
    if word is not None and word != "endef":
        return DIRECTIVE, word
    if LineUtils.parse_variable_assignment(code) is not None:
        return ASSIGNMENT, None
    # A rule has a ':' before any inline recipe (GNU make manual 4.2, lines
    # 1488 and 1499-1503). 'endef' outside a body is an ordinary word for
    # make 4.x.
    semicolon = LineUtils.find_unquoted_char(code, ";")
    targets = code if semicolon is None else code[:semicolon]
    if LineUtils.find_unquoted_char(targets, ":") is not None:
        return RULE, None
    if LineUtils.expands_to_blanks(code):
        return FUNCTION_CALL, None
    if is_automake_conditional(code):
        return CONDITIONAL, "if"
    return OTHER, None


@dataclass(frozen=True)
class _Logical:
    """A logical line, with what every reading of it needs."""

    # Its first physical line, which make tests for the recipe prefix
    first: str
    # Its physical lines
    physical: tuple[str, ...]
    # The logical line, joined as for makefile syntax
    text: str
    # text, cut at its comment
    code: str
    # The kind of makefile syntax: BLANK, COMMENT, ... (see _classify)
    kind: str
    # The directive word of a conditional or directive
    word: Optional[str]

    @property
    def words(self) -> list[str]:
        """The words of the line before its comment."""
        return self.code.split()


class _Reading(NamedTuple):
    """One way make may have read the lines so far."""

    # make 4.x rather than make 3.81
    make4: bool
    # Whether a rule context is open (make's 'filenames' or 'no_targets')
    rule: bool
    # The value of .RECIPEPREFIX, which make 3.81 does not know
    recipe_prefix: _PrefixValue
    # make's state of each open conditional, outermost first (_READ, ...)
    frames: tuple[int, ...]
    # The nesting depth of the define body that make reads, 0 outside one
    body: int
    # True inside a define of a branch that make skips
    skipped_define: bool
    # Inside a define of .RECIPEPREFIX that make reads: its operator, and
    # the start of its body so far (see _body_start)
    prefix_define: Optional[tuple[str, Optional[str]]] = None

    @property
    def prefix(self) -> Optional[str]:
        """The recipe prefix, or None where make computes it."""
        return self.recipe_prefix.prefix


# (the kind make reads a line as, None where it skips it, or _SKIPPED_RECIPE
# where it skips it as a recipe line; the reading after the line)
_Step = tuple[Optional[str], _Reading]


class _Readings:
    """Every way make may read the lines so far.

    This follows make's read.c: each branch of every conditional and both make
    3.81 and make 4.x. Readings in which make stops with an error are dropped,
    or with past_errors go on as if make skipped the line (see scan_makefile).
    Readings that end in the same state are merged, so their number stays
    small. For each reading it keeps the rules whose rule context may be open
    in it, as the indexes of their lines.
    """

    def __init__(self, past_errors: bool = False) -> None:
        self.readings: dict[_Reading, frozenset[int]] = {
            _Reading(make4, False, _PrefixValue(), (), 0, False): frozenset()
            for make4 in (False, True)
        }
        self.saturated = False
        self.past_errors = past_errors

    def read(
        self, line: _Logical, anchor: int
    ) -> tuple[frozenset[str], Optional[frozenset[int]], bool]:
        """
        Read a logical line.

        Args:
            line: The logical line
            anchor: The index that stands for the line, which names the rule
                that the line starts

        Returns:
            The kinds make may read the line as, the rules whose recipe it
            may be a line of (None if that is not known), and whether make
            may skip it as a recipe line in a branch that it skips
        """
        if self.saturated:
            return frozenset({RECIPE, DEFINE_BODY, ENDEF, line.kind}), None, True
        kinds: set[str] = set()
        owners: set[int] = set()
        skipped = False
        after: dict[_Reading, frozenset[int]] = {}
        for reading, rules in self.readings.items():
            steps = self._step(reading, line)
            if not steps and self.past_errors:
                # make stops at the line: go on as if it skipped it.
                steps = [(None, reading)]
            for kind, successor in steps:
                if kind == _SKIPPED_RECIPE:
                    skipped = True
                elif kind is not None:
                    kinds.add(kind)
                if kind == RECIPE:
                    owners.update(rules)
                if not successor.rule:
                    successor_rules: frozenset[int] = frozenset()
                elif kind in (RULE, OTHER):
                    # The line starts a rule of its own.
                    successor_rules = frozenset({anchor})
                else:
                    successor_rules = rules
                after[successor] = after.get(successor, frozenset()) | successor_rules
        # If make stops at the line in every reading, go on as if it skipped
        # the line.
        if after:
            self.readings = after
        if len(self.readings) > _MAX_READINGS:
            self.saturated = True
        return frozenset(kinds), frozenset(owners), skipped

    def open_unknown_content(self, anchor: int) -> None:
        """Let unknown lines follow, which may start or end a rule context.

        A rule that they may hold is named by anchor.
        """
        after: dict[_Reading, frozenset[int]] = {}
        for reading, rules in self.readings.items():
            for rule in (False, True):
                successor = reading._replace(rule=rule)
                successor_rules = rules | {anchor} if rule else frozenset()
                after[successor] = after.get(successor, frozenset()) | successor_rules
        self.readings = after

    def _step(self, reading: _Reading, line: _Logical) -> list[_Step]:
        """Return each way that one reading reads a logical line."""
        steps: list[_Step] = []
        first_char = line.first[:1]
        if not first_char:
            prefixed_cases: tuple[bool, ...] = (False,)
        elif reading.prefix is None:
            # A prefix that make computes is taken to be no character that
            # names start with, which would clash with every name.
            plausible = not (first_char.isalnum() or first_char == "_")
            prefixed_cases = (True, False) if plausible else (False,)
        else:
            prefixed_cases = (first_char == reading.prefix,)
        ignoring = any(reading.frames)
        for prefixed in prefixed_cases:
            if reading.body:
                steps.append(_body_step(reading, line, prefixed))
            elif prefixed and reading.rule:
                # A recipe line. In a branch that make skips, the line is
                # skipped without a look at its text (GNU make manual 7.1,
                # lines 5315-5333).
                steps.append((_SKIPPED_RECIPE if ignoring else RECIPE, reading))
            else:
                steps.extend(_syntax_steps(reading, line, prefixed))
        return steps


def _body_step(reading: _Reading, line: _Logical, prefixed: bool) -> _Step:
    """
    Read a line of a define body (GNU make manual 6.8, lines 4823-4827).

    The 'endef' of a define of .RECIPEPREFIX sets the recipe prefix from the
    body (see _assign_recipe_prefix).
    """
    directive = None if prefixed else LineUtils.define_body_directive(line.text)
    if directive == "endef" and reading.body == 1:
        ended = reading._replace(body=0, prefix_define=None)
        if reading.prefix_define is not None:
            operator, start = reading.prefix_define
            value = _assign_recipe_prefix(
                reading.recipe_prefix, operator, start or "", body=True
            )
            ended = ended._replace(recipe_prefix=value)
        return ENDEF, ended
    if reading.prefix_define is not None:
        operator, start = reading.prefix_define
        start = _body_start(start, line.text)
        reading = reading._replace(prefix_define=(operator, start))
    if directive == "define":
        return DEFINE_BODY, reading._replace(body=reading.body + 1)
    if directive == "endef":
        return DEFINE_BODY, reading._replace(body=reading.body - 1)
    return DEFINE_BODY, reading


def _syntax_steps(reading: _Reading, line: _Logical, prefixed: bool) -> list[_Step]:
    """Read a line as makefile syntax, in a branch that make reads or skips."""
    ignoring = any(reading.frames)
    if line.kind in (BLANK, COMMENT):
        return [(None if ignoring else line.kind, reading)]
    if reading.skipped_define:
        # Only the 'endef' line ends it: make 4.x wants nothing else on that
        # line, make 3.81 looks at the first word.
        words = line.words
        if words == ["endef"] or (not reading.make4 and words[:1] == ["endef"]):
            return [(None, reading._replace(skipped_define=False))]
        return [(None, reading)]
    if line.kind == CONDITIONAL:
        # make reads conditional directives in skipped branches too, to
        # find the 'else' and 'endif' that belong together.
        return [
            (CONDITIONAL, reading._replace(frames=frames))
            for frames in _conditional_frames(reading.frames, line)
        ]
    if ignoring:
        if line.kind == DEFINE:
            return [(None, reading._replace(skipped_define=True))]
        return [(None, reading)]
    return _syntax_effect(reading, line, prefixed)


def _conditional_frames(
    frames: tuple[int, ...], line: _Logical
) -> list[tuple[int, ...]]:
    """
    Return the states of the open conditionals after a conditional directive.

    An opener starts a branch that make may read or skip, and so does an
    'else ifeq ...' that comes before any branch was read (GNU make manual
    7.2, lines 5399-5421). Inside a branch that make skips, nothing is read.
    A directive with no conditional to end stops make.
    """
    if line.word == "endif":
        return [frames[:-1]] if frames else []
    if line.word == "else":
        if not frames:
            return []
        outer = frames[:-1]
        top = _READ if frames[-1] == _WAIT else _DONE
        words = line.words
        if top == _READ and len(words) > 1 and words[1] in _CONDITIONAL_OPENERS:
            if any(outer):
                return [outer + (_WAIT,)]
            return [outer + (_READ,), outer + (_WAIT,)]
        return [outer + (top,)]
    if any(frames):
        return [frames + (_WAIT,)]
    return [frames + (_READ,), frames + (_WAIT,)]


def _syntax_effect(reading: _Reading, line: _Logical, prefixed: bool) -> list[_Step]:
    """
    Change a reading as make does after a line of makefile syntax it reads.

    Makefile syntax ends a rule context (GNU make manual 5.1, lines
    2881-2884). make 3.81 keeps it at lines that start with 'override', at a
    'define' and at an include directive that names no file, and reads
    'X ::= 1' as a rule. A line that starts with the recipe prefix outside a
    rule context stops make unless it is an assignment or a directive (3.8,
    lines 1217-1219; "recipe commences before first target", lines
    11292-11297), and so does other text that cannot expand to anything
    ("missing separator").
    """
    kind = line.kind
    words = line.words
    first_word = words[0] if words else ""
    ended = reading._replace(rule=False)
    if kind == DEFINE:
        if reading.make4:
            name, operator = _define_name_and_operator(line.code)
            if name == ".RECIPEPREFIX":
                ended = ended._replace(prefix_define=(operator, None))
            return [(DEFINE, ended._replace(body=1))]
        if first_word in ("define", "override"):
            return [(DEFINE, reading._replace(body=1))]
        if first_word == "private":
            return []
        # 'export define X' exports the variables 'define' and 'X'.
        return [(DIRECTIVE, ended)]
    if kind == ASSIGNMENT:
        assignment = LineUtils.parse_variable_assignment(line.code)
        if reading.make4:
            if assignment is not None and assignment.name == ".RECIPEPREFIX":
                ended = ended._replace(
                    recipe_prefix=_assign_recipe_prefix(
                        reading.recipe_prefix, assignment.operator, assignment.value
                    )
                )
            return [(ASSIGNMENT, ended)]
        if first_word == "override":
            return [(ASSIGNMENT, reading)]
        operator = assignment.operator if assignment is not None else "="
        if operator == "::=":
            return [(RULE, reading._replace(rule=True))]
        if operator == ":::=":
            return []
        return [(ASSIGNMENT, ended)]
    if kind == DIRECTIVE:
        return _directive_steps(reading, line, first_word)
    if prefixed:
        return []
    if kind == TARGET_VARIABLE:
        assignment = target_variable_assignment(line.code)
        if (
            not reading.make4
            and assignment is not None
            and "private" in assignment.modifiers
        ):
            # make 3.81 does not know 'private' and reads a rule.
            return [(RULE, reading._replace(rule=True))]
        return [(TARGET_VARIABLE, ended)]
    if kind == FUNCTION_CALL:
        return [(FUNCTION_CALL, ended)]
    if kind == RULE:
        return [(RULE, reading._replace(rule=True))]
    if "$" in line.code or _SUBSTITUTION.search(line.code):
        # It may expand to a rule or to nothing (GNU make manual 3.8, lines
        # 1231-1236).
        return [(OTHER, reading._replace(rule=True)), (OTHER, ended)]
    return []


def _directive_steps(reading: _Reading, line: _Logical, first_word: str) -> list[_Step]:
    """Change a reading at a directive other than a conditional or define."""
    ended = reading._replace(rule=False)
    if reading.make4:
        return [(DIRECTIVE, ended)]
    if first_word == "override":
        # make 3.81 reports an invalid override directive and goes on.
        return [(DIRECTIVE, reading)]
    if line.word in _INCLUDE_WORDS:
        names = _include_names(line.code)
        if not names:
            return [(DIRECTIVE, reading)]
        if _references_only(names):
            return [(DIRECTIVE, reading), (DIRECTIVE, ended)]
        return [(DIRECTIVE, ended)]
    if line.word in ("undefine", "load", "-load") and first_word not in (
        "export",
        "unexport",
    ):
        # make 3.81 does not know these directives.
        return []
    return [(DIRECTIVE, ended)]


class _Scanner:
    """The state of make while it reads the lines from the top."""

    def __init__(
        self,
        lines: Sequence[str],
        hidden: Optional[Mapping[int, Sequence[str]]],
        past_errors: bool = False,
    ) -> None:
        # The lines with the hidden lines in place. visible[k] is the index in
        # lines of merged[k], or None for a hidden line, and anchors[k] is
        # the index in lines that stands for it.
        self.merged: list[str] = []
        self.visible: list[Optional[int]] = []
        self.anchors: list[int] = []
        for index, line in enumerate(lines):
            self.merged.append(line)
            self.visible.append(index)
            self.anchors.append(index)
            for hidden_line in (hidden or {}).get(index, ()):
                self.merged.append(hidden_line)
                self.visible.append(None)
                self.anchors.append(index)
        self.unknown_regions = hidden is None
        self.prefix = "\t"
        # The value of .RECIPEPREFIX that self.prefix comes from, and inside
        # a define of .RECIPEPREFIX its operator and the start of its body
        # (see _body_start)
        self.prefix_value = _PrefixValue()
        self.prefix_define: Optional[tuple[str, Optional[str]]] = None
        # Whether a rule context may reach the next line, and the rule that
        # its recipe would belong to (see LineState.rule_line)
        self.in_rule = False
        self.rule: Optional[int] = None
        self.define_depth = 0
        self.conditionals: list[_Conditional] = []
        self.next_ident = 0
        self.readings = _Readings(past_errors)

    def scan(self) -> list[LineState]:
        """Read all lines and return the state of each visible one."""
        states: list[LineState] = []
        start = 0
        while start < len(self.merged):
            text, end = LineUtils.join_logical_line(self.merged, start)
            code = _code(text)
            kind, word = _classify(code)
            if kind == BLANK and code != text:
                kind = COMMENT
            physical = tuple(self.merged[start:end])
            line = _Logical(self.merged[start], physical, text, code, kind, word)
            readings, owners, skipped = self.readings.read(line, self.anchors[start])
            state = self._read(start, end, line, readings, owners, skipped)
            for index in range(start, end):
                if self.visible[index] is None:
                    continue
                if index == start:
                    states.append(state)
                else:
                    states.append(dataclasses.replace(state, continuation=True))
            if self.unknown_regions and any(
                _REGION_MARKERS.is_format_disabled_line(line)
                for line in self.merged[start:end]
            ):
                # Lines that a region hides may follow, and may hold a rule.
                self._open_rule_context(self.anchors[end - 1])
                self._unsettle()
                self.readings.open_unknown_content(self.anchors[end - 1])
            start = end
        return states

    def _read(
        self,
        start: int,
        end: int,
        line: _Logical,
        readings: frozenset[str],
        owners: Optional[frozenset[int]],
        skipped: bool,
    ) -> LineState:
        """Read the logical line merged[start:end] and return its state."""
        prefixed = self.merged[start].startswith(self.prefix)
        rule_context = self.in_rule
        rule_line = self.rule if self.in_rule else None
        branches = tuple((c.ident, c.branch) for c in self.conditionals)
        recipe_prefix = self.prefix
        recipe_prefix_known = self.prefix_value.prefix is not None
        text = line.text
        if self.define_depth > 0:
            kind = self._read_body_line(text, prefixed)
            if self.prefix_define is not None:
                operator, body_start = self.prefix_define
                if kind == ENDEF:
                    self.prefix_define = None
                    self._set_prefix_value(
                        _assign_recipe_prefix(
                            self.prefix_value, operator, body_start or "", body=True
                        )
                    )
                else:
                    body_start = _body_start(body_start, line.text)
                    self.prefix_define = (operator, body_start)
        else:
            kind, word = line.kind, line.word
            self._note_unsettling_line(line.code, kind, word, prefixed)
            if self.in_rule and prefixed:
                kind = RECIPE
                text = "\n".join(self.merged[start:end])
            else:
                self._take_effect(kind, word, line.code, prefixed, start)
        return LineState(
            kind=kind,
            text=text,
            rule_context=rule_context,
            rule_line=rule_line,
            depth=len(branches),
            branches=branches,
            recipe_prefix=recipe_prefix,
            continuation=False,
            logical_start=self.anchors[start],
            readings=readings,
            recipe_owners=owners,
            recipe_prefix_known=recipe_prefix_known,
            skipped_as_recipe=skipped,
        )

    def _read_body_line(self, text: str, prefixed: bool) -> str:
        """Read a line of a define body (GNU make manual 6.8, lines 4823-4827)."""
        if not prefixed:
            word = LineUtils.define_body_directive(text)
            if word == "define":
                self.define_depth += 1
            elif word == "endef":
                self.define_depth -= 1
                if self.define_depth == 0:
                    self._unsettle()
                    return ENDEF
        return DEFINE_BODY

    def _take_effect(
        self, kind: str, word: Optional[str], code: str, prefixed: bool, start: int
    ) -> None:
        """Change the state as make does after a line of makefile syntax."""
        if kind == CONDITIONAL:
            self._read_conditional(word, prefixed)
        elif kind == DEFINE:
            # make 3.81 keeps the rule context at a 'define' line, make 4.x
            # ends it.
            self.define_depth = 1
            name, operator = _define_name_and_operator(code)
            if name == ".RECIPEPREFIX":
                self.prefix_define = (operator, None)
        elif kind in (ASSIGNMENT, TARGET_VARIABLE, DIRECTIVE, FUNCTION_CALL):
            if kind == ASSIGNMENT:
                assignment = LineUtils.parse_variable_assignment(code)
                if assignment is not None and assignment.name == ".RECIPEPREFIX":
                    self._set_prefix_value(
                        _assign_recipe_prefix(
                            self.prefix_value, assignment.operator, assignment.value
                        )
                    )
            # Makefile syntax ends a rule context (GNU make manual 5.1, lines
            # 2881-2884). make 3.81 keeps it at lines that start with
            # 'override', and at an include directive whose file names
            # expand to nothing. A recipe-prefixed function call outside a
            # rule context stops make (lines 11292-11297).
            if code.split(None, 1)[:1] != [
                "override"
            ] and not _names_may_expand_to_nothing(word, code):
                self._end_rule_context()
        elif kind in (RULE, OTHER) and not prefixed:
            self._open_rule_context(self.anchors[start])

    def _read_conditional(self, word: Optional[str], prefixed: bool) -> None:
        """Change the state at a conditional directive (GNU 5345-5421)."""
        if word in _CONDITIONAL_OPENERS or word == "if":
            self.conditionals.append(
                _Conditional(
                    ident=self.next_ident,
                    before=(self.in_rule, self.rule),
                    # RecipeValidationRule never takes a recipe-prefixed line
                    # or an automake 'if' for the start of a conditional.
                    unsettled=prefixed or word == "if",
                )
            )
            self.next_ident += 1
            if word == "if" and not prefixed:
                # RecipeValidationRule reads an automake 'if' as text that
                # may be a rule; it does not start a rule of its own.
                self.in_rule = True
        elif word == "else":
            if not self.conditionals:
                self.in_rule = True
                return
            conditional = self.conditionals[-1]
            conditional.ends.append(self.rule if self.in_rule else None)
            conditional.branch += 1
            if conditional.unsettled:
                self.in_rule = True
                self.rule = _latest(conditional.before[1], *conditional.ends)
            else:
                # make reads this branch only when it ignored the branches
                # before, so the lines above the conditional decide.
                self.in_rule, self.rule = conditional.before
        elif word == "endif":
            if self.conditionals:
                conditional = self.conditionals.pop()
                self.rule = _latest(
                    conditional.before[1],
                    self.rule if self.in_rule else None,
                    *conditional.ends,
                )
            # The rule context after 'endif' depends on the branch make took.
            self.in_rule = True

    def _note_unsettling_line(
        self, code: str, kind: str, word: Optional[str], prefixed: bool
    ) -> None:
        """Unsettle the open conditionals at lines whose meaning may vary.

        These are the lines that RecipeValidationRule does not read past when
        it looks for the conditional of an 'else': a conditional directive
        that starts with the recipe prefix, which may be a recipe line (GNU
        make manual 5.1, lines 2902-2905), and a line that starts with 'if',
        which may be an automake conditional.
        """
        words = code.split(None, 1)
        if (prefixed and kind == CONDITIONAL and word != "if") or (
            words
            and words[0] == "if"
            and (kind == OTHER or (kind == CONDITIONAL and word == "if"))
        ):
            self._unsettle()

    def _unsettle(self) -> None:
        """Make every open conditional's 'else' keep a possible rule context."""
        for conditional in self.conditionals:
            conditional.unsettled = True

    def _set_prefix_value(self, value: _PrefixValue) -> None:
        """
        Follow a new value of .RECIPEPREFIX (GNU 5158-5169).

        Where the value is not known here, the previous prefix stays.
        """
        self.prefix_value = value
        if value.prefix is not None:
            self.prefix = value.prefix

    def _open_rule_context(self, rule: int) -> None:
        self.in_rule = True
        self.rule = rule

    def _end_rule_context(self) -> None:
        self.in_rule = False
        self.rule = None


def _latest(*rules: Optional[int]) -> Optional[int]:
    """Return the last of the rules that are known, or None."""
    known = [rule for rule in rules if rule is not None]
    return max(known) if known else None
