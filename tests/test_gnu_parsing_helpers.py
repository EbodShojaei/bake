"""Tests for the GNU make parsing helpers in LineUtils.

Line numbers refer to the GNU make 4.4.1 manual. Behaviour that the manual
leaves implicit was checked with GNU make 4.4.1, and with 3.81 where 3.81
supports the feature. TestAgainstGnuMake repeats the cases that both versions
agree on with the make found on PATH.
"""

import os
import shutil
import subprocess

import pytest

from mbake.utils.line_utils import LineUtils, VariableAssignment

BS = "\\"  # one backslash, to keep continuation lines readable


class TestFindUnquotedChar:
    """find_unquoted_char finds separators the way make does."""

    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            ("foo: bar ; @echo", 9),
            ("foo: bar # see; notes", 9),
            ("foo: a\\;b", None),
            ("foo: $(x;y) ;", 12),
        ],
    )
    def test_semicolon_before_comment(self, line, expected):
        """The first unquoted ';' or '#' tells an inline recipe from a comment
        (GNU 1488, 1499-1503, 730-742). In 'foo: bar # see; notes' it is the
        '#', so there is no inline recipe."""
        assert LineUtils.find_unquoted_char(line, ";#") == expected

    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            ("a\\:b: X", 4),
            ("a\\\\:b", 3),
            ("a\\\\\\:b:", 6),
            ("\\:", None),
        ],
    )
    def test_backslash_parity(self, line, expected):
        """As with '\\#' (GNU 730-737), an odd run of backslashes escapes the
        character and an even run escapes itself; make applies this to ':'
        and ';' as well."""
        assert LineUtils.find_unquoted_char(line, ":") == expected

    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            ("$(OBJS:.o=.c): x", 13),
            ("${a:b}:", 6),
            ("$(a(b:c)d:e):", 12),
            ("${a(b}:", 6),
            ("$(a{b):", 6),
            ("$(a:b", None),
            ("$$:", 2),
            ("$::", 2),
            ("x$", None),
        ],
    )
    def test_variable_references_are_skipped(self, line, expected):
        """Characters inside $(...) and ${...} are literal; only the same kind
        of bracket nests, and an unterminated reference runs to the end of the
        line. '$$' and single-character references such as '$:' are skipped
        whole (GNU 739-742)."""
        assert LineUtils.find_unquoted_char(line, ":") == expected

    def test_start_index(self):
        """The search starts at start, but backslashes before it still count
        (GNU 730-737)."""
        assert LineUtils.find_unquoted_char("a:b:c", ":", 2) == 3
        assert LineUtils.find_unquoted_char("\\:x:", ":", 1) == 3

    def test_dollar_always_starts_a_reference(self):
        """A '$' starts a variable reference, so it is never found
        (GNU 739-742)."""
        assert LineUtils.find_unquoted_char("a $b $", "$") is None


class TestFindCommentStart:
    """find_comment_start finds make comments."""

    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            ("a # c", 2),
            ("# full", 0),
            ("a \\# c", None),
            ("a \\\\# c", 4),
            ("a \\\\\\# c", None),
        ],
    )
    def test_comment_and_escapes(self, line, expected):
        """'#' starts a comment; '\\#' is a literal '#', and an even run of
        backslashes leaves the '#' unescaped (GNU 730-737)."""
        assert LineUtils.find_comment_start(line) == expected

    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            ("X := $(subst #,x,a#b) # c", 22),
            ("X := ${subst #,x,a#b}", None),
            ("X := $(foo # c", None),
            ('X := "a#b"', 7),
            ("X := a$$#b", 8),
            ("X := a$#b", None),
            ("no comment", None),
            ("", None),
        ],
    )
    def test_hash_inside_references_quotes_and_dollars(self, line, expected):
        """'#' inside a variable reference or function call is literal
        (GNU 739-742; make 4.4.1 sets 'X := $(subst #,x,a#b)' to 'axb').
        Quotes are not special: GNU 730-737 names only '\\#' as an escape,
        and make sets 'X := "a#b"' to '"a'. '$$' is a literal '$', so 'a$$#b'
        has a comment, while '$#' is a reference to the variable '#' (make
        4.4.1 sets 'X := a$#b' to 'ab'). make 3.81 does not follow GNU
        739-742 and reads both the subst and the '$#' cases as comments."""
        assert LineUtils.find_comment_start(line) == expected


class TestParseVariableAssignment:
    """parse_variable_assignment splits assignments like make."""

    @pytest.mark.parametrize(
        ("text", "operator", "value"),
        [
            ("CC = gcc", "=", "gcc"),
            ("CC:=gcc", ":=", "gcc"),
            ("CC ::= gcc", "::=", "gcc"),
            ("CC :::= gcc", ":::=", "gcc"),
            ("CC ?= gcc", "?=", "gcc"),
            ("CC += -g", "+=", "-g"),
            ("CC != echo hi", "!=", "echo hi"),
        ],
    )
    def test_operators(self, text, operator, value):
        """Every assignment operator (GNU 4577-4579, 4612-4625, 4649-4664)."""
        assert LineUtils.parse_variable_assignment(text) == VariableAssignment(
            (), "CC", operator, value
        )

    @pytest.mark.parametrize(
        ("text", "name", "operator"),
        [
            ("cflags = -g", "cflags", "="),
            ("my.var = 1", "my.var", "="),
            ("$(prefix)_name := x", "$(prefix)_name", ":="),
            ("a+b = 1", "a+b", "="),
            ("X\t= 1", "X", "="),
            ("   X = 1", "X", "="),
            ("a$:=1", "a$:", "="),
            ("a\\:= b", "a\\", ":="),
        ],
    )
    def test_names(self, text, name, operator):
        """A name may hold any characters but ':', '#', '=' and whitespace, in
        any case, and variable references (GNU 4091-4092, 4100-4101,
        4585-4586, 4595-4597). '$:' is a reference, so 'a$:=1' assigns to
        'a$:' with '=', and a backslash does not escape the ':' of ':='."""
        result = LineUtils.parse_variable_assignment(text)
        assert result is not None
        assert (result.name, result.operator) == (name, operator)

    def test_modifiers(self):
        """'export', 'unexport', 'override' and 'private' may precede the
        name, in any number and order (GNU 4942-4944, 10883-10902)."""
        result = LineUtils.parse_variable_assignment(
            "override export private CFLAGS += -O2"
        )
        assert result is not None
        assert result.modifiers == ("override", "export", "private")
        assert (result.name, result.operator, result.value) == ("CFLAGS", "+=", "-O2")
        assert LineUtils.parse_variable_assignment("unexport X ?= 1") == (
            VariableAssignment(("unexport",), "X", "?=", "1")
        )

    @pytest.mark.parametrize(
        ("text", "name"),
        [
            ("export = 1", "export"),
            ("define = 1", "define"),
            ("ifeq = 1", "ifeq"),
            ("override := 2", "override"),
            ("vpath += x", "vpath"),
        ],
    )
    def test_directive_words_as_variable_names(self, text, name):
        """A directive word is a valid variable name (GNU 4091-4092);
        make 4.4.1 reads 'export = 1' as an assignment to 'export'."""
        result = LineUtils.parse_variable_assignment(text)
        assert result is not None
        assert (result.modifiers, result.name) == ((), name)

    @pytest.mark.parametrize(
        ("text", "value"),
        [
            ("X = a b  ", "a b  "),
            ("X =\t \tv", "v"),
            ("X = a # c ", "a # c "),
            ("X = a\\#b", "a\\#b"),
            ("X =", ""),
            ("X =   ", ""),
        ],
    )
    def test_value_is_source_text_with_trailing_whitespace(self, text, value):
        """The value starts after the operator and its leading whitespace
        (GNU 4579-4580, 4585-4586) and keeps trailing whitespace
        (GNU 4273-4288). Comments and escapes are left for the caller."""
        result = LineUtils.parse_variable_assignment(text)
        assert result is not None
        assert result.value == value

    @pytest.mark.parametrize(
        "text",
        [
            "export",
            "export X",
            "define X",
            "define X =",
            "undefine X",
            "override define X",
            "foo: bar",
            "foo : bar",
            "foo::bar",
            "foo: X = 1",
            "X # = 1",
            "# X = 1",
            "= 1",
            ":= 1",
            "foo bar = 1",
            "foo $(x)= 1",
            "X + = 1",
            "X : = 1",
            "X::::=1",
            "",
            "   ",
        ],
    )
    def test_non_assignments(self, text):
        """Rule lines, comments, define/undefine directives, 'export NAME',
        empty names and names with whitespace are not assignments
        (GNU 4091-4092, 4577-4579, 730-737, 4795-4799, 4864-4871)."""
        assert LineUtils.parse_variable_assignment(text) is None


class TestIsTargetSpecificVariable:
    """is_target_specific_variable recognises every target-specific form."""

    @pytest.mark.parametrize(
        "line",
        [
            "prog : CFLAGS = -g",
            "%.o : CFLAGS = -O",
            "lib/%.o: CFLAGS := -fPIC -g",
            "%.o: CFLAGS := -g",
        ],
    )
    def test_manual_examples(self, line):
        """The manual's target- and pattern-specific examples
        (GNU 4938-4951, 4971-4976, 4994-5005, 5018-5019)."""
        assert LineUtils.is_target_specific_variable(line)

    @pytest.mark.parametrize(
        "line",
        [
            "foo: bar = 1",
            "foo: CFlags = -g",
            "foo: my.var = 1",
            "foo: $(V) = 1",
            "foo: X ::= 1",
            "foo: X :::= 1",
            "foo: X != echo",
            "foo: X ?= 1",
            "foo: X += 1",
            "foo: override export CFLAGS += -O2",
            "foo: unexport X = 1",
            "foo: private X = 1",
            "foo: export = 1",
            "foo:X=1",
        ],
    )
    def test_any_name_operator_and_modifier(self, line):
        """Any assignment form, modifier and name case
        (GNU 4091-4092, 4100-4101, 4940-4951, 5045-5047)."""
        assert LineUtils.is_target_specific_variable(line)

    @pytest.mark.parametrize(
        "line",
        [
            "$(OBJS): CFLAGS += -g",
            "foo bar: X = 1",
            "a\\:b: X = 1",
            "prog:: x = 1",
            "foo :: X = 1",
            "foo bar &: X = 1",
        ],
    )
    def test_target_lists(self, line):
        """Several targets get the value each (GNU 4946-4947). The target list
        ends at the first unescaped ':' outside references (GNU 730-742), and
        double-colon rules take target-specific variables too (GNU 2721-2722;
        make 4.4.1 and 3.81 both set x for 'prog:: x = 1')."""
        assert LineUtils.is_target_specific_variable(line)

    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            ("foo: X = a;b", True),
            ("foo: X = a#b", True),
            ("foo: X = $(subst ;,x,a;b)", True),
            ("foo: X = a\\;b", True),
            ("foo: ;X=1", False),
            ("foo: a;X=1", False),
            ("foo: # X = 1", False),
        ],
    )
    def test_line_is_cut_at_first_semicolon_or_comment(self, line, expected):
        """make cuts a rule line at its first unquoted ';' or '#' before it
        tests for an assignment: 'foo: ;X=1' is an inline recipe
        (GNU 1488, 1499-1503) and 'foo: # X = 1' a plain rule (GNU 730-737).
        A ';' after the assignment belongs to the value: make sets X to 'a;b'
        for 'foo: X = a;b'."""
        assert LineUtils.is_target_specific_variable(line) is expected

    @pytest.mark.parametrize(
        "line",
        [
            "CC:=gcc",
            "CC = a:b",
            "foo: bar",
            "foo:",
            "foo: X",
            "foo.o: %.o: %.c",
            ": X = 1",
            "foo: = 1",
            "foo: export",
            "foo: define X = 1",
            "X::::=1",
            "# foo: X = 1",
            "",
        ],
    )
    def test_not_target_specific(self, line):
        """Plain assignments, rules, static pattern rules (GNU 2603), rules
        without targets, empty names and comments are not target-specific
        (GNU 4577-4579, 4938-4951, 730-737)."""
        assert not LineUtils.is_target_specific_variable(line)

    @pytest.mark.parametrize("line", ["&: X = 1", "&:: X = 1", " &: X = 1"])
    def test_grouped_separator_without_targets(self, line):
        """A bare '&' is only the grouped-target separator, so these lines have
        no targets (GNU 2501-2502). make 3.81, which has no grouped targets,
        would read '&' as a target name."""
        assert not LineUtils.is_target_specific_variable(line)

    @pytest.mark.parametrize(
        "word", sorted(LineUtils.NON_RULE_DIRECTIVE_WORDS - {"endef"})
    )
    def test_directive_lines_are_not_target_specific(self, word):
        """A directive line is never a rule, whatever follows the directive
        word (GNU 10847-10913, 9028-9034, 9091)."""
        assert not LineUtils.is_target_specific_variable(f"{word} foo: X = 1")

    @pytest.mark.parametrize(
        "line",
        [
            "override define foo: X = 1",
            "private define foo: X = 1",
            "override private define foo: X = 1",
            "override export define foo: X = 1",
            "override  define\tfoo: X = 1",
            "override define foo:bar =",
            "override undefine foo: X = 1",
            "private undefine foo: X = 1",
        ],
    )
    def test_modifiers_before_define_or_undefine(self, line):
        """Modifiers before 'define' or 'undefine' leave the line a directive
        (GNU 4776-4781, 4801-4804, 4844-4850, 4878-4882). make 4.4.1 reads
        'override define foo: X = 1' as the start of a define body and
        'private undefine foo: X = 1' as an undefine."""
        assert not LineUtils.is_target_specific_variable(line)

    @pytest.mark.parametrize(
        "line",
        [
            "export: X = 1",
            "vpath: X = 1",
            "ifdef: X = 1",
            "override foo: X = 1",
            "private foo: X = 1",
            "override export foo: X = 1",
            "override vpath foo: X = 1",
            "override define: X = 1",
            "override definefoo: X = 1",
            "private undefine: X = 1",
            "endef foo: X = 1",
        ],
    )
    def test_directive_words_that_start_a_rule(self, line):
        """'export:' is not the word 'export'. 'override' and 'private' start
        an assignment or a directive only when an assignment or the exact word
        'define' or 'undefine' follows them (GNU 4776-4781, 4878-4882,
        10883-10902), so 'override define:' names the targets 'override' and
        'define'. 'endef' only ends a define body (GNU 4797-4799). make 4.4.1
        reads each of these lines as a target-specific variable."""
        assert LineUtils.is_target_specific_variable(line)

    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            ("a" + BS + ";b foo: X = 1", False),
            ("foo " + BS + "; bar: X = 1", False),
            ("foo" + BS + ";bar:: X = 1", False),
            ("a" + BS * 3 + ";b foo: X = 1", True),
            ("a" + BS * 5 + ";b foo: X = 1", False),
            ("a" + BS * 7 + ";b foo: X = 1", True),
            ("a" + BS + ";b foo: X = 1 # c", False),
            ("a" + BS + ";b foo: X = 1" + BS + ";2", False),
            ("a" + BS + ";b foo: X = $(subst ;,x,y)", False),
            ("a" + BS + ";b foo: X = 1;2", True),
            ("a" + BS + ";b foo: X = 1" + BS * 2 + ";2", True),
            ("foo $(a" + BS + ";b): X = 1", True),
            ("a" + BS + "#b foo: X = 1", True),
        ],
    )
    def test_escaped_semicolon_in_target_list(self, line, expected):
        """make removes the backslash before an escaped ';' and, if the line
        has no unquoted ';' (GNU 1499-1503), looks for ';' in the target words
        again, so a ';' after 1, 5, 9, ... backslashes ends the target list
        (GNU 730-737). make 4.4.1 and 3.81 stop with "missing separator" on
        'a\\;b foo: X = 1', but set X for 'a\\\\\\;b foo: X = 1' and
        'a\\;b foo: X = 1;2'. References are skipped, and '#' is not looked
        for again."""
        assert LineUtils.is_target_specific_variable(line) is expected


class TestIsReferenceOnly:
    """is_reference_only recognises lines that expand to makefile text."""

    @pytest.mark.parametrize(
        "text",
        [
            "$(info x)",
            "$(eval $(call T,x))",
            "${VAR}",
            "  $(A) $(B)  ",
            "$(A)$(B)",
            "$(foreach o,$(OBJS),$(eval $(call R,$(o))))",
            "$(info x) # comment",
            "  $(call setup)\t# set up",
            "$(eval \\",
        ],
    )
    def test_reference_only_lines(self, text):
        """These lines hold only references: make expands them and reads the
        result as makefile syntax (GNU 1209-1229, 6381-6390). A trailing
        comment is removed first (GNU 730-742); an unterminated reference runs
        to the end."""
        assert LineUtils.is_reference_only(text)

    @pytest.mark.parametrize(
        "text",
        [
            "$(CC) -o x",
            "echo $(X)",
            "$(A): $(B)",
            "$(A) = 1",
            "$$x",
            "$@",
            "$(info x) \\",
            "# $(info x)",
            "",
            "   ",
        ],
    )
    def test_other_text(self, text):
        """Text besides references, including '$$' and single-character
        references, means the line is not reference-only (GNU 6381-6390,
        1499-1503)."""
        assert not LineUtils.is_reference_only(text)


class TestBackslashContinuation:
    """Backslash/newline parity, with no whitespace stripping."""

    @pytest.mark.parametrize(
        ("text", "expected"),
        [("", 0), ("a", 0), ("a\\", 1), ("a\\\\\\", 3), ("\\\\", 2), ("a\\ ", 0)],
    )
    def test_count_trailing_backslashes(self, text, expected):
        """Only the backslashes at the very end count (GNU 730-733)."""
        assert LineUtils.count_trailing_backslashes(text) == expected

    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            ("a " + BS, True),
            ("a " + BS * 2, False),
            ("a " + BS * 3, True),
            ("a " + BS + " ", False),
            ("a " + BS + "\t", False),
            ("", False),
            (BS, True),
        ],
    )
    def test_ends_with_continuation(self, line, expected):
        """A trailing backslash continues the line unless another backslash
        escapes it, and a backslash followed by whitespace does not
        (GNU 730-733, 765-769, 2910-2915; make 3.81 and 4.4.1 read
        'X = a \\ ' as the value 'a \\ ')."""
        assert LineUtils.ends_with_continuation(line) is expected

    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            ("a " + BS + " ", True),
            ("a " + BS + "\t", True),
            ("a " + BS * 3 + "  ", True),
            ("a " + BS, False),
            ("a " + BS * 2 + " ", False),
            ("a  ", False),
            ("", False),
        ],
    )
    def test_has_dangling_backslash(self, line, expected):
        """An unescaped backslash followed only by whitespace does not
        continue the line, but would once the whitespace is stripped
        (GNU 730-733, 765-769)."""
        assert LineUtils.has_dangling_backslash(line) is expected

    @pytest.mark.parametrize(
        "line",
        ["a " + BS, "a " + BS + " ", "a " + BS * 2, "a " + BS * 3, "a", ""],
    )
    def test_is_continuation_line_uses_strict_parity(self, line):
        """is_continuation_line gives the same answer as ends_with_continuation
        (GNU 730-733, 765-769)."""
        strict = LineUtils.ends_with_continuation(line)
        assert LineUtils.is_continuation_line(line) is strict


class TestJoinLogicalLine:
    """join_logical_line builds the logical line make reads."""

    @pytest.mark.parametrize(
        ("lines", "start", "expected"),
        [
            (["A = a " + BS, "    b", "C"], 0, ("A = a b", 2)),
            (["# c " + BS, "foo:", "x"], 0, ("# c foo:", 2)),
            (["X = 1"], 0, ("X = 1", 1)),
            (["a " + BS, BS, "b"], 0, ("a b", 3)),
            (["X = a " + BS, "  b  "], 0, ("X = a b  ", 2)),
        ],
    )
    def test_joins_like_make(self, lines, start, expected):
        """Outside recipes each backslash/newline and the whitespace around it
        become one space, and consecutive backslash/newlines condense
        (GNU 776-781). A comment continues the same way (GNU 730-733). The
        last line keeps its trailing whitespace: make sets X to 'a b  '
        (GNU 4273-4277)."""
        assert LineUtils.join_logical_line(lines, start) == expected

    @pytest.mark.parametrize(
        ("lines", "expected"),
        [
            (["X = a   b " + BS, " c   d  "], ("X = a   b c   d  ", 2)),
            (["X = a" + BS, "b"], ("X = a b", 2)),
            (["  A = a " + BS, "\tb"], ("  A = a b", 2)),
            (["X = a " + BS, "   " + BS, "  b"], ("X = a b", 3)),
            (["  " + BS, "b"], (" b", 2)),
        ],
    )
    def test_only_whitespace_around_backslash_newline_changes(self, lines, expected):
        """Only the whitespace around a backslash/newline is condensed, and a
        backslash/newline always leaves one space (GNU 776-781); other
        whitespace, including leading whitespace, is kept."""
        assert LineUtils.join_logical_line(lines, 0) == expected

    @pytest.mark.parametrize(
        ("lines", "expected"),
        [
            (["X = a" + BS * 3, "b"], ("X = a" + BS + " b", 2)),
            (["X = a " + BS * 3, "  b"], ("X = a " + BS + " b", 2)),
            (["X = a" + BS * 5, "b"], ("X = a" + BS * 2 + " b", 2)),
            (["X = a" + BS * 2, "b"], ("X = a" + BS * 2, 1)),
        ],
    )
    def test_escaped_backslashes_before_a_continuation(self, lines, expected):
        """Backslashes before a continuation backslash escape each other, and
        make keeps one for each pair: 'X = a\\\\\\' then 'b' gives 'a\\ b'
        (GNU 730-733, 765-769). An even run does not continue the line."""
        assert LineUtils.join_logical_line(lines, 0) == expected

    def test_dangling_backslash_ends_the_line(self):
        """A backslash followed by a space does not continue the line
        (GNU 765-769; make 3.81 and 4.4.1 set X to 'a \\ ' and Y to 'b')."""
        lines = ["X = a " + BS + " ", "Y = b"]
        assert LineUtils.join_logical_line(lines, 0) == ("X = a " + BS + " ", 1)
        assert LineUtils.join_logical_line(lines, 1) == ("Y = b", 2)

    @pytest.mark.parametrize(
        ("lines", "expected"),
        [
            (["X = a " + BS], ("X = a ", 1)),
            (["X = a " + BS, "   "], ("X = a ", 2)),
        ],
    )
    def test_continuation_at_the_end(self, lines, expected):
        """A backslash/newline with nothing after it still becomes a space
        (GNU 776-781): make sets X to 'a ' in both cases when the file ends
        with a newline."""
        assert LineUtils.join_logical_line(lines, 0) == expected

    def test_start_in_the_middle(self):
        """The logical line starts at start; the index after it is returned
        (GNU 766-769)."""
        lines = ["x", "X = a " + BS, "\tb", "z"]
        assert LineUtils.join_logical_line(lines, 1) == ("X = a b", 3)
        assert LineUtils.join_logical_line(lines, 3) == ("z", 4)

    @pytest.mark.parametrize("start", [-1, 2])
    def test_start_out_of_range(self, start):
        """start must index a physical line."""
        with pytest.raises(IndexError):
            LineUtils.join_logical_line(["a", "b"], start)


class TestNonRuleDirectiveWords:
    """NON_RULE_DIRECTIVE_WORDS lists the directives in the manual."""

    def test_words(self):
        """The directives of GNU 10847-10913 plus 'load' and '-load'
        (GNU 9028-9034, 9091). 'override' and 'private' are modifiers
        (GNU 10883-10902): they make a line a directive only before 'define'
        or 'undefine' (GNU 4776-4781, 4878-4882), and
        parse_variable_assignment reports them before an assignment."""
        words = LineUtils.NON_RULE_DIRECTIVE_WORDS
        assert isinstance(words, frozenset)
        assert words == {
            "define",
            "endef",
            "undefine",
            "ifdef",
            "ifndef",
            "ifeq",
            "ifneq",
            "else",
            "endif",
            "include",
            "-include",
            "sinclude",
            "export",
            "unexport",
            "vpath",
            "load",
            "-load",
        }


# make runs with a minimal environment so that no inherited variable (such as X
# or MAKEFLAGS) changes what it reads.
_MAKE_ENV = {"PATH": os.defpath, "LC_ALL": "C"}


@pytest.fixture(scope="module")
def gnu_make():
    """Return (make, true) paths, or skip when GNU make cannot run here."""
    if os.name == "nt":
        pytest.skip("GNU make checks do not run on Windows")
    make = shutil.which("make")
    true = shutil.which("true")
    if make is None or true is None:
        pytest.skip("make or true is not installed")
    try:
        version = subprocess.run(
            [make, "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            env=_MAKE_ENV,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        pytest.skip("make --version failed")
    if "GNU Make" not in version:
        pytest.skip("make is not GNU make")
    return make, true


def _run_make(gnu_make, tmp_path, text, goal):
    """Run make on text with the goal and return the completed process."""
    make, true = gnu_make
    return subprocess.run(
        [make, "-r", "-R", "-f", "-", f"SHELL={true}", goal],
        input=text,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        env=_MAKE_ENV,
    )


def _make_output(gnu_make, tmp_path, text, goal):
    """Run make on text and return the lines it prints that start with '['."""
    proc = _run_make(gnu_make, tmp_path, text, goal)
    return [line for line in proc.stdout.splitlines() if line.startswith("[")]


def _value_of_x(lines):
    """Return the value of X as the helpers read lines (recursive '=' only)."""
    value = ""
    index = 0
    while index < len(lines):
        text, index = LineUtils.join_logical_line(lines, index)
        comment = LineUtils.find_comment_start(text)
        if comment is not None:
            text = text[:comment]
        assignment = LineUtils.parse_variable_assignment(text)
        if assignment is not None and assignment.name == "X":
            value = assignment.value
    return value


class TestAgainstGnuMake:
    """The helpers agree with the GNU make on PATH (3.81 and 4.x alike)."""

    @pytest.mark.parametrize(
        "lines",
        [
            ["X = a " + BS, "  b  "],
            ["X = a " + BS, BS, "b"],
            ["X = a " + BS, "   " + BS, "  b"],
            ["X = a" + BS, "b"],
            ["X = a" + BS * 3, "b"],
            ["X = a" + BS * 5, "b"],
            ["X = a" + BS * 2],
            ["X = a   b " + BS, " c   d  "],
            ["X = a " + BS + " ", "Y = b"],
            ["X = a " + BS, "   "],
            ["  X = a " + BS, "\tb"],
            ["X = a$$#b"],
            ['X = "a#b"'],
            ["X = a b  # c"],
            ["# c " + BS, "X = 1"],
            ["# c " + BS * 2, "X = 1"],
            ["override X = 1"],
            ["export X = 1"],
        ],
    )
    def test_assignment_values(self, gnu_make, tmp_path, lines):
        """Joining, comment removal and value parsing match make's value
        (GNU 730-742, 776-781, 4273-4288)."""
        text = "\n".join(lines) + "\n$(info [$(value X)])\nprobe: ;\n"
        expected = "[" + _value_of_x(lines) + "]"
        assert _make_output(gnu_make, tmp_path, text, "probe") == [expected]

    @pytest.mark.parametrize(
        "line",
        [
            "foo: X = 1",
            "foo : X = 1",
            "foo bar: X = 1",
            "foo: X := 1",
            "foo: X += 1",
            "foo: X ?= 1",
            "foo: override X = 1",
            "foo: export X = 1",
            "foo: X = a;b",
            "foo: X = a#b",
            "foo: X = $(subst ;,x,a;b)",
            "foo: X = a\\;b",
            "foo: # X = 1",
            "%oo: X = 1",
            "foo:: X = 1",
            "foo :: X = 1",
            "foo bar &: X = 1",
            "private foo: X = 1",
            "export foo: X = 1",
            "unexport foo: X = 1",
            "vpath foo: X = 1",
            "sinclude foo: X = 1",
            "-include foo: X = 1",
            "override undefine foo: X = 1",
            "a" + BS * 3 + ";b foo: X = 1",
            "a" + BS + ";b foo: X = 1;2",
            "a" + BS + "#b foo: X = 1",
            "foo $(x" + BS + ";y): X = 1",
        ],
    )
    def test_target_specific_variables(self, gnu_make, tmp_path, line):
        """make sets X for foo exactly when the helper says the line is
        target-specific (GNU 4938-4951, 4994-5005, 1499-1503, 10847-10913,
        4878-4882)."""
        colons = "::" if "::" in line else ":"
        text = f"{line}\nfoo{colons} ;$(info [$(X)])\n"
        output = _make_output(gnu_make, tmp_path, text, "foo")
        assert len(output) == 1
        assert (output[0] != "[]") is LineUtils.is_target_specific_variable(line)

    @pytest.mark.parametrize(
        "line",
        [
            "a" + BS + ";b foo: X = 1",
            "foo " + BS + "; bar: X = 1",
            "a" + BS * 5 + ";b foo: X = 1",
            "a" + BS + ";b foo: X = 1 # c",
        ],
    )
    def test_semicolon_found_again_in_targets(self, gnu_make, tmp_path, line):
        """With no unquoted ';' on the line, make looks for ';' in the target
        words again and stops with "missing separator", so the line is not
        target-specific (GNU 730-737, 1499-1503)."""
        proc = _run_make(gnu_make, tmp_path, f"{line}\nfoo: ;$(info [$(X)])\n", "foo")
        assert proc.returncode != 0
        assert "missing separator" in proc.stderr
        assert not LineUtils.is_target_specific_variable(line)

    @pytest.mark.parametrize(
        "line", ["define foo: X = 1", "override define foo: X = 1"]
    )
    def test_define_lines(self, gnu_make, tmp_path, line):
        """A define line, with or without 'override', starts a define body
        that runs to 'endef' (GNU 4776-4781, 4795-4799, 4844-4850), so make
        never reads it as a target-specific variable."""
        text = f"{line}\nfoo: X = 2\nendef\nfoo: ;$(info [$(X)])\n"
        assert _make_output(gnu_make, tmp_path, text, "foo") == ["[]"]
        assert not LineUtils.is_target_specific_variable(line)
