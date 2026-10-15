"""Tests for '# bake-format off' regions when formatting rules add or remove lines.

Rules only see the lines outside disabled regions. Every region has to come back
unchanged, right after its '# bake-format off' line, wherever the lines around it
moved, and messages have to use the line numbers of the file.
"""

from collections.abc import Sequence
from pathlib import Path
from typing import Any, Optional

import pytest

from mbake.config import Config, FormatterConfig
from mbake.core.formatter import MakefileFormatter
from mbake.plugins.base import FormatResult, FormatterPlugin
from mbake.utils import FormatDisableHandler

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "format_disable"

# Blank-line cleanup turns the three blank lines into one.
BLANK_LINES_BEFORE_REGION = [
    "# Header",
    "",
    "",
    "",
    "# bake-format off",
    "X=1",
    "# bake-format on",
    "",
    "all:",
    "\t@echo all",
    "",
    "clean:",
    "\trm -f x",
]

PROJECT_WITH_REGION = [
    "# Header",
    "",
    "# bake-format off",
    "X=1",
    "# bake-format on",
    "",
    "all: prog",
    "",
    "prog: main.c",
    "\tcc -o prog main.c",
    "",
    "clean:",
    "\trm -f prog",
]

# A region closed by another off marker, one closed by an on marker, an empty
# off/on pair (no region) and a region that runs to the end of the file.
REGION_KINDS = [
    "# bake-format off",
    "a  =  1",
    "# bake-format off",
    "",
    "b  =  2",
    "# bake-format on",
    "",
    "",
    "all:",
    "\t@echo all",
    "# bake-format off",
    "# bake-format on",
    "",
    "# bake-format off",
    "tail  :  x",
]

MARKERS_AROUND_ONE_LINE = [
    "x = 1",
    "# bake-format off",
    "keep   me",
    "# bake-format on",
    "all:",
    "\t@echo hi",
]


def _formatter(gnu_error_format: bool = True, **options: Any) -> MakefileFormatter:
    return MakefileFormatter(
        Config(formatter=FormatterConfig(**options), gnu_error_format=gnu_error_format)
    )


def _region_lines(lines: Sequence[str]) -> list[list[str]]:
    """The hidden lines of each disabled region, in file order."""
    regions = FormatDisableHandler().find_disabled_regions(list(lines))
    return [region.original_lines for region in regions]


def _disabled_indices(lines: Sequence[str]) -> set[int]:
    regions = FormatDisableHandler().find_disabled_regions(list(lines))
    return {i for region in regions for i in range(region.start_line, region.end_line)}


class _LineRewriter(FormatterPlugin):
    """A custom rule that replaces the lines it is given."""

    def __init__(self, rewrite: Any, priority: int = 60) -> None:
        super().__init__("line_rewriter", priority=priority)
        self.rewrite = rewrite

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        new_lines = self.rewrite(lines)
        return FormatResult(
            lines=new_lines,
            changed=new_lines != lines,
            errors=[],
            warnings=[],
            check_messages=[],
        )


class _ContextRecorder(FormatterPlugin):
    """A custom rule that records its input lines and the region context."""

    def __init__(self, priority: int) -> None:
        super().__init__(f"context_recorder_{priority}", priority=priority)
        self.calls: list[tuple[list[str], Optional[dict]]] = []

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        self.calls.append((list(lines), context.get("disabled_region_lines")))
        return FormatResult(
            lines=lines, changed=False, errors=[], warnings=[], check_messages=[]
        )


class _HiddenLineClearer(FormatterPlugin):
    """A custom rule that empties the hidden-line lists it is given."""

    def __init__(self) -> None:
        super().__init__("hidden_line_clearer", priority=2)

    def format(
        self, lines: list[str], config: dict, check_mode: bool = False, **context: Any
    ) -> FormatResult:
        for hidden in (context.get("disabled_region_lines") or {}).values():
            hidden.clear()
        return FormatResult(
            lines=lines, changed=False, errors=[], warnings=[], check_messages=[]
        )


class TestRegionsStayInPlace:
    """Rules that add or remove lines leave every region where it belongs."""

    def test_blank_line_collapse_keeps_region_in_place(self):
        """With the default config, collapsing blank lines above a region must
        not move 'X=1' out of it or repeat the last rule."""
        formatter = _formatter()

        lines, errors, _ = formatter.format_lines(BLANK_LINES_BEFORE_REGION)

        assert lines == [
            "# Header",
            "",
            "# bake-format off",
            "X=1",
            "# bake-format on",
            "",
            "all:",
            "\t@echo all",
            "",
            "clean:",
            "\trm -f x",
        ]
        assert not errors
        content = formatter.format("\n".join(BLANK_LINES_BEFORE_REGION)).content
        assert content == (
            "# Header\n\n# bake-format off\nX=1\n# bake-format on\n\n"
            "all:\n\t@echo all\n\nclean:\n\trm -f x\n"
        )

    @pytest.mark.parametrize(
        ("group", "expected"),
        [
            (
                True,
                [
                    "# bake-format off",
                    "weird   :   x",
                    "# bake-format on",
                    ".PHONY: clean",
                    "",
                    "clean:",
                    "\trm -f x",
                ],
            ),
            (
                False,
                [
                    "# bake-format off",
                    "weird   :   x",
                    "# bake-format on",
                    ".PHONY: clean",
                    "clean:",
                    "\trm -f x",
                ],
            ),
        ],
        ids=["grouped", "individual"],
    )
    def test_phony_insertion_keeps_disabled_lines(self, group, expected):
        """Inserting .PHONY lines must not drop the rule or its recipe."""
        formatter = _formatter(
            auto_insert_phony_declarations=True,
            group_phony_declarations=group,
            phony_at_top=True,
        )

        lines, errors, _ = formatter.format_lines(
            [
                "# bake-format off",
                "weird   :   x",
                "# bake-format on",
                "clean:",
                "\trm -f x",
            ]
        )

        assert lines == expected
        assert not errors

    def test_grouped_phony_at_file_start_keeps_every_rule(self):
        """A grouped .PHONY line at the start of the file must not cost the
        last rule or pull 'X=1' out of its region."""
        formatter = _formatter(
            auto_insert_phony_declarations=True,
            group_phony_declarations=True,
            phony_at_top=False,
        )

        lines, errors, _ = formatter.format_lines(PROJECT_WITH_REGION)

        assert not errors
        assert lines.count("clean:") == 1
        assert lines.count("\trm -f prog") == 1
        start = lines.index("# bake-format off")
        end = lines.index("# bake-format on")
        assert lines[start + 1 : end] == ["X=1"]
        assert lines[0].startswith(".PHONY:")
        assert set(lines[0].split(":", 1)[1].split()) == {"all", "clean"}
        kept = [line for line in lines[1:] if line.strip()]
        assert kept == [line for line in PROJECT_WITH_REGION if line.strip()]

    def test_format_disable_fixture_with_auto_insert(self):
        """The format_disable fixture keeps each region verbatim after its
        '# bake-format off' line when .PHONY lines are added."""
        source = (FIXTURE_DIR / "input.mk").read_text(encoding="utf-8").splitlines()
        expected = (
            (FIXTURE_DIR / "expected.mk").read_text(encoding="utf-8").splitlines()
        )
        formatter = _formatter(
            auto_insert_phony_declarations=True,
            group_phony_declarations=True,
            phony_at_top=False,
        )

        lines, errors, _ = formatter.format_lines(source)

        assert not errors
        assert _region_lines(lines) == _region_lines(source)
        hidden = _disabled_indices(lines)
        inserted = [
            i
            for i, line in enumerate(lines)
            if line.startswith(".PHONY") and i not in hidden
        ]
        kept = [
            line for i, line in enumerate(lines) if line.strip() and i not in inserted
        ]
        # Apart from the added .PHONY and blank lines, nothing is lost,
        # repeated or reordered.
        assert kept == [line for line in expected if line.strip()]
        declared = {
            target for i in inserted for target in lines[i].split(":", 1)[1].split()
        }
        assert {"target1", "target3"} <= declared

    def test_custom_rule_moving_lines_keeps_regions_after_their_markers(self):
        """A rule that adds a line at the top and removes blank lines moves
        every marker; each region still follows its own marker, its blank
        line included."""
        formatter = _formatter()
        formatter.register_rule(
            _LineRewriter(
                lambda lines: ["# added"] + [line for line in lines if line.strip()]
            )
        )

        lines, errors, _ = formatter.format_lines(REGION_KINDS)

        assert lines == [
            "# added",
            "# bake-format off",
            "a  =  1",
            "# bake-format off",
            "",
            "b  =  2",
            "# bake-format on",
            "all:",
            "\t@echo all",
            "# bake-format off",
            "# bake-format on",
            "# bake-format off",
            "tail  :  x",
        ]
        assert not errors

    @pytest.mark.parametrize(
        "rewrite",
        [
            lambda lines: [line.upper() for line in lines if "bake-format" not in line],
            lambda lines: ["# bake-format off"] + [line.upper() for line in lines],
            lambda lines: [
                line.upper() for line in lines if line != "# bake-format on"
            ],
        ],
        ids=["drops-all-markers", "adds-off-marker", "drops-on-marker"],
    )
    def test_rule_changing_marker_lines_is_ignored(self, rewrite):
        """Line changes from a rule that adds or removes marker lines are
        skipped, so the region and its markers stay as written."""
        formatter = _formatter()
        formatter.register_rule(_LineRewriter(rewrite))

        lines, errors, _ = formatter.format_lines(MARKERS_AROUND_ONE_LINE)

        assert lines == MARKERS_AROUND_ONE_LINE
        assert not errors

    @pytest.mark.parametrize(
        "source",
        [
            BLANK_LINES_BEFORE_REGION,
            PROJECT_WITH_REGION,
            REGION_KINDS,
            (FIXTURE_DIR / "input.mk").read_text(encoding="utf-8").splitlines(),
        ],
        ids=["blank-lines", "project", "region-kinds", "fixture"],
    )
    def test_second_run_is_stable_with_regions(self, source):
        """Formatting the output again with the default config changes
        nothing."""
        first = _formatter().format("\n".join(source)).content
        second = _formatter().format(first).content

        assert second == first

    def test_mostly_disabled_file_keeps_missing_newline(self, tmp_path):
        """A file that is almost all disabled keeps its missing final newline."""
        makefile = tmp_path / "Makefile"
        makefile.write_bytes(b"# bake-format off\nfoo:bar\n  x")

        changed, errors, _ = _formatter().format_file(makefile)

        assert changed is False
        assert not errors
        assert makefile.read_bytes() == b"# bake-format off\nfoo:bar\n  x"


class TestMessageLineNumbers:
    """Messages count the lines of the file, hidden lines included."""

    DUPLICATE = [
        "# bake-format off",
        "a",
        "b",
        "# bake-format on",
        "all:",
        "\t@echo ok",
        "all:",
        "\t@echo dup",
    ]

    def test_duplicate_target_lines(self):
        _, errors, _ = _formatter().format_lines(self.DUPLICATE)

        assert errors == [
            "7: Error: Duplicate target 'all' defined at lines 5 and 7. "
            "Second definition will override the first."
        ]

    def test_duplicate_target_lines_traditional_format(self):
        _, errors, _ = _formatter(gnu_error_format=False).format_lines(self.DUPLICATE)

        [error] = [error for error in errors if "Duplicate target 'all'" in error]
        assert "defined at lines 5 and 7." in error
        assert "(line 7)" in error

    def test_line_prefix(self):
        _, _, warnings = _formatter().format_lines(
            ["# bake-format off", "a", "b", "# bake-format on", "FOO =? bar"]
        )

        assert any(
            warning.startswith("Line 5: Possible typo in assignment operator '=?'")
            for warning in warnings
        ), warnings

    def test_line_range_prefix(self):
        _, _, warnings = _formatter(align_variable_assignments=True).format_lines(
            ["# bake-format off", "a", "b", "# bake-format on", "A = 1", "BBB = 2"],
            check_only=True,
        )

        assert "Lines 5-6: Variable assignments would be aligned" in warnings

    @pytest.mark.parametrize(
        "gnu_error_format", [True, False], ids=["gnu", "traditional"]
    )
    def test_quoted_makefile_text_keeps_its_numbers(self, gnu_error_format):
        """Only the message's own line number changes, not numbers in the
        makefile text it quotes. The numbers match those for the same file
        without the markers, where the hidden comment lines are visible."""
        source = [
            "# bake-format off",
            "# hidden 1",
            "# hidden 2",
            "# bake-format on",
            "X=a:b # see (line 2)",
            "Y=a:b # defined at lines 1 and 2",
            "all:",
            "\t@echo $(X)",
        ]
        without_markers = [line.replace("bake-format", "no-format") for line in source]

        def syntax_warnings(lines: list[str]) -> list[str]:
            _, _, warnings = _formatter(gnu_error_format=gnu_error_format).format_lines(
                lines
            )
            return [
                warning for warning in warnings if "Invalid target syntax" in warning
            ]

        warnings = syntax_warnings(source)

        assert warnings == syntax_warnings(without_markers)
        assert len(warnings) == 2
        assert "Invalid target syntax: X=a:b # see (line 2)" in warnings[0]
        assert "Invalid target syntax: Y=a:b # defined at lines 1 and 2" in warnings[1]

    @pytest.mark.parametrize(
        ("gnu_error_format", "message"),
        [
            (True, "5: Warning: Missing final newline"),
            (False, "Warning: Missing final newline (line 5)"),
        ],
        ids=["gnu", "traditional"],
    )
    def test_final_newline_warning_points_at_end_of_file(
        self, gnu_error_format, message
    ):
        """The file ends inside a region, so the last line is a hidden one."""
        source = "all:\n\t@echo a\n# bake-format off\nx\ny"

        _, _, warnings = _formatter(gnu_error_format=gnu_error_format).format_lines(
            source.splitlines(), check_only=True, original_content=source
        )

        assert message in warnings


class TestDisabledRegionLinesContext:
    """Rules can read the hidden lines from context['disabled_region_lines']."""

    SOURCE = [
        "",
        "",
        "",
        "# bake-format off",
        "a = 1",
        "# bake-format off",
        "b = 2",
        "c = 3",
        "# bake-format on",
        "all:",
        "\t@echo all",
        "# bake-format off",
        "# bake-format on",
        "x = 1",
        "# bake-format off",
        "tail = 1",
    ]

    def test_keys_are_marker_indices_in_the_rule_input(self):
        """Every '# bake-format off' line is a key, also one that hides no
        lines, and the keys follow the markers when an earlier rule removes
        lines."""
        formatter = _formatter()
        first, later = _ContextRecorder(priority=1), _ContextRecorder(priority=60)
        formatter.register_rule(first)
        formatter.register_rule(later)

        formatter.format_lines(self.SOURCE)

        [(first_lines, first_hidden)] = first.calls
        assert first_hidden == {
            3: ["a = 1"],
            4: ["b = 2", "c = 3"],
            8: [],
            11: ["tail = 1"],
        }
        [(later_lines, later_hidden)] = later.calls
        assert later_hidden == {
            1: ["a = 1"],
            2: ["b = 2", "c = 3"],
            6: [],
            9: ["tail = 1"],
        }
        for lines, hidden in ((first_lines, first_hidden), (later_lines, later_hidden)):
            markers = {i for i, line in enumerate(lines) if line == "# bake-format off"}
            assert set(hidden) == markers

    def test_marker_at_end_of_file_hides_no_lines(self):
        """An off marker on the last line is a key too, with no hidden lines."""
        formatter = _formatter()
        recorder = _ContextRecorder(priority=1)
        formatter.register_rule(recorder)

        formatter.format_lines(
            [
                "# bake-format off",
                "a  =  1",
                "# bake-format on",
                "all:",
                "\t@echo all",
                "# bake-format off",
            ]
        )

        [(lines, hidden)] = recorder.calls
        assert lines[4] == "# bake-format off"
        assert hidden == {0: ["a  =  1"], 4: []}

    def test_rules_get_their_own_copy(self):
        """A rule that changes the lists it is given cannot change the file."""
        formatter = _formatter()
        recorder = _ContextRecorder(priority=60)
        formatter.register_rule(_HiddenLineClearer())
        formatter.register_rule(recorder)

        lines, _, _ = formatter.format_lines(self.SOURCE)

        assert _region_lines(lines) == [["a = 1"], ["b = 2", "c = 3"], ["tail = 1"]]
        [(_, hidden)] = recorder.calls
        assert hidden == {1: ["a = 1"], 2: ["b = 2", "c = 3"], 6: [], 9: ["tail = 1"]}

    def test_files_without_regions_have_no_hidden_lines(self):
        formatter = _formatter()
        recorder = _ContextRecorder(priority=1)
        formatter.register_rule(recorder)

        formatter.format_lines(["x = 1", "all:", "\t@echo all"])

        [(_, hidden)] = recorder.calls
        assert not hidden
