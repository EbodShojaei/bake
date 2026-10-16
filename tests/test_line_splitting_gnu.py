"""Tests for splitting makefile text into lines the way GNU make reads it.

GNU make ends a line only at a newline: "the newline character is special and
marks the end of a statement" (GNU make manual 3.1.1, lines 757-758 and
766-769). make 3.81 and 4.4.1 drop the one carriage return right before a
newline (CRLF line endings) and read every other character as part of the
line. str.splitlines() also ends lines at CR, VT, FF, FS, GS, RS, NEL, LS and
PS, so formatting cut values and recipe lines in two and turned the rest of a
comment (3.1, lines 730-734) into makefile syntax.

The make-backed tests feed bytes to each GNU make on PATH ('make' and
'gmake'), so every character reaches make, and check that formatting keeps
what make reads.
"""

import io
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import mbake
from mbake import cli
from mbake.cli import app
from mbake.config import Config, FormatterConfig
from mbake.core.formatter import MakefileFormatter
from mbake.utils import line_utils

TESTS = Path(__file__).resolve().parent

# The characters other than a newline at which str.splitlines() ends a line.
# make reads CR, VT and FF as whitespace in some places; the others are never
# whitespace to make.
WHITESPACE_BREAKS = {"CR": "\r", "VT": "\x0b", "FF": "\x0c"}
DATA_BREAKS = {
    "FS": "\x1c",
    "GS": "\x1d",
    "RS": "\x1e",
    "NEL": "\x85",
    "LS": "\N{LINE SEPARATOR}",
    "PS": "\N{PARAGRAPH SEPARATOR}",
}
BREAKS = {**WHITESPACE_BREAKS, **DATA_BREAKS}

# A character inside a variable value (GNU 4273-4288), a comment (730-734) and
# a recipe line (2917-2921); {s} is the character
INSIDE_A_LINE = {
    "value": "X = a{s}b\n$(info [$(X)])\nall: ; @:\n",
    "comment": "# note{s}all: ; @echo injected\nreal: ; @echo real\n",
    "recipe": "all:\n\t@printf '[%s]\\n' 'a{s}b'\n",
}

# A character after a line's last backslash. make does not continue the line,
# because the backslash is not the last character of the line (GNU 730-733,
# 762-769), so the character must not be stripped
AFTER_A_BACKSLASH = {
    "value": "X = a \\{s}\n$(info [$(X)])\nall: ; @:\n",
    "comment": "# c \\{s}\nX = 1\n$(info [$(X)])\nall: ; @:\n",
    "recipe": "all:\n\t@printf '[%s]\\n' a \\{s}\n\tb\n",
}
# A CR, VT or FF after the backslash of a value or a recipe line is trailing
# whitespace, so it still ends the line as before this change, and make then
# reads a continued line, as it did before (left for the handling of these
# characters as data in values and recipe text)
AFTER_A_BACKSLASH_CASES = [
    (name, context)
    for name in sorted(BREAKS)
    for context in sorted(AFTER_A_BACKSLASH)
    if not (name in WHITESPACE_BREAKS and context in ("recipe", "value"))
]

# FS, GS, RS, NEL, LS and PS in the edges of a line, where make reads them as
# part of the line too
DATA_IN_EDGES = {
    "leading": "{s}X = 1\n$(info [$(X)][$({s}X)])\nall: ; @:\n",
    "trailing-value": "X = a{s}\n$(info [$(X)])\nall: ; @:\n",
    "trailing-comment": "# note{s}\nreal: ; @echo real\n",
    "after-tab": "all:\n\t{s}@printf '[%s]\\n' a\n",
}

# A lone carriage return next to makefile syntax. make 3.81 and 4.4.1 read
# some of these differently (make 3.81 keeps it in the value of 'X =\ra',
# 4.4.1 drops it), so formatting must keep it where it is
NEXT_TO_SYNTAX = {
    "after-operator": "X =\ra\n$(info [$(X)])\nall: ; @:\n",
    "after-append": "X = 1\nX +=\ra\n$(info [$(X)])\nall: ; @:\n",
    "after-colon": "all:\rdep\ndep: ; @echo dep\n",
    "before-colon": "all\r: dep\ndep: ; @echo dep\n",
    "static-pattern": "a.o b.o:\r%.o: %.c\n\t@echo $@\n%.c: ; @:\n",
}

# CRLF makefiles: a value with trailing whitespace, a backslash-CRLF in a
# value, a define, a recipe line and a comment (GNU 762-781, 2910-2921,
# 4785-4814)
CRLF_MAKEFILES = {
    "value": b"X = a\r\nY = b \r\n",
    "continued-value": b"X = a \\\r\n  b\r\n",
    "define": b"define V\r\nline1\r\nline2\r\nendef\r\n",
    "continued-recipe": b"all:\r\n\t@printf '[%s]\\n' a\\\r\n\tb\r\n",
    "continued-comment": b"# c \\\r\nX = 1\r\nY = 2\r\n",
}

# '.PHONY' lines with a FF in a target name and a CR after the colon, and the
# auto-insert settings under which PhonyRule groups or splits '.PHONY' lines
PHONY_LINES = {
    "ff-in-a-name": ".PHONY: b\x0c a\na: ; @:\nb: ; @:\n",
    "cr-after-colon": ".PHONY:\r all dep\nall: dep ; @:\ndep: ; @:\n",
}
PHONY_CONFIGS = {
    "group-at-top": {
        "auto_insert_phony_declarations": True,
        "group_phony_declarations": True,
        "phony_at_top": False,
    },
    "ungroup": {
        "auto_insert_phony_declarations": True,
        "group_phony_declarations": False,
    },
}

# Every input above with every character, a carriage return before CRLF, and
# a one-line text without a newline
STABILITY_INPUTS = [
    template.format(s=char)
    for char in BREAKS.values()
    for template in [*INSIDE_A_LINE.values(), *AFTER_A_BACKSLASH.values()]
]
STABILITY_INPUTS += [*NEXT_TO_SYNTAX.values(), "X = a\r\r\nall: ; @:\n", "X = a\rb"]

_MAKE_ENV = {"PATH": os.defpath, "LC_ALL": "C"}
_GOAL = "mbake-test-goal"


def _formatter(**config):
    return MakefileFormatter(Config(formatter=FormatterConfig(**config)))


def _runner() -> CliRunner:
    """Return a CliRunner that keeps stdout and stderr apart."""
    try:
        return CliRunner(mix_stderr=False)  # click < 8.2
    except TypeError:
        return CliRunner()  # click >= 8.2 always captures stderr separately


def _empty_config(tmp_path):
    """Return the path of an empty configuration file: the default settings."""
    path = tmp_path / "bake.toml"
    path.write_text("")
    return path


@pytest.fixture(scope="module", params=["make", "gmake"])
def gnu_make(request):
    """Return (make, true) paths, or skip when that GNU make cannot run here.

    'gmake' is often a second GNU make, such as 4.x next to macOS's 3.81.
    """
    if os.name == "nt":
        pytest.skip("GNU make checks do not run on Windows")
    make = shutil.which(request.param)
    true = shutil.which("true")
    if make is None or true is None:
        pytest.skip(f"{request.param} or true is not installed")
    plain_make = shutil.which("make")
    if (
        request.param != "make"
        and plain_make is not None
        and os.path.realpath(plain_make) == os.path.realpath(make)
    ):
        pytest.skip("gmake is the same program as make")
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


def _dry_run(gnu_make, cwd, data):
    """Return (returncode, stdout) of 'make -n' on the makefile bytes."""
    make, true = gnu_make
    proc = subprocess.run(
        [make, "-r", "-R", "-n", "-f", "-", f"SHELL={true}"],
        input=data,
        cwd=cwd,
        capture_output=True,
        timeout=60,
        env=_MAKE_ENV,
    )
    return proc.returncode, proc.stdout


def _database(gnu_make, cwd, data):
    """Return make's database for the makefile bytes, without its comments.

    The goal is in a second makefile, so nothing follows the last line of the
    makefile under test. Comment lines, which hold file names, line numbers
    and times, and the working directory are left out.
    """
    make, true = gnu_make
    (cwd / "input.mk").write_bytes(data)
    (cwd / "goal.mk").write_bytes(f"{_GOAL}: ;\n".encode())
    proc = subprocess.run(
        [make, "-r", "-R", "-p", "-q", "-f", "input.mk", "-f", "goal.mk"]
        + [f"SHELL={true}", _GOAL],
        cwd=cwd,
        capture_output=True,
        timeout=60,
        env=_MAKE_ENV,
    )
    lines = [
        line
        for line in proc.stdout.split(b"\n")
        if line and not line.startswith(b"#") and not line.startswith(b"CURDIR :=")
    ]
    return proc.returncode, sorted(lines)


class TestSplitMakefileLines:
    """split_makefile_lines() ends lines where make does."""

    @pytest.mark.parametrize("name", sorted(BREAKS))
    def test_character_inside_a_line_stays(self, name):
        char = BREAKS[name]
        text = f"X = a{char}b\nall:\n"
        assert line_utils.split_makefile_lines(text) == [f"X = a{char}b", "all:"]

    @pytest.mark.parametrize("name", sorted(BREAKS))
    def test_character_inside_the_last_line_stays(self, name):
        char = BREAKS[name]
        text = f"Y = 1\nX = a{char}b"
        assert line_utils.split_makefile_lines(text) == ["Y = 1", f"X = a{char}b"]

    @pytest.mark.parametrize(
        "text",
        ["", "a", "a\n", "a\n\n", "\n", "a\r\n", "a\r\nb", "a\r\n\r\n", "a\nb\r\n"],
    )
    def test_newlines_and_crlf_split_as_splitlines(self, text):
        assert line_utils.split_makefile_lines(text) == text.splitlines()

    def test_carriage_return_of_crlf_is_not_part_of_the_line(self):
        """make continues a line that ends with backslash-CRLF."""
        text = "X = a \\\r\n  b\r\nY = 1\r\n"
        assert line_utils.split_makefile_lines(text) == ["X = a \\", "  b", "Y = 1"]

    def test_final_carriage_return_ends_the_last_line(self):
        assert line_utils.split_makefile_lines("X = a\nY = b\r") == ["X = a", "Y = b"]

    def test_classic_mac_line_endings(self):
        text = "X = 1\rall:\r\t@echo hi\r"
        assert line_utils.split_makefile_lines(text) == ["X = 1", "all:", "\t@echo hi"]

    @pytest.mark.parametrize("name", sorted(WHITESPACE_BREAKS))
    @pytest.mark.parametrize(
        "template",
        ["X = a \\{s}\nb\n", "{s}X = 1\n", "X = 1\n{s}\nY = 2\n", "all:\n\t{s}@:\n"],
        ids=["trailing", "leading", "alone", "after-tab"],
    )
    def test_cr_vt_ff_in_the_edges_of_a_line_end_it_as_before(self, name, template):
        """They keep the handling of str.splitlines(), as before. make reads
        them as whitespace only in some of these places, such as before a
        directive or an assignment; elsewhere they are data, such as in make
        3.81's target names and at the end of a value or a recipe line."""
        text = template.format(s=WHITESPACE_BREAKS[name])
        assert line_utils.split_makefile_lines(text) == text.splitlines()

    @pytest.mark.parametrize("name", sorted(DATA_BREAKS))
    @pytest.mark.parametrize(
        "template, expected",
        [
            ("X = a \\{s}\nb\n", ["X = a \\{s}", "b"]),
            ("{s}X = 1\n", ["{s}X = 1"]),
            ("X = 1\n{s}\nY = 2\n", ["X = 1", "{s}", "Y = 2"]),
            ("all:\n\t{s}@:\n", ["all:", "\t{s}@:"]),
        ],
        ids=["trailing", "leading", "alone", "after-tab"],
    )
    def test_fs_gs_rs_nel_ls_ps_never_end_a_line(self, name, template, expected):
        """make never reads them as whitespace (FS ends no 'endif')."""
        char = DATA_BREAKS[name]
        text = template.format(s=char)
        assert line_utils.split_makefile_lines(text) == [
            line.format(s=char) for line in expected
        ]

    def test_fixtures_and_verilator_makefiles_split_as_before(self):
        paths = sorted(TESTS.glob("fixtures/*/*.mk"))
        paths += sorted(path for path in (TESTS / "verilator").iterdir())
        assert len(paths) > 100
        for path in paths:
            # A checkout may have turned LF into CRLF
            text = path.read_bytes().decode("utf-8")
            assert line_utils.split_makefile_lines(text) == text.splitlines(), path.name
            expected = text.replace("\r\n", "\n")
            assert line_utils.normalize_newlines(text) == expected, path.name


class TestNormalizeNewlines:
    """normalize_newlines() reads line endings as universal newlines do."""

    @pytest.mark.parametrize(
        "text, expected",
        [
            ("Y = 1\r\nall:\r\n", "Y = 1\nall:\n"),
            ("X = a\nY = b\r", "X = a\nY = b\n"),
            ("X = 1\rall:\r\t@echo hi\r", "X = 1\nall:\n\t@echo hi\n"),
            ("X = a\r\r\n", "X = a\n\n"),
            ("X = a\rb\r\n", "X = a\rb\n"),
            ("# a\x0cb\r\n", "# a\x0cb\n"),
        ],
        ids=["crlf", "final-cr", "classic-mac", "cr-crlf", "cr-in-line", "ff"],
    )
    def test_line_endings(self, text, expected):
        assert line_utils.normalize_newlines(text) == expected

    @pytest.mark.parametrize(
        "text",
        ["Y = 1\r\nall:\r\n", "X = a\nY = b\r", "X = 1\rY = 2\r", "a\r\r\nb\n\r"],
    )
    def test_matches_universal_newlines(self, text):
        stream = io.TextIOWrapper(io.BytesIO(text.encode()), encoding="utf-8")
        assert line_utils.normalize_newlines(text) == stream.read()


class TestProtectLineBreaks:
    """The rules see stand-ins for the characters inside lines."""

    def test_round_trip(self):
        lines = ["X =\ra", "# a\x0cb", "\tprintf 'a\N{LINE SEPARATOR}b'", ""]
        protected = line_utils.protect_line_breaks(lines)
        assert protected is not None
        assert not any(char in line for line in protected for char in BREAKS.values())
        assert [line_utils.restore_line_breaks(line) for line in protected] == lines

    def test_cr_vt_ff_in_the_edges_of_a_line_are_left_alone(self):
        assert line_utils.protect_line_breaks(["\x0cX = a \\\x0c"]) == [
            "\x0cX = a \\\x0c"
        ]

    @pytest.mark.parametrize("name", sorted(DATA_BREAKS))
    def test_fs_gs_rs_nel_ls_ps_are_replaced_everywhere(self, name):
        char = DATA_BREAKS[name]
        protected = line_utils.protect_line_breaks([f"{char}X = a{char}", char])
        assert protected is not None
        assert not any(char in line for line in protected)

    def test_lines_that_hold_a_stand_in_are_left_alone(self):
        assert line_utils.protect_line_breaks(["X = a" + chr(0xFDD0) + "\x0cb"]) is None

    def test_format_keeps_carriage_return_after_an_operator(self):
        assert _formatter().format("X =\ra\n").content == "X = \ra\n"

    def test_messages_quote_the_character(self):
        text = "a\x0cb: ; @echo 1\na\x0cb: ; @echo 2\n"
        errors = _formatter().format(text).errors
        assert len(errors) == 1
        assert "'a\x0cb'" in errors[0]
        assert chr(0xFDD2) not in errors[0]


class TestFormatterKeepsLines:
    """The formatter no longer cuts a line at these characters."""

    @pytest.mark.parametrize("context", sorted(INSIDE_A_LINE))
    @pytest.mark.parametrize("name", sorted(BREAKS))
    def test_format_keeps_character(self, name, context):
        text = INSIDE_A_LINE[context].format(s=BREAKS[name])
        assert _formatter().format(text).content == text

    def test_disabled_region_keeps_form_feed(self):
        text = "# bake-format off\nX = a\x0cb\n# bake-format on\nY=1\n"
        expected = "# bake-format off\nX = a\x0cb\n# bake-format on\nY = 1\n"
        assert _formatter().format(text).content == expected

    @pytest.mark.skipif(os.name == "nt", reason="the write uses CRLF on Windows")
    def test_format_file_keeps_lone_carriage_return(self, tmp_path):
        path = tmp_path / "Makefile"
        path.write_bytes(b"X = a\rb\nY=1\n$(info [$(X)] [$(Y)])\nall: ; @:\n")
        changed, errors, _ = _formatter().format_file(path)
        assert (changed, errors) == (True, [])
        expected = b"X = a\rb\nY = 1\n$(info [$(X)] [$(Y)])\nall: ; @:\n"
        assert path.read_bytes() == expected

    def test_check_reads_a_comment_as_one_line(self, tmp_path):
        """The rule after the form feed is part of the comment, so 'all' is
        defined once."""
        path = tmp_path / "Makefile"
        data = b"# all: ; @echo a\x0call: ; @echo b\nall: ; @echo c\n"
        path.write_bytes(data)
        changed, errors, _ = _formatter().format_file(path, check_only=True)
        assert (changed, errors) == (False, [])
        assert path.read_bytes() == data

    def test_validate_file_reads_a_comment_as_one_line(self, tmp_path):
        path = tmp_path / "Makefile"
        path.write_bytes(b"# note\x0cY=1\nall: ; @:\n")
        errors = _formatter().validate_file(path)
        assert not any(error.startswith("assignment_spacing") for error in errors)


class TestStability:
    """Formatting the output again changes nothing."""

    @pytest.mark.parametrize("text", STABILITY_INPUTS)
    def test_second_run_changes_nothing(self, text):
        formatter = _formatter()
        once = formatter.format(text).content
        assert formatter.format(once).content == once

    @pytest.mark.parametrize("name", sorted(BREAKS))
    def test_auto_insert_leaves_target_names_with_the_character_alone(self, name):
        """make 3.81 keeps a CR, VT or FF at the end of a target name and
        make 4.4.1 drops it, and a '.PHONY' line cannot end with one."""
        text = f"all{BREAKS[name]}: ; @echo t\n"
        formatter = _formatter(auto_insert_phony_declarations=True)
        assert formatter.format(text).content == text

    @pytest.mark.parametrize("config", sorted(PHONY_CONFIGS))
    @pytest.mark.parametrize("name", sorted(PHONY_LINES))
    def test_phony_line_with_the_character_stays_as_written(
        self, tmp_path, name, config
    ):
        """make reads '.PHONY: b<FF> a' as declaring 'b<FF>'. Grouping or
        splitting the line moved the character to the end of a line, where
        make drops it and the next run ended the line there."""
        text = PHONY_LINES[name]
        formatter = _formatter(**PHONY_CONFIGS[config])
        once = formatter.format(text).content
        assert formatter.format(once).content == once
        assert once == text
        path = tmp_path / "Makefile"
        path.write_bytes(text.encode())
        formatter.format_file(path)
        assert formatter.format_file(path, check_only=True)[:2] == (False, [])


class TestCompatibility:
    """Line endings are handled as before."""

    def test_format_writes_lf_for_crlf(self):
        result = _formatter().format("Y = 1\r\nall:\r\n\t@echo $(Y)\r\n")
        assert result.content == "Y = 1\nall:\n\t@echo $(Y)\n"
        assert result.changed

    @pytest.mark.parametrize(
        "data",
        [
            b"Y = 1\r\nall:\r\n\t@echo $(Y)\r\n",
            b"X = a\nY = b\r",
            b"X = 1\rall:\r\t@echo hi\r",
        ],
        ids=["crlf", "final-cr", "classic-mac"],
    )
    def test_formatted_file_is_left_alone(self, tmp_path, data):
        path = tmp_path / "Makefile"
        path.write_bytes(data)
        formatter = _formatter()
        assert formatter.format_file(path, check_only=True)[:2] == (False, [])
        assert formatter.format_file(path) == (False, [], [])
        assert path.read_bytes() == data

    def test_check_passes_on_a_formatted_crlf_file(self, tmp_path):
        path = tmp_path / "Makefile"
        path.write_bytes(b"Y = 1\r\nall:\r\n\t@echo $(Y)\r\n")
        result = _runner().invoke(
            app,
            ["format", "--config", str(_empty_config(tmp_path)), "--check"]
            + [str(path)],
        )
        assert result.exit_code == 0


class TestAgainstGnuMake:
    """make reads the same from the formatted makefile as from the original.

    Every input works with make 3.81 and 4.x.
    """

    @pytest.mark.parametrize("context", sorted(INSIDE_A_LINE))
    @pytest.mark.parametrize("name", sorted(BREAKS))
    def test_character_inside_a_line(self, gnu_make, tmp_path, name, context):
        """make reads the character as part of the line (GNU 757-758)."""
        text = INSIDE_A_LINE[context].format(s=BREAKS[name])
        formatted = _formatter().format(text).content
        expected = _dry_run(gnu_make, tmp_path, text.encode())
        assert _dry_run(gnu_make, tmp_path, formatted.encode()) == expected
        assert formatted == text

    @pytest.mark.parametrize("name, context", AFTER_A_BACKSLASH_CASES)
    def test_character_after_a_final_backslash(self, gnu_make, tmp_path, name, context):
        """The backslash is not the last character, so make does not continue
        the line (GNU 730-733, 762-769). A CR before CRLF is the case for CR."""
        char = "\r\r" if name == "CR" else BREAKS[name]
        text = AFTER_A_BACKSLASH[context].format(s=char)
        expected = _dry_run(gnu_make, tmp_path, text.encode())
        formatted = _formatter().format(text).content
        assert _dry_run(gnu_make, tmp_path, formatted.encode()) == expected

    @pytest.mark.parametrize("context", sorted(DATA_IN_EDGES))
    @pytest.mark.parametrize("name", sorted(DATA_BREAKS))
    def test_fs_gs_rs_nel_ls_ps_in_the_edges_of_a_line(
        self, gnu_make, tmp_path, name, context
    ):
        """make reads them as part of the line there too."""
        text = DATA_IN_EDGES[context].format(s=DATA_BREAKS[name])
        formatted = _formatter().format(text).content
        expected = _dry_run(gnu_make, tmp_path, text.encode())
        assert _dry_run(gnu_make, tmp_path, formatted.encode()) == expected
        assert formatted == text

    @pytest.mark.parametrize("name", sorted(NEXT_TO_SYNTAX))
    def test_carriage_return_next_to_syntax(self, gnu_make, tmp_path, name):
        data = NEXT_TO_SYNTAX[name].encode()
        expected = _database(gnu_make, tmp_path, data)
        formatted = _formatter().format(data.decode()).content.encode()
        assert _database(gnu_make, tmp_path, formatted) == expected
        path = tmp_path / "Makefile"
        path.write_bytes(data)
        _formatter().format_file(path)
        assert _database(gnu_make, tmp_path, path.read_bytes()) == expected

    @pytest.mark.skipif(os.name == "nt", reason="the write uses CRLF on Windows")
    def test_format_file_with_lone_carriage_return(self, gnu_make, tmp_path):
        data = b"X = a\rb\nY=1\n$(info [$(X)] [$(Y)])\nall: ; @:\n"
        expected = _dry_run(gnu_make, tmp_path, data)
        assert expected[1].startswith(b"[a\rb] [1]\n")
        path = tmp_path / "Makefile"
        path.write_bytes(data)
        _formatter().format_file(path)
        assert _dry_run(gnu_make, tmp_path, path.read_bytes()) == expected

    @pytest.mark.parametrize("name", sorted(CRLF_MAKEFILES))
    def test_crlf_makefile_formatted_with_lf(self, gnu_make, tmp_path, name):
        """make drops the carriage return of each CRLF, so the LF output gives
        the same database."""
        data = CRLF_MAKEFILES[name]
        formatted = _formatter().format(data.decode()).content.encode()
        assert b"\r" not in formatted
        expected = _database(gnu_make, tmp_path, data)
        assert _database(gnu_make, tmp_path, formatted) == expected


class TestCli:
    """The command line reads and copies files without newline translation."""

    @pytest.mark.parametrize(
        "data",
        [b"Y=1\r\nall:\r\n\t@echo $(Y)\r\n", b"X = a\rb\nY=1\nall: ; @:\n"],
        ids=["crlf", "lone-cr"],
    )
    def test_backup_is_a_byte_for_byte_copy(self, tmp_path, data):
        path = tmp_path / "Makefile"
        path.write_bytes(data)
        result = _runner().invoke(
            app,
            ["format", "--config", str(_empty_config(tmp_path)), "--backup"]
            + [str(path)],
        )
        assert result.exit_code == 0
        backups = list(tmp_path.glob("Makefile.*.bak"))
        assert len(backups) == 1
        assert backups[0].read_bytes() == data

    @pytest.mark.skipif(os.name == "nt", reason="stdin reads CRLF as LF on Windows")
    def test_stdin_keeps_form_feed_and_lone_carriage_return(self, tmp_path):
        data = b"# note\x0cmore\nX = a\rb\n$(info [$(X)])\nall: ; @:\n"
        tree = Path(mbake.__file__).resolve().parent.parent
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            path for path in (str(tree), env.get("PYTHONPATH", "")) if path
        )
        proc = subprocess.run(
            [sys.executable, "-m", "mbake", "format", "--config", os.devnull]
            + ["--stdin"],
            input=data,
            cwd=tmp_path,
            env=env,
            capture_output=True,
            timeout=120,
        )
        assert proc.returncode == 0, proc.stderr
        # A notice about an old 'bake' module may come first
        assert proc.stdout.endswith(data)

    def test_diff_is_silent_for_form_feed_in_a_comment(self, tmp_path):
        path = tmp_path / "Makefile"
        path.write_bytes(b"# note\x0cmore\nreal: ; @echo real\n")
        result = _runner().invoke(
            app,
            ["format", "--config", str(_empty_config(tmp_path)), "--diff"]
            + [str(path)],
        )
        assert result.exit_code == 0
        assert "Diff for" not in result.stdout
        assert "- # note" not in result.stdout

    def test_diff_shows_only_the_changed_line(self, tmp_path):
        path = tmp_path / "Makefile"
        path.write_bytes(b"# note\x0cmore\nY=1\nreal: ; @echo real\n")
        result = _runner().invoke(
            app,
            ["format", "--config", str(_empty_config(tmp_path)), "--diff"]
            + [str(path)],
        )
        assert result.exit_code == 0
        assert "- Y=1" in result.stdout
        assert "+ Y = 1" in result.stdout
        assert "# note" not in result.stdout


class TestReadStdinText:
    """--stdin reads bytes, so a carriage return inside a line stays."""

    DATA = b"X = a\rb\r\n# c\x0cd\nY = \xc3\xa9\n"

    @staticmethod
    def _stdin(monkeypatch, stream, os_name):
        monkeypatch.setattr(sys, "stdin", stream)
        monkeypatch.setattr(cli, "os", SimpleNamespace(name=os_name))

    def test_posix_keeps_every_character(self, monkeypatch):
        # A universal-newline stream, as on Windows, would read '\r' as '\n'
        stream = io.TextIOWrapper(io.BytesIO(self.DATA), encoding="utf-8")
        self._stdin(monkeypatch, stream, "posix")
        assert cli._read_stdin_text() == self.DATA.decode("utf-8")

    def test_windows_keeps_carriage_return_inside_a_line(self, monkeypatch):
        stream = io.TextIOWrapper(io.BytesIO(self.DATA), encoding="utf-8")
        self._stdin(monkeypatch, stream, "nt")
        assert cli._read_stdin_text() == "X = a\rb\n# c\x0cd\nY = \xe9\n"

    def test_decodes_with_the_encoding_of_stdin(self, monkeypatch):
        stream = io.TextIOWrapper(io.BytesIO(b"X = caf\xe9\r\n"), encoding="latin-1")
        self._stdin(monkeypatch, stream, "posix")
        assert cli._read_stdin_text() == "X = caf\xe9\r\n"

    def test_stream_without_bytes(self, monkeypatch):
        self._stdin(monkeypatch, io.StringIO("X = a\rb\n"), "posix")
        assert cli._read_stdin_text() == "X = a\rb\n"
