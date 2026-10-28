"""Colon spacing leaves directives and function-call lines as written.

The rules that space the colon of a rule line used to space every colon they
found, also in 'vpath %.c src:lib', 'include a:b', 'ifeq ($(X),a:b)',
'ifneq (,$(findstring :,$(X)))' and '$(info platform:$(X))'. GNU make reads
those lines as written, so the extra space changed what make did: a search
path, an included file name, a conditional's result or printed text (GNU make
manual 4.5.2, lines 1823-1826; 3.3, lines 846-848; 7.2, lines 5386-5400;
8.13). The expected values of the make-backed tests come from running GNU
make on the input; the probe rule is passed as a second makefile so nothing is
appended after the input's last line.
"""

import os
import shutil
import subprocess

import pytest

from mbake.config import Config, FormatterConfig
from mbake.core.formatter import MakefileFormatter

# make runs with a minimal environment so that no inherited variable changes
# what it reads.
_MAKE_ENV = {"PATH": os.defpath, "LC_ALL": "C"}

PROBE = "__probe:\n\t@echo [$(Y)] [$(X)]\n"


@pytest.fixture(scope="module")
def gnu_make():
    """Return the make path, or skip when GNU make cannot run here."""
    if os.name == "nt":
        pytest.skip("GNU make checks do not run on Windows")
    make = shutil.which("make")
    if make is None or shutil.which("true") is None:
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
    return make


def _format(text, **options):
    config = Config(formatter=FormatterConfig(**options))
    return MakefileFormatter(config).format(text).content


def _make_output(make, tmp_path, text, args):
    """Run make -s on text with the probe in a second makefile; return stdout."""
    (tmp_path / "input.mk").write_text(text, encoding="utf-8")
    (tmp_path / "probe.mk").write_text(PROBE, encoding="utf-8")
    proc = subprocess.run(
        [make, "-r", "-R", "-s", "-f", "input.mk", "-f", "probe.mk", *args],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        env=_MAKE_ENV,
    )
    return proc.returncode, proc.stdout


DIRECTIVE_LINES = [
    "vpath %.c src:lib\n",
    "vpath %.h include:src # c:d\n",
    "include a:b\n",
    "-include conf:d/x.mk\n",
    "sinclude a:b\n",
    "ifeq ($(X),a:b)\nY = 1\nendif\n",
    "ifdef X\nelse ifeq (a:b,$(Z))\nendif\n",
    "ifneq (,$(findstring :,$(X)))\nY = 1\nendif\n",
    "ifneq (,$(filter %.o:%.c,$(X)))\nY = 1\nendif\n",
    "undefine X:Y\n",
    "$(info platform:$(X))\n",
    "${info x:y}\n",
    "$(call setup,a:b)\n",
    "$(eval T:=1)\n",
]


@pytest.mark.parametrize("text", DIRECTIVE_LINES)
@pytest.mark.parametrize("space_before_colon", [False, True])
def test_directive_and_function_lines_stay_as_written(text, space_before_colon):
    """No rule puts a space next to a colon that is not a rule separator."""
    full = "X = a:b\n" + text + "all:\n\t@echo ok\n"
    once = _format(full, space_before_colon=space_before_colon)
    assert once.splitlines()[1 : 1 + text.count("\n")] == text.splitlines()
    assert _format(once, space_before_colon=space_before_colon) == once


@pytest.mark.parametrize(
    ("line", "spaced"),
    [
        ("foo:bar", "foo: bar"),
        ("$(TARGET):$(DEPS)", "$(TARGET): $(DEPS)"),
        ("foo bar:baz", "foo bar: baz"),
        ("%.o:%.c", "%.o: %.c"),
    ],
)
def test_rule_lines_are_still_spaced(line, spaced):
    """Ordinary rule lines keep today's spacing."""
    text = line + "\n\t@echo ok\n"
    assert _format(text) == spaced + "\n\t@echo ok\n"


@pytest.mark.parametrize(
    ("text", "args"),
    [
        ("X = a:b\nifneq (,$(findstring :,$(X)))\nY = 1\nendif\n", ["__probe"]),
        ("X = a:b\nifeq ($(X),a:b)\nY = 1\nendif\n", ["__probe"]),
        ("X = 1\n$(info platform:$(X))\n", ["__probe"]),
        ("X = a.o\nifneq (,$(filter %.o:%.c,$(X)))\nY = 1\nendif\n", ["__probe"]),
    ],
)
def test_make_reads_input_and_output_the_same(gnu_make, tmp_path, text, args):
    """make prints the same for the input and for the formatted output."""
    expected = _make_output(gnu_make, tmp_path, text, args)
    assert expected[0] == 0
    assert _make_output(gnu_make, tmp_path, _format(text), args) == expected


def test_indented_conditional_keeps_its_colon():
    """A conditional written with leading blanks goes to column 0 as before,
    with its text untouched."""
    text = (
        "X = a:b\n  ifneq (,$(findstring :,$(X)))\n  Y = 1\n  endif\nall:\n\t@echo ok\n"
    )
    once = _format(text)
    assert "ifneq (,$(findstring :,$(X)))" in once.splitlines()
    assert _format(once) == once


def test_included_file_name_is_kept(gnu_make, tmp_path):
    """'include a:b' names one file (manual 3.3, lines 846-848): make reads
    it for the input and for the output; 'include a: b' would name two."""
    (tmp_path / "a:b").write_text("Y = 1\n", encoding="utf-8")
    text = "include a:b\nall:\n\t@echo ok\n"
    output = _format(text)
    assert output == text
    expected = _make_output(gnu_make, tmp_path, text, ["__probe"])
    assert expected == (0, "[1] []\n")
    assert _make_output(gnu_make, tmp_path, output, ["__probe"]) == expected
