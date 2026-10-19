"""Tests for .PHONY lines that own command lines, and for a stable target order.

With auto_insert_phony_declarations, PhonyRule groups, moves or splits the
.PHONY lines. A line that starts with the recipe prefix after a '.PHONY:'
line, in its rule context, is a recipe line of .PHONY (GNU make manual 5.1,
lines 2878-2884). Moving the '.PHONY:' line left such a line without its
rule: make then read it as makefile syntax (an assignment it never had), as
a command of another target, or stopped with "recipe commences before first
target" (lines 11292-11297). Such '.PHONY:' lines now stay as they are.

The targets that PhonyRule inserts or reports came in set order, which
changes with Python's hash seed, so two runs could disagree. They now come
in the order of the rules that define them.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import mbake
from mbake.config import Config, FormatterConfig
from mbake.core.formatter import MakefileFormatter

# make runs with a minimal environment so that no inherited variable (such as
# MAKEFLAGS) changes what it reads.
_MAKE_ENV = {"PATH": os.defpath, "LC_ALL": "C"}

GROUP_AFTER = {
    "auto_insert_phony_declarations": True,
    "group_phony_declarations": True,
    "phony_at_top": True,
}
GROUP_TOP = {
    "auto_insert_phony_declarations": True,
    "group_phony_declarations": True,
    "phony_at_top": False,
}
UNGROUP = {
    "auto_insert_phony_declarations": True,
    "group_phony_declarations": False,
}
# With indent_nested_conditionals on, ConditionalRule may change these lines
# before PhonyRule sees them; that is covered by the tests of
# fix/indent-mode-make-semantics, which builds on this branch.
CONFIGS = {
    "group_after": GROUP_AFTER,
    "group_top": GROUP_TOP,
    "ungroup": UNGROUP,
}

# {name: (text, goals, make settings)}: each .PHONY line owns a command line.
OWNED_COMMANDS = {
    "declaration_in_a_conditional": (
        "X = 1\nifeq (a,a)\n.PHONY: t1\n\t$(R)\nendif\nt1: ; @echo t1\n",
        ["t1"],
        [],
    ),
    "assignment_text_in_a_branch": (
        ".PHONY:all t2\n.PHONY:t1\nifdef A\n\tX = 2\nendif\n"
        "all: ; @echo [$(X)]\nt1: ; @:\nt2: ; @:\n",
        ["all", "t1", "t2"],
        ["A=1"],
    ),
    "command_in_a_branch": (
        ".PHONY: all clean\nifeq ($(OS),Windows_NT)\n\t$(MAKE) -C win\nendif\n"
        "all: ; @echo all\nclean: ; @echo clean\n",
        ["all", "clean"],
        ["OS=Windows_NT"],
    ),
    "assignment_text_after_a_rule": (
        "%.x: ; @echo i\nifeq (a,a)\n  X = 2\n$(info i)\n.PHONY: t3\n\tX ?= 1\n"
        "-include nofile.mk\nendif\nt3: t2\nt2: ; @echo [$(X)]\n",
        ["t3"],
        [],
    ),
    "command_after_a_top_level_declaration": (
        "all: ; @echo all\n.PHONY: all\n\t@echo phony\nclean: ; @echo clean\n",
        ["all", "clean"],
        [],
    ),
}


def _format(text, config):
    return MakefileFormatter(Config(formatter=FormatterConfig(**config))).format(text)


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


def _make_reads(gnu_make, tmp_path, text, goals, settings):
    """Return make's exit status, dry-run output and messages for text.

    The messages lose the 'file:line: ' prefix, which other line counts
    change. Nothing is appended after the text's last line.
    """
    make, true = gnu_make
    (tmp_path / "Makefile").write_text(text, encoding="utf-8")
    proc = subprocess.run(
        [make, "-r", "-R", "-n", "-f", "Makefile", f"SHELL={true}", *settings, *goals],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        env=_MAKE_ENV,
    )
    messages = sorted(
        line.split(": ", 2)[-1] for line in proc.stderr.splitlines() if line
    )
    return proc.returncode, proc.stdout, messages


def _cases():
    return [(name, config) for name in sorted(OWNED_COMMANDS) for config in CONFIGS]


class TestDeclarationsThatOwnCommandsStay:
    @pytest.mark.parametrize(("name", "config"), _cases())
    def test_command_lines_keep_their_declaration(self, name, config):
        """Every '.PHONY:' line that owns a command line is in the output,
        directly above that command, as in the input."""
        text = OWNED_COMMANDS[name][0]
        output = _format(text, CONFIGS[config]).content.splitlines()
        lines = text.splitlines()
        for index, line in enumerate(lines):
            if line.startswith("\t") and lines[index - 1].startswith(".PHONY"):
                position = next(
                    i
                    for i, out in enumerate(output)
                    if out.startswith("\t") and out.strip() == line.strip()
                )
                assert output[position - 1] == lines[index - 1]

    @pytest.mark.parametrize(("name", "config"), _cases())
    def test_second_run_changes_nothing(self, name, config):
        once = _format(OWNED_COMMANDS[name][0], CONFIGS[config]).content
        assert _format(once, CONFIGS[config]).content == once

    @pytest.mark.parametrize(("name", "config"), _cases())
    def test_make_reads_the_same(self, gnu_make, tmp_path, name, config):
        text, goals, settings = OWNED_COMMANDS[name]
        output = _format(text, CONFIGS[config]).content
        for current in ([], settings) if settings else ([],):
            before = _make_reads(gnu_make, tmp_path, text, goals, current)
            assert before[0] == 0, before
            assert _make_reads(gnu_make, tmp_path, output, goals, current) == before


class TestOrganizingStillWorks:
    def test_declarations_that_own_nothing_are_grouped(self):
        text = ".PHONY: a\na:\n\t@echo a\n.PHONY: b\nb:\n\t@echo b\n"
        expected = ".PHONY: a b\n\na:\n\t@echo a\nb:\n\t@echo b\n"
        assert _format(text, GROUP_AFTER).content == expected

    def test_missing_declaration_is_inserted(self):
        text = "all: prog\n\t@echo all\nclean:\n\t@echo clean\n"
        assert _format(text, GROUP_TOP).content.startswith(".PHONY: all clean\n")


THREE_RULES = (
    "zeta:\n\t@echo z\nalpha:\n\t@echo a\nmid:\n\t@echo m\n"
    "build:\n\t@echo b\ncheck:\n\t@echo c\n"
)


class TestStableTargetOrder:
    """The order of inserted and reported targets is the order of their rules,
    whatever the hash seed of the process."""

    def test_inserted_targets_follow_the_rules(self):
        first = _format(THREE_RULES, GROUP_TOP).content.splitlines()[0]
        assert first == ".PHONY: zeta alpha mid build check"

    def test_check_message_follows_the_rules(self):
        formatter = MakefileFormatter(Config(formatter=FormatterConfig()))
        _, _, warnings = formatter.format_lines(
            THREE_RULES.splitlines(), True, THREE_RULES
        )
        assert any(
            w.endswith("targets: zeta, alpha, mid, build, check") for w in warnings
        )

    @pytest.mark.skipif(os.name == "nt", reason="subprocess stdin bytes")
    @pytest.mark.parametrize("config", ["group_top", "group_after", "ungroup"])
    def test_output_is_the_same_for_every_hash_seed(self, tmp_path, config):
        settings = "".join(
            f"{key} = {str(value).lower()}\n" for key, value in CONFIGS[config].items()
        )
        (tmp_path / "bake.toml").write_text(
            "[formatter]\n" + settings, encoding="utf-8"
        )
        tree = str(Path(mbake.__file__).resolve().parent.parent)
        outputs = set()
        for seed in ("0", "1", "2", "3", "42"):
            env = {
                **os.environ,
                "PYTHONHASHSEED": seed,
                "PYTHONPATH": os.pathsep.join(
                    [tree, *filter(None, [os.environ.get("PYTHONPATH")])]
                ),
            }
            proc = subprocess.run(
                [sys.executable, "-m", "mbake", "format", "--config", "bake.toml"]
                + ["--stdin"],
                input=THREE_RULES.encode(),
                capture_output=True,
                cwd=tmp_path,
                env=env,
                timeout=60,
            )
            assert proc.returncode == 0, proc.stderr
            outputs.add(proc.stdout)
        assert len(outputs) == 1
