"""Tests for .PHONY declarations whose targets have no rule the rule can see.

With auto_insert_phony_declarations, PhonyRule groups or ungroups the
existing .PHONY declarations. A declaration whose targets' rules are hidden
by '# bake-format off', or are not in the file at all (a fragment that
another makefile includes), was dropped: grouping found no place before a
rule or variable and lost the line, and ungrouping only re-declared targets
before a visible rule. Without the declaration make treats the targets as
files (GNU make manual 4.6, lines 2053-2056): 'make install' then fails with
"No rule to make target", and a rule whose target exists as a file no longer
runs. The declaration now stays.
"""

import os
import re
import shutil
import subprocess

import pytest

from mbake.config import Config, FormatterConfig
from mbake.core.formatter import MakefileFormatter

# make runs with a minimal environment so that no inherited variable (such as
# MAKEFLAGS) changes what it reads.
_MAKE_ENV = {"PATH": os.defpath, "LC_ALL": "C"}

CONFIGS = {
    "auto_group_after": {
        "auto_insert_phony_declarations": True,
        "group_phony_declarations": True,
        "phony_at_top": True,
    },
    "auto_group_top": {
        "auto_insert_phony_declarations": True,
        "group_phony_declarations": True,
        "phony_at_top": False,
    },
    "auto_ungroup": {
        "auto_insert_phony_declarations": True,
        "group_phony_declarations": False,
    },
}

# Each text is already formatted: the declaration must survive every config.
DECLARATIONS_WITHOUT_VISIBLE_RULES = {
    "rules_hidden_in_region": (
        "# bake-format off\nall:\n\t@echo building all\nclean:\n\t@echo cleaning\n"
        "# bake-format on\n.PHONY: all clean\n"
    ),
    "declaration_after_region_no_rules": (
        "# c\n# bake-format off\nX = 1\n# bake-format on\n.PHONY: install\n"
    ),
    "fragment_after_region": (
        "# common.mk - shared declarations\n# bake-format off\nPREFIX   =   /usr/local\n"
        "# bake-format on\n.PHONY: install uninstall\n"
    ),
    "fragment_without_region": (
        "# common.mk - shared declarations\nPREFIX = /usr/local\n\n.PHONY: install uninstall\n"
    ),
}


# With phony_at_top off (auto_group_top) the kept declaration moves to the
# top of the file, as every grouped declaration does; elsewhere the text is
# already formatted and comes back unchanged.
MOVED_TO_TOP = {
    "rules_hidden_in_region": (
        ".PHONY: all clean\n\n# bake-format off\nall:\n\t@echo building all\nclean:\n"
        "\t@echo cleaning\n# bake-format on\n"
    ),
    "declaration_after_region_no_rules": (
        ".PHONY: install\n\n# c\n# bake-format off\nX = 1\n# bake-format on\n"
    ),
    "fragment_after_region": (
        ".PHONY: install uninstall\n\n# common.mk - shared declarations\n"
        "# bake-format off\nPREFIX   =   /usr/local\n# bake-format on\n"
    ),
    "fragment_without_region": (
        ".PHONY: install uninstall\n\n# common.mk - shared declarations\n"
        "PREFIX = /usr/local\n"
    ),
}


def _expected(text_name, config_name):
    if config_name == "auto_group_top":
        return MOVED_TO_TOP[text_name]
    return DECLARATIONS_WITHOUT_VISIBLE_RULES[text_name]


def _formatter(name):
    return MakefileFormatter(Config(formatter=FormatterConfig(**CONFIGS[name])))


def _cases():
    return [
        (text_name, config_name)
        for text_name in sorted(DECLARATIONS_WITHOUT_VISIBLE_RULES)
        for config_name in sorted(CONFIGS)
    ]


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


def _phony_targets(gnu_make, tmp_path, name, text):
    """Return the targets make lists for .PHONY in its database for text.

    The goal lives in a second makefile, so nothing is appended after the
    text's last line.
    """
    make, true = gnu_make
    (tmp_path / name).write_text(text, encoding="utf-8")
    (tmp_path / "goal.mk").write_text("__g: ;\n", encoding="utf-8")
    proc = subprocess.run(
        [
            make,
            "-r",
            "-R",
            "-p",
            "-q",
            "-f",
            name,
            "-f",
            "goal.mk",
            f"SHELL={true}",
            "__g",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        env=_MAKE_ENV,
    )
    for line in proc.stdout.splitlines():
        match = re.match(r"^\.PHONY:\s*(.*)$", line)
        if match:
            return sorted(match.group(1).split())
    return []


class TestDeclarationsStay:
    """The .PHONY line of targets without a visible rule is kept."""

    @pytest.mark.parametrize(("text_name", "config_name"), _cases())
    def test_formatted_output_keeps_the_declaration(self, text_name, config_name):
        text = DECLARATIONS_WITHOUT_VISIBLE_RULES[text_name]
        expected = _expected(text_name, config_name)
        assert _formatter(config_name).format(text).content == expected

    @pytest.mark.parametrize(("text_name", "config_name"), _cases())
    def test_second_run_changes_nothing(self, text_name, config_name):
        text = DECLARATIONS_WITHOUT_VISIBLE_RULES[text_name]
        first = _formatter(config_name).format(text).content
        assert _formatter(config_name).format(first).content == first

    @pytest.mark.parametrize(("text_name", "config_name"), _cases())
    def test_check_mode_agrees(self, text_name, config_name, tmp_path):
        """A file that format leaves alone passes the check; one it moves
        the declaration in is reported, and passes once formatted."""
        text = DECLARATIONS_WITHOUT_VISIBLE_RULES[text_name]
        path = tmp_path / "Makefile"
        path.write_text(text, encoding="utf-8")
        changed, errors, _ = _formatter(config_name).format_file(path, check_only=True)
        assert errors == []
        if _expected(text_name, config_name) == text:
            assert not changed
        # Where the declaration moves to the top, check mode does not report
        # it: PhonyRule never edits lines in check mode (the file-mode --check
        # policy of this release), so only the formatted file is checked.
        _formatter(config_name).format_file(path)
        assert path.read_text(encoding="utf-8") == _expected(text_name, config_name)
        changed, errors, _ = _formatter(config_name).format_file(path, check_only=True)
        assert (changed, errors) == (False, [])

    @pytest.mark.parametrize(("text_name", "config_name"), _cases())
    def test_make_keeps_the_phony_targets(
        self, gnu_make, tmp_path, text_name, config_name
    ):
        """make's .PHONY set is the same for the input and the output."""
        text = DECLARATIONS_WITHOUT_VISIBLE_RULES[text_name]
        expected = _phony_targets(gnu_make, tmp_path, "input.mk", text)
        assert expected, "the input declares phony targets"
        output = _formatter(config_name).format(text).content
        assert _phony_targets(gnu_make, tmp_path, "output.mk", output) == expected


class TestOrganizingStillWorks:
    """Declarations of targets with visible rules are still grouped, moved
    and split as before."""

    def test_grouping_merges_declarations_of_visible_rules(self):
        text = ".PHONY: a\na:\n\t@echo a\n.PHONY: b\nb:\n\t@echo b\n"
        expected = ".PHONY: a b\n\na:\n\t@echo a\nb:\n\t@echo b\n"
        assert _formatter("auto_group_after").format(text).content == expected

    def test_ungrouping_splits_declarations_of_visible_rules(self):
        text = ".PHONY: a b\na:\n\t@echo a\nb:\n\t@echo b\n"
        expected = ".PHONY: a\na:\n\t@echo a\n.PHONY: b\nb:\n\t@echo b\n"
        assert _formatter("auto_ungroup").format(text).content == expected

    def test_ungrouping_keeps_only_the_targets_without_a_rule(self):
        """A mixed declaration keeps the targets that get no individual one."""
        text = ".PHONY: a install\na:\n\t@echo a\n"
        expected = ".PHONY: install\n.PHONY: a\na:\n\t@echo a\n"
        assert _formatter("auto_ungroup").format(text).content == expected
