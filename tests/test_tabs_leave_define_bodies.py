"""Tests for TabsRule leaving define bodies as written.

The lines of a define body are the value of a variable (GNU make manual 6.8,
lines 4795-4799): the leading spaces of a body line are part of the value,
so turning them into a TAB changes what make reads. The one exception is a
body that holds a rule template, a rule line whose target has '$', '{' or
'%': after $(eval $(call ...)) make reads its recipe lines as recipe lines,
so they keep getting their TAB, as before. The make-backed tests take their
expected value from GNU make itself.
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

# Bodies whose space-led lines are data: every one must come back unchanged.
DATA_BODIES = {
    "space_indented_lines": (
        "define PAD\nx\n    indented\n  less\nendef\n" "$(info [$(PAD)])\nall: ; @:\n"
    ),
    "yaml_like_body": (
        "define CFG\nkey: 1\n  - item\nendef\n$(info [$(CFG)])\nall: ; @:\n"
    ),
    "override_define": (
        "override define MSG\n  hi\nendef\n$(info [$(MSG)])\nall: ; @:\n"
    ),
    "export_define": ("export define MSG\n  hi\nendef\n$(info [$(MSG)])\nall: ; @:\n"),
    "nested_define": (
        "define OUTER\ndefine INNER\n  x\nendef\nendef\n$(info [$(OUTER)])\nall: ; @:\n"
    ),
    "body_after_a_rule": ("all: ; @:\ndefine MSG\n  hi\nendef\n$(info [$(MSG)])\n"),
    "body_in_conditional": (
        "ifdef X\ndefine MSG\n  hi\nendef\nendif\n$(info [$(MSG)])\nall: ; @:\n"
    ),
}

# A body that holds a rule template keeps the repair of its recipe lines.
TEMPLATE_BODY = (
    "define TPL\n$(1):\n    @echo built $(1)\nendef\nall: x\n$(eval $(call TPL,x))\n"
)
TEMPLATE_BODY_REPAIRED = (
    "define TPL\n$(1):\n\t@echo built $(1)\nendef\nall: x\n$(eval $(call TPL,x))\n"
)


def _formatter(**kwargs):
    return MakefileFormatter(Config(formatter=FormatterConfig(**kwargs)))


@pytest.fixture(scope="module", params=["make", "gmake"])
def gnu_make(request):
    """Return (make, true, major version), or skip when that GNU make cannot
    run here. 'gmake' is often a second GNU make, such as 4.x next to macOS's
    3.81."""
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
    match = re.match(r"GNU Make (\d+)\.", version)
    if "GNU Make" not in version or match is None:
        pytest.skip("make is not GNU make")
    return make, true, int(match.group(1))


def _run(gnu_make, tmp_path, name, text, goal="all", env=None):
    """Write text to tmp_path/name and run make on it; return (status, stdout)."""
    make, _, _ = gnu_make
    (tmp_path / name).write_text(text, encoding="utf-8")
    proc = subprocess.run(
        [make, "-r", "-R", "-s", "-f", name, goal],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        env={**_MAKE_ENV, **(env or {})},
    )
    return proc.returncode, proc.stdout


class TestBodiesAreLeftAsWritten:
    @pytest.mark.parametrize("name", sorted(DATA_BODIES))
    def test_output_is_unchanged(self, name):
        text = DATA_BODIES[name]
        assert _formatter().format(text).content == text

    @pytest.mark.parametrize("name", sorted(set(DATA_BODIES) - {"body_in_conditional"}))
    def test_output_is_unchanged_with_nested_indentation(self, name):
        """TabsRule's part with indent_nested_conditionals on. (A body inside
        a conditional is indented by ConditionalRule there; not this rule.)"""
        text = DATA_BODIES[name]
        formatter = _formatter(indent_nested_conditionals=True, tab_width=4)
        assert formatter.format(text).content == text

    @pytest.mark.parametrize("name", sorted(DATA_BODIES))
    def test_make_reads_the_same_value(self, gnu_make, tmp_path, name):
        """make prints the variable's value; input and output must agree."""
        text = DATA_BODIES[name]
        if name in ("export_define", "nested_define") and gnu_make[2] < 4:
            pytest.skip("this make has no export define or nested define")
        env = {"X": "1"} if name == "body_in_conditional" else None
        before = _run(gnu_make, tmp_path, "input.mk", text, env=env)
        assert before[0] == 0, before
        output = _formatter().format(text).content
        assert _run(gnu_make, tmp_path, "output.mk", output, env=env) == before

    def test_body_inside_a_disabled_region_is_untouched(self):
        text = "# bake-format off\ndefine PAD\n    indented\nendef\n# bake-format on\nall:\n\t@echo ok\n"
        assert _formatter().format(text).content == text


class TestTemplatesAndRecipesStillGetTheirTab:
    def test_template_recipe_line_is_repaired(self):
        assert _formatter().format(TEMPLATE_BODY).content == TEMPLATE_BODY_REPAIRED

    def test_template_rule_works_after_repair(self, gnu_make, tmp_path):
        """make can run the rule the repaired template defines (GNU 6388-6427)."""
        output = _formatter().format(TEMPLATE_BODY).content
        status, stdout = _run(gnu_make, tmp_path, "output.mk", output, goal="x")
        assert (status, stdout.strip()) == (0, "built x")

    def test_recipe_outside_a_body_is_still_converted(self):
        text = "all:\n    echo hi\ndefine MSG\n  hi\nendef\n"
        expected = "all:\n\techo hi\ndefine MSG\n  hi\nendef\n"
        assert _formatter().format(text).content == expected
