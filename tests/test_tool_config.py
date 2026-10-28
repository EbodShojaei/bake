"""The tool settings in pyproject.toml name the installed package, mbake.

The package directory was renamed from bake/ to mbake/ in v1.3.0, but the ruff
isort and coverage sections kept the old name. 'coverage run -m pytest' and a
bare 'pytest --cov' then measured nothing; only an explicit 'pytest --cov=mbake',
as CI passes, produced a report.
"""

import sys
from pathlib import Path

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

REPO = Path(__file__).resolve().parents[1]
PYPROJECT = REPO / "pyproject.toml"


@pytest.fixture(scope="module")
def tool_settings():
    """Return the [tool] table of pyproject.toml, or skip without the file."""
    if not PYPROJECT.is_file():
        pytest.skip("pyproject.toml is not part of this checkout")
    with PYPROJECT.open("rb") as handle:
        return tomllib.load(handle)["tool"]


def test_the_package_directory_is_mbake(tool_settings):
    """The settings below must name the package that exists on disk."""
    assert (REPO / "mbake" / "__init__.py").is_file()


def test_ruff_isort_knows_mbake_as_first_party(tool_settings):
    """Imports of mbake are grouped as first-party wherever ruff runs from."""
    assert tool_settings["ruff"]["lint"]["isort"]["known-first-party"] == ["mbake"]


def test_coverage_measures_mbake(tool_settings):
    """'coverage run' without --source measures the mbake package."""
    assert tool_settings["coverage"]["run"]["source"] == ["mbake"]
