"""Tests for finding .bake.toml in the current directory and its parents.

Run from the project root:
    pytest tests/test_config_discovery.py -v
"""

import os
import re
import sys
import tempfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

import mbake.config
from mbake.cli import app
from mbake.config import Config, FormatterConfig

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

INVALID_TOML = "not valid toml !!!"
WARNING_PREFIX = "mbake: warning: ignoring invalid configuration file "

# ---------------------------------------------------------------------------
# Helpers (tests/ is not a package, so these are copied from test_config.py)
# ---------------------------------------------------------------------------


def _write_toml(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def _fake_home(tmp: str):
    """Patch Path.home() to point at a temp directory."""
    return patch("pathlib.Path.home", return_value=Path(tmp))


def _fake_cwd(tmp: str):
    """Patch Path.cwd() to point at a temp directory."""
    return patch("pathlib.Path.cwd", return_value=Path(tmp))


def _no_project_config():
    """Make the project search find nothing, whatever lies above the temp dir."""
    # create=True lets the tests that pin main's behaviour run on main too
    return patch("mbake.config.project_config_candidates", return_value=[], create=True)


def _search_within(root: Path):
    """Ignore any .bake.toml above ``root``, such as a real ~/.bake.toml.

    For tests that expect nothing above the temp dir to be found: on Windows
    the temp dir lies inside the home directory, and elsewhere a stray
    /tmp/.bake.toml would be found. getattr() and create=True keep these tests
    runnable on main, which has no project search to patch.
    """
    real_candidates = getattr(mbake.config, "project_config_candidates", None)

    def candidates(start):
        return [path for path in real_candidates(start) if root in path.parents]

    return patch("mbake.config.project_config_candidates", candidates, create=True)


def _runner() -> CliRunner:
    """Return a CliRunner that keeps stdout and stderr apart."""
    try:
        return CliRunner(mix_stderr=False)  # click < 8.2
    except TypeError:
        return CliRunner()  # click >= 8.2 always captures stderr separately


@pytest.fixture(autouse=True)
def _no_xdg_config_home(monkeypatch):
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)


@pytest.fixture
def home(tmp_path):
    """An empty fake home directory."""
    path = tmp_path / "home"
    path.mkdir()
    with _fake_home(str(path)):
        yield path


# ---------------------------------------------------------------------------
# project_config_candidates()
# ---------------------------------------------------------------------------


class TestProjectConfigCandidates:
    """The list of places to look is finite and ends at the root on every OS."""

    @pytest.mark.parametrize(
        ("start", "directories"),
        [
            ("C:/Users/x/proj", ["C:/Users/x/proj", "C:/Users/x", "C:/Users", "C:/"]),
            ("C:/", ["C:/"]),
            ("//server/share/dir", ["//server/share/dir", "//server/share/"]),
            ("//?/C:/a/b", ["//?/C:/a/b", "//?/C:/a", "//?/C:/"]),
            (
                "//?/UNC/server/share/dir",
                ["//?/UNC/server/share/dir", "//?/UNC/server/share/"],
            ),
            (r"C:\Users\x", ["C:/Users/x", "C:/Users", "C:/"]),
            (r"\\?\C:\a", ["//?/C:/a", "//?/C:/"]),
        ],
    )
    def test_windows_search_ends_at_drive_or_share_root(self, start, directories):
        # A loop that stops when the parent equals Path(root) never ends here:
        # the root of C:\x is "\", but its last parent is "C:\"
        start_path = PureWindowsPath(start)
        candidates = mbake.config.project_config_candidates(start_path)
        assert candidates == [PureWindowsPath(d) / ".bake.toml" for d in directories]
        assert candidates[-1] == PureWindowsPath(start_path.anchor) / ".bake.toml"

    def test_posix_search_ends_at_root(self):
        candidates = mbake.config.project_config_candidates(
            PurePosixPath("/home/u/proj")
        )
        assert candidates == [
            PurePosixPath(d) / ".bake.toml"
            for d in ("/home/u/proj", "/home/u", "/home", "/")
        ]


# ---------------------------------------------------------------------------
# Config.find_project_config_path() and Config.find_config_path()
# ---------------------------------------------------------------------------


class TestFindProjectConfigPath:
    """Config.find_project_config_path() returns the nearest file, unloaded."""

    def test_returns_nearest_file(self, tmp_path):
        _write_toml(tmp_path / ".bake.toml", "[formatter]\n")
        _write_toml(tmp_path / "a" / ".bake.toml", "[formatter]\n")
        # The start directory itself does not have to exist
        found = Config.find_project_config_path(tmp_path / "a" / "b")
        assert found == tmp_path / "a" / ".bake.toml"

    def test_relative_start_is_taken_from_cwd(self, tmp_path):
        _write_toml(tmp_path / ".bake.toml", "[formatter]\n")
        with _fake_cwd(str(tmp_path / "a")):
            found = Config.find_project_config_path(Path("b"))
        assert found == tmp_path / ".bake.toml"

    def test_dotdot_in_start_is_resolved(self, tmp_path):
        # The literal parents of p/q/../x include p/q, which is not a parent
        # of p/x, so p/q/.bake.toml must not be found
        _write_toml(tmp_path / ".bake.toml", "[formatter]\n")
        _write_toml(tmp_path / "p" / "q" / ".bake.toml", "[formatter]\n")
        found = Config.find_project_config_path(tmp_path / "p" / "q" / ".." / "x")
        assert found == tmp_path / ".bake.toml"

    def test_relative_dotdot_start_is_resolved(self, tmp_path):
        _write_toml(tmp_path / ".bake.toml", "[formatter]\n")
        _write_toml(tmp_path / "p" / "q" / ".bake.toml", "[formatter]\n")
        with _fake_cwd(str(tmp_path / "p" / "q")):
            found = Config.find_project_config_path(Path("..") / "x")
        assert found == tmp_path / ".bake.toml"


class TestFindConfigPath:
    """Config.find_config_path() names the file that load_or_default() uses."""

    def test_skips_invalid_files_like_load_or_default(self, tmp_path, home):
        project = tmp_path / "project"
        _write_toml(project / ".bake.toml", INVALID_TOML)
        _write_toml(tmp_path / ".bake.toml", "[formatter]\ntab_width = 5\n")
        skipped = []
        with _fake_cwd(str(project)):
            path = Config.find_config_path(
                on_invalid=lambda path, error: skipped.append(path)
            )
            config = Config.load_or_default()
        assert path == tmp_path / ".bake.toml"
        assert config.formatter.tab_width == 5
        assert skipped == [project / ".bake.toml"]

    def test_falls_back_to_user_location(self, home):
        with _no_project_config():
            assert Config.find_config_path() == home / ".config" / "bake.toml"

    def test_reports_only_files_passed_over(self, tmp_path, home):
        project = tmp_path / "project"
        _write_toml(project / ".bake.toml", INVALID_TOML)
        (home / ".bake.toml").write_text(INVALID_TOML)
        skipped = []
        with _fake_cwd(str(project)), _search_within(tmp_path):
            path = Config.find_config_path(
                on_invalid=lambda path, error: skipped.append(path)
            )
        # Nothing loads, so the user config is returned and is not reported
        assert path == home / ".bake.toml"
        assert skipped == [project / ".bake.toml"]


# ---------------------------------------------------------------------------
# Config.load_or_default()
# ---------------------------------------------------------------------------


class TestLoadOrDefault:
    """Config.load_or_default() searches the current directory and its parents."""

    # Contributed by @lazolv in #104.
    def test_ancestor_directories_are_searched(self):
        """All ancestor directories of CWD are searched for a .bake.toml, not just the CWD.
        Moreover, the deepest (the closest to CWD) .bake.toml is preferred."""
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            tempfile.TemporaryDirectory() as fake_home,
        ):
            cwd = os.path.join(tmpdir, "anc1/anc2/wd/")
            _write_toml(
                Path(cwd).parent.parent / ".bake.toml", "[formatter]\ntab_width = 7\n"
            )
            _write_toml(
                Path(cwd).parent.parent.parent / ".bake.toml",
                "[formatter]\ntab_width = 999\n",
            )
            _write_toml(Path(fake_home) / ".bake.toml", "[formatter]\ntab_width = 2\n")
            with _fake_home(fake_home), _fake_cwd(cwd):
                result = Config.load_or_default()
        assert result.formatter.tab_width == 7

    def test_invalid_config_is_reported_and_next_one_used(self, tmp_path, home):
        project = tmp_path / "project"
        _write_toml(project / ".bake.toml", INVALID_TOML)
        _write_toml(tmp_path / ".bake.toml", "[formatter]\ntab_width = 5\n")
        calls = []
        with _fake_cwd(str(project)):
            result = Config.load_or_default(
                on_invalid=lambda path, error: calls.append((path, error))
            )
        assert result.formatter.tab_width == 5
        assert len(calls) == 1
        path, error = calls[0]
        assert path == project / ".bake.toml"
        assert isinstance(error, ValueError)
        assert type(error.__cause__) is tomllib.TOMLDecodeError

    def test_library_stays_silent_without_callback(self, tmp_path, home, capsys):
        project = tmp_path / "project"
        _write_toml(project / ".bake.toml", INVALID_TOML)
        with _fake_cwd(str(project)), _search_within(tmp_path):
            result = Config.load_or_default()
        assert isinstance(result.formatter, FormatterConfig)
        assert capsys.readouterr() == ("", "")

    def test_directory_named_bake_toml_is_skipped(self, tmp_path, home):
        project = tmp_path / "project"
        (project / ".bake.toml").mkdir(parents=True)
        _write_toml(tmp_path / ".bake.toml", "[formatter]\ntab_width = 6\n")
        calls = []
        with _fake_cwd(str(project)):
            result = Config.load_or_default(
                on_invalid=lambda path, error: calls.append(path)
            )
        assert result.formatter.tab_width == 6
        assert calls == []

    def test_unavailable_cwd_skips_project_search(self, home):
        _write_toml(home / ".bake.toml", "[formatter]\ntab_width = 3\n")
        deleted = FileNotFoundError(2, "No such file or directory")
        with patch("pathlib.Path.cwd", side_effect=deleted):
            assert Config.find_project_config_path() is None
            result = Config.load_or_default()
        assert result.formatter.tab_width == 3

    def test_unreadable_location_is_skipped(self, tmp_path, home):
        project = tmp_path / "a" / "b"
        blocked = project / ".bake.toml"
        _write_toml(tmp_path / "a" / ".bake.toml", "[formatter]\ntab_width = 4\n")
        real_exists = Path.exists

        def exists(path, *args, **kwargs):
            # Python < 3.14 raises instead of returning False here
            if path == blocked:
                raise PermissionError(13, "Permission denied", str(path))
            return real_exists(path, *args, **kwargs)

        with _fake_cwd(str(project)), patch.object(Path, "exists", exists):
            result = Config.load_or_default()
        assert result.formatter.tab_width == 4

    def test_user_config_is_tried_once_when_cwd_is_inside_home(self, tmp_path, home):
        (home / ".bake.toml").write_text(INVALID_TOML)
        calls = []
        with _fake_cwd(str(home / "src" / "project")), _search_within(tmp_path):
            result = Config.load_or_default(
                on_invalid=lambda path, error: calls.append(path)
            )
        assert isinstance(result.formatter, FormatterConfig)
        assert calls == [home / ".bake.toml"]

    def test_explicit_path_skips_discovery(self, tmp_path, home):
        _write_toml(tmp_path / ".bake.toml", "[formatter]\ntab_width = 7\n")
        custom = tmp_path / "custom.toml"
        _write_toml(custom, "[formatter]\ntab_width = 9\n")
        with _fake_cwd(str(tmp_path)):
            result = Config.load_or_default(custom, explicit=True)
        assert result.formatter.tab_width == 9

    def test_search_stops_at_the_first_usable_file(self, tmp_path):
        project = tmp_path / "a" / "b"
        _write_toml(project / ".bake.toml", "[formatter]\ntab_width = 3\n")
        probed = []
        real_exists = Path.exists

        def exists(path, *args, **kwargs):
            probed.append(path)
            return real_exists(path, *args, **kwargs)

        with (
            _fake_cwd(str(project)),
            patch.object(Path, "exists", exists),
            patch.object(
                Config,
                "determine_config_path",
                side_effect=AssertionError("user config looked up"),
            ),
        ):
            result = Config.load_or_default()
        assert result.formatter.tab_width == 3
        # Config.load checks the chosen file again; nothing else is probed
        assert set(probed) == {project / ".bake.toml"}


# ---------------------------------------------------------------------------
# mbake config
# ---------------------------------------------------------------------------


class TestConfigCommand:
    """'mbake config' and 'mbake config --path' use the same lookup as format."""

    def test_path_shows_cwd_config(self, tmp_path, home):
        _write_toml(tmp_path / ".bake.toml", "[formatter]\ntab_width = 7\n")
        with _fake_cwd(str(tmp_path)):
            result = _runner().invoke(app, ["config", "--path"])
        assert result.exit_code == 0
        assert result.stdout == f"{tmp_path / '.bake.toml'}\n"

    def test_shows_cwd_config(self, tmp_path, home):
        _write_toml(tmp_path / ".bake.toml", "[formatter]\ntab_width = 7\n")
        with _fake_cwd(str(tmp_path)):
            result = _runner().invoke(app, ["config"])
        assert result.exit_code == 0, result.stdout
        assert "Configuration from" in result.stdout
        assert re.search(r"tab_width\s+7\b", result.stdout)

    def test_path_shows_ancestor_config(self, tmp_path, home):
        _write_toml(tmp_path / ".bake.toml", "[formatter]\n")
        with _fake_cwd(str(tmp_path / "a" / "b")):
            result = _runner().invoke(app, ["config", "--path"])
        assert result.exit_code == 0
        assert result.stdout == f"{tmp_path / '.bake.toml'}\n"

    def test_path_without_project_config_prints_user_location(self, home):
        with _no_project_config():
            result = _runner().invoke(app, ["config", "--path"])
        assert result.exit_code == 0
        assert result.stdout == f"{home / '.config' / 'bake.toml'}\n"

    def test_path_is_printed_verbatim(self, tmp_path):
        # Long paths must not be wrapped, and [bracketed] parts are not markup
        path = tmp_path / ("x" * 90) / "[proj]" / "bake.toml"
        result = _runner().invoke(app, ["config", "--path", "--config", str(path)])
        assert result.exit_code == 0
        assert result.stdout == f"{path}\n"

    @pytest.mark.parametrize(
        "parts",
        [
            ("[wip]",),
            pytest.param(
                ("[", "bold]"),
                marks=pytest.mark.skipif(
                    os.name == "nt", reason="'[/bold]' needs '/' as the separator"
                ),
            ),
        ],
    )
    def test_bracketed_path_is_not_read_as_markup(self, tmp_path, parts):
        # The config file can now be in any parent directory. Rich markup used
        # to drop [wip] from the path, and [/bold] crashed the command.
        config_file = tmp_path.joinpath(*parts, ".bake.toml")
        missing = config_file.with_name("missing.toml")
        _write_toml(config_file, "[formatter]\ntab_width = 7\n")
        shown = _runner().invoke(app, ["config", "--config", str(config_file)])
        absent = _runner().invoke(app, ["config", "--config", str(missing)])
        # Rich may wrap a long path, so line breaks are ignored
        assert shown.exit_code == 0, shown.stdout
        assert f"Configuration from {config_file}" in shown.stdout.replace("\n", "")
        assert absent.exit_code == 1
        assert f"not found at {missing}" in absent.stdout.replace("\n", "")

    def test_invalid_nearest_config_is_skipped_with_warning(self, tmp_path, home):
        project = tmp_path / "project"
        _write_toml(project / ".bake.toml", INVALID_TOML)
        _write_toml(tmp_path / ".bake.toml", "[formatter]\ntab_width = 5\n")
        with _fake_cwd(str(project)):
            path_result = _runner().invoke(app, ["config", "--path"])
            show_result = _runner().invoke(app, ["config"])
        warning = f"{WARNING_PREFIX}'{project / '.bake.toml'}': "
        assert path_result.exit_code == 0
        assert path_result.stdout == f"{tmp_path / '.bake.toml'}\n"
        assert path_result.stderr.startswith(warning)
        assert path_result.stderr.count("\n") == 1
        assert show_result.exit_code == 0, show_result.stdout
        assert re.search(r"tab_width\s+5\b", show_result.stdout)
        assert show_result.stderr.startswith(warning)

    def test_invalid_user_config_is_still_an_error(self, home):
        (home / ".bake.toml").write_text(INVALID_TOML)
        with _no_project_config():
            result = _runner().invoke(app, ["config"])
        assert result.exit_code == 1
        assert "Failed to load config" in result.stdout
        # The error is about the file shown, so it is not also a warning
        assert result.stderr == ""


# ---------------------------------------------------------------------------
# Warnings for invalid discovered config files
# ---------------------------------------------------------------------------


class TestInvalidConfigWarning:
    """A discovered config file that fails to load is skipped with a warning."""

    def test_format_stdin_warns_on_stderr_only(self, tmp_path, home):
        project = tmp_path / "project"
        _write_toml(project / ".bake.toml", INVALID_TOML)
        _write_toml(
            tmp_path / ".bake.toml", "[formatter]\nspace_around_assignment = false\n"
        )
        source = "CC=gcc\nall:\n\t@echo hi\n"
        with _fake_cwd(str(project)):
            result = _runner().invoke(app, ["format", "--stdin"], input=source)
        assert result.exit_code == 0, result.stdout
        # Formatted with the next config file, which keeps CC=gcc as is
        assert result.stdout == source
        assert result.stderr.startswith(f"{WARNING_PREFIX}'{project / '.bake.toml'}': ")
        assert result.stderr.endswith("\n")
        assert result.stderr.count("\n") == 1
        # Not in FILE:LINE: form, so editors do not report it as a diagnostic
        assert not re.match(r"[^:\n]+:[0-9]+: ", result.stderr)

    def test_validate_warns_on_stderr_only(self, tmp_path, home):
        project = tmp_path / "project"
        _write_toml(project / ".bake.toml", INVALID_TOML)
        with (
            _fake_cwd(str(project)),
            _search_within(tmp_path),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value.returncode = 0
            mock_run.return_value.stderr = ""
            result = _runner().invoke(
                app, ["validate", "--stdin"], input="all:\n\t@echo hi\n"
            )
        assert result.exit_code == 0, result.stdout
        assert result.stdout == ""
        assert result.stderr.startswith(f"{WARNING_PREFIX}'{project / '.bake.toml'}': ")
        assert result.stderr.count("\n") == 1

    def test_two_invalid_files_give_two_warnings(self, tmp_path, home):
        inner = tmp_path / "a" / "b"
        _write_toml(inner / ".bake.toml", INVALID_TOML)
        _write_toml(tmp_path / "a" / ".bake.toml", "[formatter\n")
        _write_toml(
            tmp_path / ".bake.toml", "[formatter]\nspace_around_assignment = false\n"
        )
        with _fake_cwd(str(inner)):
            result = _runner().invoke(app, ["format", "--stdin"], input="CC=gcc\n")
        assert result.exit_code == 0, result.stdout
        assert result.stdout == "CC=gcc\n"
        lines = result.stderr.splitlines()
        assert len(lines) == 2
        assert lines[0].startswith(f"{WARNING_PREFIX}'{inner / '.bake.toml'}': ")
        assert lines[1].startswith(
            f"{WARNING_PREFIX}'{tmp_path / 'a' / '.bake.toml'}': "
        )

    @pytest.mark.parametrize(
        ("args", "exit_code", "message"),
        [
            (["format", "--stdin"], 2, "Fatal error"),
            (["validate", "--stdin"], 2, "Fatal error"),
            (["config"], 1, "Failed to load config"),
        ],
    )
    def test_explicit_invalid_config_still_fails(
        self, tmp_path, args, exit_code, message
    ):
        bad = tmp_path / "bad.toml"
        bad.write_text(INVALID_TOML)
        result = _runner().invoke(app, [*args, "--config", str(bad)], input="CC=gcc\n")
        assert result.exit_code == exit_code
        assert message in result.stdout
        assert "warning" not in result.stderr


# ---------------------------------------------------------------------------
# Deleted working directory
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    os.name == "nt", reason="Windows cannot remove the working directory"
)
def test_deleted_cwd_uses_user_config(tmp_path, home, monkeypatch):
    _write_toml(home / ".bake.toml", "[formatter]\nspace_around_assignment = false\n")
    gone = tmp_path / "gone"
    gone.mkdir()
    monkeypatch.chdir(gone)
    gone.rmdir()
    try:
        result = _runner().invoke(app, ["format", "--stdin"], input="CC=gcc\n")
    finally:
        os.chdir(tmp_path)
    assert result.exit_code == 0, result.stdout
    assert result.stdout == "CC=gcc\n"


@pytest.mark.skipif(os.name == "nt", reason="POSIX file system features")
class TestSpecialPaths:
    """Paths that only POSIX file systems can produce."""

    def test_dev_null_link_masks_the_user_config(self, tmp_path, home):
        """A .bake.toml linked to /dev/null is an empty config, as on main."""
        _write_toml(home / ".bake.toml", "[formatter]\ntab_width = 3\n")
        project = tmp_path / "project"
        project.mkdir()
        (project / ".bake.toml").symlink_to(os.devnull)
        calls = []
        with _fake_cwd(str(project)), _search_within(tmp_path):
            result = Config.load_or_default(
                on_invalid=lambda path, error: calls.append(path)
            )
        assert result.formatter.tab_width == FormatterConfig().tab_width
        assert calls == []

    def test_user_config_reached_by_another_name_is_tried_once(self, tmp_path, home):
        """The user config is skipped when the walk already tried that file."""
        walked = tmp_path / "work" / ".bake.toml"
        _write_toml(walked, INVALID_TOML)
        os.link(walked, home / ".bake.toml")
        calls = []
        with _fake_cwd(str(tmp_path / "work" / "src")), _search_within(tmp_path):
            Config.load_or_default(on_invalid=lambda path, error: calls.append(path))
        assert calls == [walked]

    def test_warning_stays_on_one_line(self, tmp_path, home):
        """Control characters in the path are escaped in the warning."""
        project = tmp_path / "odd\nname"
        _write_toml(project / ".bake.toml", INVALID_TOML)
        with _fake_cwd(str(project)), _search_within(tmp_path):
            result = _runner().invoke(app, ["format", "--stdin"], input="CC=gcc\n")
        assert result.exit_code == 0
        assert result.stderr.count("\n") == 1
        assert "odd\\nname" in result.stderr
