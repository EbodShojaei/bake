"""Tests for configuration loading and XDG path resolution.

Run from the project root:
    pytest tests/test_config.py -v
    pytest  # runs all tests including this file
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from mbake.config import Config, FormatterConfig


# ---------------------------------------------------------------------------
# Helpers
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


# ---------------------------------------------------------------------------
# _xdg_config_path resolution
# ---------------------------------------------------------------------------

class TestXdgConfigPath:
    """Tests for Config._xdg_config_path() resolution order."""

    def setup_method(self):
        os.environ.pop("XDG_CONFIG_HOME", None)

    def teardown_method(self):
        os.environ.pop("XDG_CONFIG_HOME", None)

    def test_home_bake_toml_wins_over_xdg(self):
        """~/.bake.toml existing takes priority even when XDG_CONFIG_HOME is set."""
        with tempfile.TemporaryDirectory() as fake_home, \
             tempfile.TemporaryDirectory() as xdg:
            _write_toml(Path(fake_home) / ".bake.toml", "[formatter]\n")
            os.environ["XDG_CONFIG_HOME"] = xdg
            with _fake_home(fake_home):
                result = Config._xdg_config_path()
            assert result == Path(fake_home) / ".bake.toml"

    def test_home_bake_toml_wins_without_xdg(self):
        """~/.bake.toml existing is returned when XDG_CONFIG_HOME is not set."""
        with tempfile.TemporaryDirectory() as fake_home:
            _write_toml(Path(fake_home) / ".bake.toml", "[formatter]\n")
            with _fake_home(fake_home):
                result = Config._xdg_config_path()
            assert result == Path(fake_home) / ".bake.toml"

    def test_xdg_env_used_when_home_file_absent(self):
        """$XDG_CONFIG_HOME/bake.toml is used when ~/.bake.toml does not exist."""
        with tempfile.TemporaryDirectory() as fake_home, \
             tempfile.TemporaryDirectory() as xdg:
            os.environ["XDG_CONFIG_HOME"] = xdg
            with _fake_home(fake_home):
                result = Config._xdg_config_path()
            assert result == Path(xdg) / "bake.toml"

    def test_default_xdg_base_when_nothing_set(self):
        """Falls back to ~/.config/bake.toml when no XDG var and no ~/.bake.toml."""
        with tempfile.TemporaryDirectory() as fake_home:
            with _fake_home(fake_home):
                result = Config._xdg_config_path()
            assert result == Path(fake_home) / ".config" / "bake.toml"

    def test_empty_xdg_env_is_ignored(self):
        """A blank/whitespace XDG_CONFIG_HOME is treated as unset."""
        with tempfile.TemporaryDirectory() as fake_home:
            os.environ["XDG_CONFIG_HOME"] = "   "
            with _fake_home(fake_home):
                result = Config._xdg_config_path()
            assert result == Path(fake_home) / ".config" / "bake.toml"

    def test_returned_path_may_not_exist(self):
        """_xdg_config_path does not require the file to exist."""
        with tempfile.TemporaryDirectory() as fake_home:
            with _fake_home(fake_home):
                result = Config._xdg_config_path()
            assert isinstance(result, Path)
            assert not result.exists()


# ---------------------------------------------------------------------------
# Config.load()
# ---------------------------------------------------------------------------

class TestLoad:
    """Tests for Config.load()."""

    def test_loads_explicit_path(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "my.toml"
            _write_toml(p, "[formatter]\ntab_width = 4\n")
            result = Config.load(p)
            assert result.formatter.tab_width == 4

    def test_missing_explicit_path_raises_file_not_found(self):
        with pytest.raises(FileNotFoundError) as exc_info:
            Config.load(Path("/nonexistent/path/config.toml"))
        assert "bake.toml" in str(exc_info.value)

    def test_invalid_toml_raises_value_error(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.toml"
            p.write_text("this is not [ valid toml !!!")
            with pytest.raises(ValueError):
                Config.load(p)

    def test_unknown_formatter_keys_are_ignored(self):
        """Keys not in FormatterConfig are silently dropped."""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "extra.toml"
            _write_toml(p, "[formatter]\ntab_width = 3\nunknown_key = true\n")
            result = Config.load(p)
            assert result.formatter.tab_width == 3

    def test_global_debug_and_verbose_flags(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "flags.toml"
            _write_toml(p, "debug = true\nverbose = true\n")
            result = Config.load(p)
            assert result.debug is True
            assert result.verbose is True

    def test_empty_toml_returns_all_defaults(self):
        """A TOML with no [formatter] section gives default FormatterConfig."""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "empty.toml"
            _write_toml(p, "# empty\n")
            result = Config.load(p)
            defaults = FormatterConfig()
            assert result.formatter.tab_width == defaults.tab_width
            assert result.formatter.max_line_length == defaults.max_line_length

    def test_loads_all_formatter_options(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "full.toml"
            _write_toml(p, """\
[formatter]
space_around_assignment = false
space_before_colon = true
space_after_colon = false
normalize_line_continuations = false
max_line_length = 80
auto_insert_phony_declarations = true
group_phony_declarations = true
phony_at_top = true
remove_trailing_whitespace = false
ensure_final_newline = true
normalize_empty_lines = false
max_consecutive_empty_lines = 5
fix_missing_recipe_tabs = false
indent_nested_conditionals = true
tab_width = 8
align_variable_assignments = true
align_across_comments = true
""")
            f = Config.load(p).formatter
            assert f.space_around_assignment is False
            assert f.space_before_colon is True
            assert f.space_after_colon is False
            assert f.normalize_line_continuations is False
            assert f.max_line_length == 80
            assert f.auto_insert_phony_declarations is True
            assert f.group_phony_declarations is True
            assert f.phony_at_top is True
            assert f.remove_trailing_whitespace is False
            assert f.ensure_final_newline is True
            assert f.normalize_empty_lines is False
            assert f.max_consecutive_empty_lines == 5
            assert f.fix_missing_recipe_tabs is False
            assert f.indent_nested_conditionals is True
            assert f.tab_width == 8
            assert f.align_variable_assignments is True
            assert f.align_across_comments is True


# ---------------------------------------------------------------------------
# Config.load_or_default()
# ---------------------------------------------------------------------------

class TestLoadOrDefault:
    """Tests for Config.load_or_default() search-order cascade."""

    def setup_method(self):
        os.environ.pop("XDG_CONFIG_HOME", None)

    def teardown_method(self):
        os.environ.pop("XDG_CONFIG_HOME", None)

    def test_no_files_returns_defaults(self):
        with tempfile.TemporaryDirectory() as fake_home, \
             tempfile.TemporaryDirectory() as cwd:
            with _fake_home(fake_home), _fake_cwd(cwd):
                result = Config.load_or_default()
        assert isinstance(result, Config)
        assert isinstance(result.formatter, FormatterConfig)
        assert result.debug is False

    def test_cwd_config_beats_everything(self):
        """A .bake.toml in the current directory takes top priority."""
        with tempfile.TemporaryDirectory() as cwd, \
             tempfile.TemporaryDirectory() as fake_home:
            _write_toml(Path(cwd) / ".bake.toml", "[formatter]\ntab_width = 7\n")
            _write_toml(Path(fake_home) / ".bake.toml", "[formatter]\ntab_width = 2\n")
            with _fake_home(fake_home), _fake_cwd(cwd):
                result = Config.load_or_default()
        assert result.formatter.tab_width == 7

    def test_home_bake_toml_used_when_no_cwd_config(self):
        """~/.bake.toml is used when there is no cwd config."""
        with tempfile.TemporaryDirectory() as cwd, \
             tempfile.TemporaryDirectory() as fake_home:
            _write_toml(Path(fake_home) / ".bake.toml", "[formatter]\ntab_width = 6\n")
            with _fake_home(fake_home), _fake_cwd(cwd):
                result = Config.load_or_default()
        assert result.formatter.tab_width == 6

    def test_xdg_config_used_when_home_file_absent(self):
        """$XDG_CONFIG_HOME/bake.toml is used when ~/.bake.toml does not exist."""
        with tempfile.TemporaryDirectory() as cwd, \
             tempfile.TemporaryDirectory() as fake_home, \
             tempfile.TemporaryDirectory() as xdg:
            _write_toml(Path(xdg) / "bake.toml", "[formatter]\ntab_width = 5\n")
            os.environ["XDG_CONFIG_HOME"] = xdg
            with _fake_home(fake_home), _fake_cwd(cwd):
                result = Config.load_or_default()
        assert result.formatter.tab_width == 5

    def test_explicit_path_used_directly(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "custom.toml"
            _write_toml(p, "[formatter]\ntab_width = 9\n")
            result = Config.load_or_default(config_path=p)
        assert result.formatter.tab_width == 9

    def test_explicit_missing_path_raises_when_explicit_true(self):
        with pytest.raises(FileNotFoundError):
            Config.load_or_default(
                config_path=Path("/nonexistent/config.toml"),
                explicit=True,
            )

    def test_explicit_missing_path_returns_defaults_when_explicit_false(self):
        result = Config.load_or_default(
            config_path=Path("/nonexistent/config.toml"),
            explicit=False,
        )
        assert isinstance(result.formatter, FormatterConfig)

    def test_broken_cwd_config_falls_through_to_home(self):
        """Invalid cwd .bake.toml is skipped; home config is tried next."""
        with tempfile.TemporaryDirectory() as cwd, \
             tempfile.TemporaryDirectory() as fake_home:
            (Path(cwd) / ".bake.toml").write_text("not valid toml !!!")
            _write_toml(Path(fake_home) / ".bake.toml", "[formatter]\ntab_width = 3\n")
            with _fake_home(fake_home), _fake_cwd(cwd):
                result = Config.load_or_default()
        assert result.formatter.tab_width == 3

    def test_broken_home_config_falls_through_to_defaults(self):
        """Invalid home config returns defaults rather than raising."""
        with tempfile.TemporaryDirectory() as cwd, \
             tempfile.TemporaryDirectory() as fake_home:
            (Path(fake_home) / ".bake.toml").write_text("not valid toml !!!")
            with _fake_home(fake_home), _fake_cwd(cwd):
                result = Config.load_or_default()
        assert isinstance(result.formatter, FormatterConfig)


# ---------------------------------------------------------------------------
# Config.to_dict() round-trip
# ---------------------------------------------------------------------------

class TestToDict:
    """Tests for Config.to_dict()."""

    def test_values_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "rt.toml"
            _write_toml(p, "[formatter]\ntab_width = 4\nmax_line_length = 100\n")
            result = Config.load(p)
        d = result.to_dict()
        assert d["formatter"]["tab_width"] == 4
        assert d["formatter"]["max_line_length"] == 100

    def test_all_formatter_keys_present(self):
        result = Config(formatter=FormatterConfig())
        keys = set(result.to_dict()["formatter"].keys())
        expected = {
            "space_around_assignment", "space_before_colon", "space_after_colon",
            "normalize_line_continuations", "max_line_length",
            "auto_insert_phony_declarations", "group_phony_declarations", "phony_at_top",
            "remove_trailing_whitespace", "ensure_final_newline",
            "normalize_empty_lines", "max_consecutive_empty_lines",
            "fix_missing_recipe_tabs", "indent_nested_conditionals", "tab_width",
            "align_variable_assignments", "align_across_comments",
        }
        assert keys == expected

    def test_global_keys_present(self):
        result = Config(formatter=FormatterConfig())
        d = result.to_dict()
        assert "debug" in d
        assert "verbose" in d
        assert "gnu_error_format" in d
        assert "wrap_error_messages" in d
