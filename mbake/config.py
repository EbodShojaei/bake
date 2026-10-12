"""Configuration loading for mbake."""

import os
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Any, Callable, Optional, TypeVar

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

# Name of the per-project config file searched for in the current directory
# and its parents
PROJECT_CONFIG_FILENAME = ".bake.toml"

_PathT = TypeVar("_PathT", bound=PurePath)

# Called with each discovered config file that fails to load and the error.
# This must stay typing.Callable: Optional[collections.abc.Callable[...]]
# raises TypeError on Python 3.9.0 and 3.9.1.
_InvalidConfigCallback = Callable[[Path, Exception], None]


def project_config_candidates(start: _PathT) -> list[_PathT]:
    """Return the project config files to try for ``start``, nearest first.

    That is ``start/.bake.toml`` followed by ``.bake.toml`` in every parent of
    ``start``. For an absolute ``start`` the list always ends at the path's
    anchor (``/``, a drive root or a UNC share), so the search terminates on
    every platform; a relative ``start`` lists only its own parents. The paths
    are not checked for existence.
    """
    return [
        directory / PROJECT_CONFIG_FILENAME for directory in (start, *start.parents)
    ]


def _is_config_file(path: Path) -> bool:
    """Return True if ``path`` exists and is not a directory.

    Special files count, as they always have: a ``.bake.toml`` symlinked to
    ``/dev/null`` is an empty config that masks the user's config. Paths that
    cannot be checked count as absent.
    """
    try:
        return path.exists() and not path.is_dir()
    except OSError:
        # Python < 3.14 re-raises errors such as PermissionError from exists()
        return False


def _same_file(first: Path, second: Path) -> bool:
    """Return True if both paths name the same file."""
    try:
        if first.resolve() == second.resolve():
            return True
    except (OSError, RuntimeError):
        # RuntimeError: symlink loop on Python < 3.13
        return first == second
    try:
        first_stat, second_stat = first.stat(), second.stat()
    except OSError:
        return False
    # The same file under another spelling, such as a mis-cased $HOME on a
    # case-insensitive volume; an inode of 0 means the filesystem cannot tell.
    return first_stat.st_ino != 0 and (first_stat.st_dev, first_stat.st_ino) == (
        second_stat.st_dev,
        second_stat.st_ino,
    )


def get_active_command_name() -> str:
    """Get the active command name for completions and messages.

    Always returns 'mbake' since that's the actual command file.
    User aliases will work with mbake completions automatically.

    Returns:
        The command name to use for completions: 'mbake'
    """
    return "mbake"


@dataclass
class FormatterConfig:
    """Configuration for Makefile formatting rules."""

    # Spacing settings
    space_around_assignment: bool = True
    space_before_colon: bool = False
    space_after_colon: bool = True

    # Line continuation settings
    normalize_line_continuations: bool = True
    max_line_length: int = 120

    # PHONY settings
    auto_insert_phony_declarations: bool = False
    group_phony_declarations: bool = False
    phony_at_top: bool = False

    # General settings
    remove_trailing_whitespace: bool = True
    ensure_final_newline: bool = True
    normalize_empty_lines: bool = True
    max_consecutive_empty_lines: int = 2
    fix_missing_recipe_tabs: bool = True

    # Conditional formatting settings (Default disabled)
    indent_nested_conditionals: bool = False
    # Indentation settings
    tab_width: int = 2

    # Variable alignment settings
    align_variable_assignments: bool = False
    align_across_comments: bool = False


@dataclass
class Config:
    """Main configuration class."""

    formatter: FormatterConfig
    debug: bool = False
    verbose: bool = False
    # Timeout used for make file syntax checking
    syntax_check_timeout = 10
    # Error message formatting
    gnu_error_format: bool = (
        True  # Use GNU standard error format (file:line: Error: message)
    )
    wrap_error_messages: bool = (
        False  # Wrap long error messages (can interfere with IDE parsing)
    )

    @staticmethod
    def determine_config_path() -> Path:
        """Return the user config path for mbake.

        Order of options:
          1. ``~/.bake.toml`` — if the file exists.
          2. ``$XDG_CONFIG_HOME/bake.toml`` — if ``$XDG_CONFIG_HOME`` is set.
          3. ``~/.config/bake.toml`` — XDG default.

        The returned path may not exist. A project ``.bake.toml`` in the current
        directory or a parent directory takes precedence over it; see
        ``find_config_path()``.
        """
        home_path = Path.home() / ".bake.toml"
        if home_path.exists():
            return home_path

        xdg_config_home = os.environ.get("XDG_CONFIG_HOME", "").strip()
        if xdg_config_home:
            return Path(xdg_config_home) / "bake.toml"

        return Path.home() / ".config" / "bake.toml"

    @staticmethod
    def default_config_path() -> Path:
        """Return the default path for creating a new config file.

        Order of preference:
          1. ``$XDG_CONFIG_HOME/bake.toml`` — if ``$XDG_CONFIG_HOME`` is set.
          2. ``~/.config/bake.toml`` — XDG default.
        """
        xdg_config_home = os.environ.get("XDG_CONFIG_HOME", "").strip()
        if xdg_config_home:
            return Path(xdg_config_home) / "bake.toml"
        return Path.home() / ".config" / "bake.toml"

    @staticmethod
    def find_project_config_path(start: Optional[Path] = None) -> Optional[Path]:
        """Return the nearest ``.bake.toml`` in ``start`` or one of its parents.

        ``start`` defaults to the current working directory, and a relative
        ``start`` is taken relative to it. A ``start`` containing ``..`` is
        resolved first, as the operating system would resolve it. Returns None
        if there is no such file or the current working directory is
        unavailable. The file is not loaded, so it may be invalid.
        """
        return next(Config._iter_project_config_paths(start), None)

    @staticmethod
    def _iter_project_config_paths(start: Optional[Path] = None) -> Iterator[Path]:
        """Yield the existing ``.bake.toml`` files from ``start`` up to the root.

        Each location is checked only when the next file is requested.
        """
        try:
            if start is None:
                start = Path.cwd()
            elif not start.is_absolute():
                start = Path.cwd() / start
            if ".." in start.parts:
                # The literal parents of a/b/../c include a/b, which is not a
                # parent of the directory that path names
                start = start.resolve()
        except (OSError, RuntimeError):
            # The working directory was deleted or cannot be accessed, or
            # resolving start hit a symlink loop (RuntimeError before 3.13)
            return
        for candidate in project_config_candidates(start):
            if _is_config_file(candidate):
                yield candidate

    @classmethod
    def find_config_path(
        cls, *, on_invalid: Optional[_InvalidConfigCallback] = None
    ) -> Path:
        """Return the config file that ``load_or_default()`` would use.

        That is the first discovered file that loads. If none loads, this is
        ``determine_config_path()``, which may be missing or invalid. Every
        other discovered file that failed to load is passed to ``on_invalid``
        with its error.
        """
        failures: list[tuple[Path, Exception]] = []
        config_path, _ = cls._load_discovered(
            lambda path, error: failures.append((path, error))
        )
        if config_path is None:
            config_path = cls.determine_config_path()
        if on_invalid is not None:
            for path, error in failures:
                # A caller that reads the returned file reports its errors itself
                if not _same_file(path, config_path):
                    on_invalid(path, error)
        return config_path

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> "Config":
        """Load configuration from XDG config path
        ( Checks if home config exists, else checks if XDG_CONFIG_HOME exists,
         else falls back to ~/.config/bake.toml)"""
        if config_path is None:
            config_path = cls.determine_config_path()

        if not config_path.exists():
            raise FileNotFoundError(
                f"Configuration file not found at {config_path}. "
                "Please create ~/.config/bake.toml with your formatting preferences."
            )

        try:
            with open(config_path, "rb") as f:
                data = tomllib.load(f)
        except Exception as e:
            raise ValueError(f"Failed to parse configuration file: {e}") from e

        # Extract formatter config, filtering out non-FormatterConfig keys
        formatter_data = data.get("formatter", {})
        # Remove any keys that aren't valid FormatterConfig fields
        valid_formatter_keys = {
            "space_around_assignment",
            "space_before_colon",
            "space_after_colon",
            "normalize_line_continuations",
            "max_line_length",
            "group_phony_declarations",
            "phony_at_top",
            "auto_insert_phony_declarations",
            "remove_trailing_whitespace",
            "ensure_final_newline",
            "normalize_empty_lines",
            "max_consecutive_empty_lines",
            "fix_missing_recipe_tabs",
            "indent_nested_conditionals",
            "tab_width",
            "align_variable_assignments",
            "align_across_comments",
        }
        filtered_formatter_data = {
            k: v for k, v in formatter_data.items() if k in valid_formatter_keys
        }
        formatter_config = FormatterConfig(**filtered_formatter_data)

        # Extract global config (only from top level - these are global settings, not formatter settings)
        global_data = {}

        if "debug" in data:
            global_data["debug"] = data["debug"]
        if "verbose" in data:
            global_data["verbose"] = data["verbose"]
        if "timeout_seconds" in data:
            global_data["timeout_seconds"] = data["timeout_seconds"]
        if "gnu_error_format" in data:
            global_data["gnu_error_format"] = data["gnu_error_format"]
        if "wrap_error_messages" in data:
            global_data["wrap_error_messages"] = data["wrap_error_messages"]

        return cls(formatter=formatter_config, **global_data)

    @classmethod
    def load_or_default(
        cls,
        config_path: Optional[Path] = None,
        explicit: bool = False,
        *,
        on_invalid: Optional[_InvalidConfigCallback] = None,
    ) -> "Config":
        """Load config or return defaults if not found.

        Without ``config_path``, the first of these files that loads is used:

          1. ``.bake.toml`` in the current directory, then in each parent
             directory up to the filesystem root (nearest first).
          2. ``determine_config_path()``: ``~/.bake.toml`` if it exists, else
             ``$XDG_CONFIG_HOME/bake.toml`` (default ``~/.config/bake.toml``).

        Files that exist but cannot be loaded are skipped. If ``on_invalid`` is
        given, it is called with the path and the error for each skipped file.

        Args:
            config_path: Path to config file, or None to search for one
            explicit: True if config_path was explicitly specified by user
            on_invalid: Called for each discovered config file that fails to load
        """
        if config_path is not None:
            # User explicitly specified a config file
            try:
                return cls.load(config_path)
            except FileNotFoundError:
                if explicit:
                    raise
                return cls(formatter=FormatterConfig())

        _, config = cls._load_discovered(on_invalid)
        if config is not None:
            return config

        # Return default configuration if no usable config file was found
        return cls(formatter=FormatterConfig())

    @classmethod
    def _load_discovered(
        cls, on_invalid: Optional[_InvalidConfigCallback] = None
    ) -> tuple[Optional[Path], Optional["Config"]]:
        """Return the first discovered config file that loads, and its config.

        Tries ``.bake.toml`` in the current directory and each parent directory
        (nearest first), then ``determine_config_path()``. Locations are checked
        one at a time, so nothing after the first usable file is looked at.
        ``on_invalid`` is called for each file that fails to load. Returns
        ``(None, None)`` if no file loads.
        """
        skipped: list[Path] = []
        for candidate in cls._iter_project_config_paths():
            try:
                return candidate, cls.load(candidate)
            except Exception as error:
                # Skip an invalid config file and try the next one
                skipped.append(candidate)
                if on_invalid is not None:
                    on_invalid(candidate, error)

        user_config = cls.determine_config_path()
        # The search reaches ~/.bake.toml itself when it passes through the
        # home directory, so a file it already skipped is not tried again
        if user_config.exists() and not any(
            _same_file(user_config, path) for path in skipped
        ):
            try:
                return user_config, cls.load(user_config)
            except Exception as error:
                if on_invalid is not None:
                    on_invalid(user_config, error)
        return None, None

    def to_dict(self) -> dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "formatter": {
                "space_around_assignment": self.formatter.space_around_assignment,
                "space_before_colon": self.formatter.space_before_colon,
                "space_after_colon": self.formatter.space_after_colon,
                "normalize_line_continuations": self.formatter.normalize_line_continuations,
                "max_line_length": self.formatter.max_line_length,
                "group_phony_declarations": self.formatter.group_phony_declarations,
                "phony_at_top": self.formatter.phony_at_top,
                "auto_insert_phony_declarations": self.formatter.auto_insert_phony_declarations,
                "remove_trailing_whitespace": self.formatter.remove_trailing_whitespace,
                "ensure_final_newline": self.formatter.ensure_final_newline,
                "normalize_empty_lines": self.formatter.normalize_empty_lines,
                "max_consecutive_empty_lines": self.formatter.max_consecutive_empty_lines,
                "fix_missing_recipe_tabs": self.formatter.fix_missing_recipe_tabs,
                "indent_nested_conditionals": self.formatter.indent_nested_conditionals,
                "tab_width": self.formatter.tab_width,
                "align_variable_assignments": self.formatter.align_variable_assignments,
                "align_across_comments": self.formatter.align_across_comments,
            },
            "debug": self.debug,
            "verbose": self.verbose,
            "syntax_check_timeout": self.syntax_check_timeout,
            "gnu_error_format": self.gnu_error_format,
            "wrap_error_messages": self.wrap_error_messages,
        }
