"""Configuration loading for mbake."""

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


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
    def determine_config_path() -> Optional[Path]:
        """Look for mbake's config in common places.

        Search scheme:
          1. ``./.bake.toml``, then ``../.bake.toml``, then ``../../.bake.toml``,
            etc. until ``/`` is hit.
          2. ``~/.bake.toml``.
          3. ``$XDG_CONFIG_HOME/bake.toml`` — if ``$XDG_CONFIG_HOME`` is set.
          4. ``~/.config/bake.toml`` — XDG default.

        Returns:
            Path to the config file, or None if it wasn't found.
        """

        def find_file_in_ancestor_directories(
            filename: str, starting_directory: Path
        ) -> Optional[Path]:
            filepath = starting_directory / filename
            while not filepath.exists():
                if filepath.parent == Path(filepath.root):
                    return None
                filepath = filepath.parent.parent / filename
            return filepath

        resolved_config_path = find_file_in_ancestor_directories(
            ".bake.toml", Path.cwd()
        )
        if resolved_config_path is not None:
            return resolved_config_path

        resolved_config_path = Path.home() / ".bake.toml"
        if resolved_config_path.exists():
            return resolved_config_path

        xdg_config_home = os.environ.get("XDG_CONFIG_HOME", "").strip()
        if xdg_config_home:
            resolved_config_path = Path(xdg_config_home) / "bake.toml"
            if resolved_config_path.exists():
                return resolved_config_path

        resolved_config_path = Path.home() / ".config" / "bake.toml"
        if resolved_config_path.exists():
            return resolved_config_path
        return None

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

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> tuple["Config", Path]:
        """Attempt to load configuration from ``config_path``,
        or from the default places if ``config_path`` is None.

        Returns:
            The loaded config and the path it's at.

        Raises:
            FileNotFoundError: If ``config_path`` wasn't found or, when ``config_path`` is None,
                if the config wasn't found at the default places.
            ValueError: If the config was found but its parsing failed.
        """
        if (
            config_path is not None and not config_path.exists()
        ):  # Bail out if a nonexistent config was passed
            raise FileNotFoundError(f"Configuration file not found at {config_path}")
        if (
            config_path is None
        ):  # If config wasn't explicitly passed, look for it in common places
            config_path = cls.determine_config_path()
        if config_path is None:  # Still nothing?
            raise FileNotFoundError(
                "Configuration file not found at the default places. "
                "Please create .bake.toml in your project's root or "
                "~/.config/bake.toml with your formatting preferences."
            )
        try:
            with open(config_path, "rb") as f:
                data = tomllib.load(f)
        except tomllib.TOMLDecodeError as e:
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
        return cls(formatter=formatter_config, **global_data), config_path

    @classmethod
    def load_or_default(
        cls, config_path: Optional[Path] = None
    ) -> tuple["Config", Optional[Path]]:
        """Like ``load`` but falls back to the default configuration
        if the config file isn't present at the default locations"""
        try:
            return cls.load(config_path)
        except FileNotFoundError:
            if config_path is None:  # Config wasn't found at the default places
                return cls(formatter=FormatterConfig()), None
            # Config was passed explicitly but wasn't found. Tell the caller about that
            raise
        # Don't handle `ValueError`
        # Tell the caller that they have an invalid config

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
