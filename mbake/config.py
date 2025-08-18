"""Configuration loading for mbake."""

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
    group_phony_declarations: bool = False
    phony_at_top: bool = False
    auto_insert_phony_declarations: bool = False

    # General settings
    remove_trailing_whitespace: bool = True
    ensure_final_newline: bool = False
    normalize_empty_lines: bool = True
    max_consecutive_empty_lines: int = 2
    fix_missing_recipe_tabs: bool = True

    # Conditional formatting settings (Default disabled)
    indent_nested_conditionals: bool = False
    # Indentation settings
    tab_width: int = 2


@dataclass
class Config:
    """Main configuration class."""

    formatter: FormatterConfig
    debug: bool = False
    verbose: bool = False
    # Error message formatting
    gnu_error_format: bool = (
        True  # Use GNU standard error format (file:line: Error: message)
    )
    wrap_error_messages: bool = (
        False  # Wrap long error messages (can interfere with IDE parsing)
    )

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> "Config":
        """Load configuration from ~/.bake.toml."""
        if config_path is None:
            config_path = Path.home() / ".bake.toml"

        if not config_path.exists():
            raise FileNotFoundError(
                f"Configuration file not found at {config_path}. "
                "Please create ~/.bake.toml with your formatting preferences."
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
        if "gnu_error_format" in data:
            global_data["gnu_error_format"] = data["gnu_error_format"]
        if "wrap_error_messages" in data:
            global_data["wrap_error_messages"] = data["wrap_error_messages"]

        return cls(formatter=formatter_config, **global_data)

    @classmethod
    def load_or_default(
        cls, config_path: Optional[Path] = None, explicit: bool = False
    ) -> "Config":
        """Load config or return defaults if not found.

        Args:
            config_path: Path to config file, or None for default
            explicit: True if config_path was explicitly specified by user
        """
        if config_path is not None:
            # User explicitly specified a config file
            try:
                return cls.load(config_path)
            except FileNotFoundError:
                if explicit:
                    raise
                return cls(formatter=FormatterConfig())

        # Try to find config file in current directory first, then home directory

        current_dir_config = Path.cwd() / ".bake.toml"
        home_config = Path.home() / ".bake.toml"

        if current_dir_config.exists():
            try:
                return cls.load(current_dir_config)
            except Exception:
                # If current directory config is invalid, fall back to home directory
                pass

        if home_config.exists():
            try:
                return cls.load(home_config)
            except Exception:
                # If home directory config is invalid, fall back to defaults
                pass

        # Return default configuration if no config file found
        return cls(formatter=FormatterConfig())

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
            },
            "debug": self.debug,
            "verbose": self.verbose,
            "gnu_error_format": self.gnu_error_format,
            "wrap_error_messages": self.wrap_error_messages,
        }
