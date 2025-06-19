"""Configuration loading for makefmt."""

from pathlib import Path
from typing import Any, Optional

try:
    import tomllib  # type: ignore[import-not-found]
except ImportError:
    import tomli as tomllib
from dataclasses import dataclass


@dataclass
class FormatterConfig:
    """Configuration for Makefile formatting rules."""

    # Indentation settings
    use_tabs: bool = True
    tab_width: int = 4

    # Spacing settings
    space_around_assignment: bool = True
    space_before_colon: bool = False
    space_after_colon: bool = True

    # Line continuation settings
    normalize_line_continuations: bool = True
    max_line_length: int = 120

    # PHONY settings
    group_phony_declarations: bool = True
    phony_at_top: bool = True

    # General settings
    remove_trailing_whitespace: bool = True
    ensure_final_newline: bool = True
    normalize_empty_lines: bool = True
    max_consecutive_empty_lines: int = 2


@dataclass
class Config:
    """Main configuration class."""

    formatter: FormatterConfig
    debug: bool = False
    verbose: bool = False

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
            "use_tabs",
            "tab_width",
            "space_around_assignment",
            "space_before_colon",
            "space_after_colon",
            "normalize_line_continuations",
            "max_line_length",
            "group_phony_declarations",
            "phony_at_top",
            "remove_trailing_whitespace",
            "ensure_final_newline",
            "normalize_empty_lines",
            "max_consecutive_empty_lines",
        }
        filtered_formatter_data = {
            k: v for k, v in formatter_data.items() if k in valid_formatter_keys
        }
        formatter_config = FormatterConfig(**filtered_formatter_data)

        # Extract global config, only taking debug and verbose
        global_data = {}
        if "debug" in data:
            global_data["debug"] = data["debug"]
        if "verbose" in data:
            global_data["verbose"] = data["verbose"]

        return cls(formatter=formatter_config, **global_data)

    @classmethod
    def load_or_default(cls, config_path: Optional[Path] = None) -> "Config":
        """Load config or return defaults if not found."""
        try:
            return cls.load(config_path)
        except FileNotFoundError:
            # Return default configuration
            return cls(formatter=FormatterConfig())

    def to_dict(self) -> dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "formatter": {
                "use_tabs": self.formatter.use_tabs,
                "tab_width": self.formatter.tab_width,
                "space_around_assignment": self.formatter.space_around_assignment,
                "space_before_colon": self.formatter.space_before_colon,
                "space_after_colon": self.formatter.space_after_colon,
                "normalize_line_continuations": self.formatter.normalize_line_continuations,
                "max_line_length": self.formatter.max_line_length,
                "group_phony_declarations": self.formatter.group_phony_declarations,
                "phony_at_top": self.formatter.phony_at_top,
                "remove_trailing_whitespace": self.formatter.remove_trailing_whitespace,
                "ensure_final_newline": self.formatter.ensure_final_newline,
                "normalize_empty_lines": self.formatter.normalize_empty_lines,
                "max_consecutive_empty_lines": self.formatter.max_consecutive_empty_lines,
            },
            "debug": self.debug,
            "verbose": self.verbose,
        }
