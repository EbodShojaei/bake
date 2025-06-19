"""Base plugin interface for bake formatting rules."""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class FormatResult:
    """Result of a formatting rule application."""

    lines: list[str]
    changed: bool
    errors: list[str]
    warnings: list[str]


class FormatterPlugin(ABC):
    """Base class for all formatting plugins."""

    def __init__(self, name: str, priority: int = 50):
        """Initialize the plugin.

        Args:
            name: Human-readable name of the plugin
            priority: Execution priority (lower numbers run first)
        """
        self.name = name
        self.priority = priority

    @abstractmethod
    def format(self, lines: list[str], config: dict) -> FormatResult:
        """Apply formatting rule to the lines.

        Args:
            lines: List of lines to format
            config: Configuration dictionary

        Returns:
            FormatResult with updated lines and metadata
        """
        pass

    def validate(self, lines: list[str], config: dict) -> list[str]:
        """Validate lines according to this rule.

        Args:
            lines: List of lines to validate
            config: Configuration dictionary

        Returns:
            List of validation error messages
        """
        result = self.format(lines, config)
        if result.changed:
            return [f"{self.name}: formatting violations detected"]
        return []

    def __lt__(self, other: "FormatterPlugin") -> bool:
        """Enable sorting by priority."""
        return self.priority < other.priority
