"""Utility modules for mbake formatting operations."""

from .format_disable import FormatDisableHandler, FormatRegion
from .line_utils import LineUtils, MakefileParser, PhonyAnalyzer
from .pattern_utils import PatternUtils
from .version_utils import (
    VersionError,
    check_for_updates,
    get_pypi_version,
    is_development_install,
    update_package,
)

__all__ = [
    "FormatDisableHandler",
    "FormatRegion",
    "LineUtils",
    "MakefileParser",
    "PhonyAnalyzer",
    "PatternUtils",
    "check_for_updates",
    "get_pypi_version",
    "update_package",
    "is_development_install",
    "VersionError",
]
