"""Constants package for mbake configuration and patterns."""

from .makefile_targets import ALL_SPECIAL_MAKE_TARGETS, DECLARATIVE_TARGETS
from .phony_targets import COMMON_PHONY_TARGETS
from .shell_commands import SHELL_COMMAND_INDICATORS

__all__ = [
    "DECLARATIVE_TARGETS",
    "COMMON_PHONY_TARGETS",
    "ALL_SPECIAL_MAKE_TARGETS",
    "SHELL_COMMAND_INDICATORS",
]
