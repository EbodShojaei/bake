"""mbake - A Python-based Makefile formatter and linter."""

__version__ = "1.2.4"
__author__ = "mbake Contributors"
__description__ = "A Python-based Makefile formatter and linter"

from .config import Config
from .core.formatter import MakefileFormatter

__all__ = ["MakefileFormatter", "Config"]
