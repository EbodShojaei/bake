"""Makefile formatter and linter."""

__version__ = "1.0.0"
__author__ = "Generated Python Makefile Formatter"

from .config import Config
from .core.formatter import MakefileFormatter

__all__ = ["MakefileFormatter", "Config"]
