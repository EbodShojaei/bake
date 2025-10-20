"""Makefile special targets and directives, grouped by semantics."""

# Targets that can be duplicated (declarative)
DECLARATIVE_TARGETS = {
    ".PHONY",
    ".SUFFIXES",
}

# Targets that affect rule behavior (can appear multiple times)
RULE_BEHAVIOR_TARGETS = {
    ".PRECIOUS",
    ".INTERMEDIATE",
    ".SECONDARY",
    ".DELETE_ON_ERROR",
    ".IGNORE",
    ".SILENT",
}

# Global directives (should NOT be duplicated)
GLOBAL_DIRECTIVES = {
    ".EXPORT_ALL_VARIABLES",
    ".NOTPARALLEL",
    ".ONESHELL",
    ".POSIX",
    ".LOW_RESOLUTION_TIME",
    ".SECOND_EXPANSION",
    ".SECONDEXPANSION",
}

# Utility/meta targets
UTILITY_TARGETS = {
    ".VARIABLES",
    ".MAKE",
    ".WAIT",
    ".INCLUDE_DIRS",
    ".LIBPATTERNS",
}

# All special targets (for easy checking)
ALL_SPECIAL_MAKE_TARGETS = (
    DECLARATIVE_TARGETS | RULE_BEHAVIOR_TARGETS | GLOBAL_DIRECTIVES | UTILITY_TARGETS
)

# Default suffixes for GNU Make
DEFAULT_SUFFIXES = {
    ".out",
    ".a",
    ".ln",
    ".o",
    ".c",
    ".cc",
    ".C",
    ".cpp",
    ".p",
    ".f",
    ".F",
    ".m",
    ".r",
    ".y",
    ".l",
    ".ym",
    ".lm",
    ".s",
    ".S",
    ".mod",
    ".sym",
    ".def",
    ".h",
    ".info",
    ".dvi",
    ".tex",
    ".texinfo",
    ".texi",
    ".txinfo",
    ".w",
    ".ch",
    ".web",
    ".sh",
    ".elc",
    ".el",
}

# Rule type information
RULE_TYPE_INFO = {
    "explicit": {"description": "Direct target:prerequisite definitions"},
    "pattern": {"description": "Pattern-based rules (%.o: %.c)"},
    "suffix": {"description": "Old-style implicit rules (.c.o:)"},
    "static_pattern": {"description": "Rules with specific target lists"},
    "double_colon": {"description": "Rules with :: separator"},
    "special_target": {"description": "Special built-in targets"},
}
