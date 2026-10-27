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

# Global directives. Like any target, they may appear in several rules (GNU
# make manual 4.11, lines 2545-2548).
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

# The default suffix list of GNU make (GNU make manual 10.2, lines 7545-7549).
# GNU make 4.4.1 has '.yl' where the manual and make 3.81 have '.lm' (see
# 'make -p'), so both are here.
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
    ".yl",
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
