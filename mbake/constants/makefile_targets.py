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
