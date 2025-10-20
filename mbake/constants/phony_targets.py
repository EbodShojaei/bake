"""Common phony target names for automatic detection."""

# Common phony target names that should be automatically detected
# These are action-oriented targets that don't represent actual files
# Only includes targets that are almost certainly phony and won't conflict with file targets
COMMON_PHONY_TARGETS = {
    "all",
    "clean",
    "install",
    "uninstall",
    "test",
    "help",
    "build",
    "rebuild",
    "debug",
    "release",
    "dist",
    "distclean",
    "docs",
    "doc",
    "lint",
    "setup",
    "format",
    "check",
    "verify",
    "validate",
}
