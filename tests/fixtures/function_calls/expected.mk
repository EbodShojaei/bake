# Test Makefile function calls with inconsistent formatting
SOURCES = $(wildcard src/*.c) $(wildcard tests/*.c)

# Function calls with nested parentheses and poor spacing
OBJECTS = $(patsubst %.c,%.o,$(filter %.c,$(SOURCES))) \
  $(patsubst %.cpp,%.o,$(filter %.cpp,$(wildcard *.cpp)))

# Complex nested function calls
VERSION = $(shell git describe --tags --abbrev=0 2>/dev/null || echo "unknown")
BUILD_DATE = $(shell date +%Y-%m-%d)
COMMIT_HASH = $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Functions with poor indentation and spacing
DEPS = $(shell find . -name "*.h" -o -name "*.hpp" | \
  head -10 | \
  sort | \
  uniq)

# Conditional function calls
COMPILER = $(if $(CC),$(CC),gcc)
OPTIMIZATION = $(if $(DEBUG),-O0 -g,-O2)

# Function calls in variable assignments
FORMATTED_VERSION = $(strip $(subst v,,$(VERSION)))
CLEAN_OBJECTS = $(filter-out %.tmp,$(OBJECTS))

# Complex substitution functions
RELATIVE_SOURCES = $(patsubst $(PWD)/%,%,$(abspath $(SOURCES)))
HEADER_DIRS = $(sort $(dir $(wildcard include/*.h)))

# Functions with shell commands
AVAILABLE_CORES = $(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)
MAKE_JOBS = $(shell echo $$(($(AVAILABLE_CORES) + 1)))