# Real-world complex Makefile example
# Project: Example C++ Application with multiple components

# Build configuration
DEBUG ?= 0
PROFILE ?= 0
STATIC ?= 0

# Toolchain detection
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
  PLATFORM = linux
  CC = gcc
  CXX = g++
else ifeq ($(UNAME_S),Darwin)
  PLATFORM = macos
  CC = clang
  CXX = clang++
else
  $(error Unsupported platform: $(UNAME_S))
endif

# Version information
VERSION = $(shell git describe --tags --dirty --always 2>/dev/null || echo "unknown")
BUILD_DATE = $(shell date +'%Y-%m-%d %H: %M: %S')
COMMIT = $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Directory structure
SRCDIR = src
INCDIR = include
BUILDDIR = build
BINDIR = bin
LIBDIR = lib
TESTDIR = tests

# Source files discovery
SOURCES = $(wildcard $(SRCDIR)/*.cpp) \
  $(wildcard $(SRCDIR)/*/*.cpp) \
  $(wildcard $(SRCDIR)/*/*/*.cpp)
HEADERS = $(wildcard $(INCDIR)/*.h) $(wildcard $(INCDIR)/*.hpp)
TEST_SOURCES = $(wildcard $(TESTDIR)/*.cpp)

# Object files
OBJECTS = $(SOURCES:$(SRCDIR)/%.cpp=$(BUILDDIR)/%.o)
TEST_OBJECTS = $(TEST_SOURCES:$(TESTDIR)/%.cpp=$(BUILDDIR)/test_%.o)

# Binary names
TARGET = $(BINDIR)/myapp
TEST_TARGET = $(BINDIR)/test_runner
LIBRARY = $(LIBDIR)/libmyapp.a

# Compiler flags with conditional settings
CPPFLAGS = -I$(INCDIR) -DVERSION=\"$(VERSION)\" -DBUILD_DATE=\"$(BUILD_DATE)\"
CXXFLAGS = -std=c++17 -Wall -Wextra -Wpedantic

ifeq ($(DEBUG),1)
  CXXFLAGS += -g -O0 -DDEBUG
  BUILDDIR := $(BUILDDIR)/debug
else
  CXXFLAGS += -O3 -DNDEBUG
  BUILDDIR := $(BUILDDIR)/release
endif

ifeq ($(PROFILE),1)
  CXXFLAGS += -pg
  LDFLAGS += -pg
endif

ifeq ($(STATIC),1)
  LDFLAGS += -static
endif

# Library dependencies
LIBS = -lpthread -lm
ifeq ($(PLATFORM),linux)
  LIBS += -ldl -lrt
endif

# Phony targets declaration
.PHONY: all clean test install uninstall debug release profile format lint docs help

# Default target
all: $(TARGET)

# Main executable
$(TARGET): $(OBJECTS) | $(BINDIR)
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS) $(LIBS)

# Static library
$(LIBRARY): $(OBJECTS) | $(LIBDIR)
	ar rcs $@ $^
	ranlib $@

# Object files compilation
$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp | $(BUILDDIR)
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

# Test object files
$(BUILDDIR)/test_%.o: $(TESTDIR)/%.cpp | $(BUILDDIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

# Test executable
test: $(TEST_TARGET)
	$(TEST_TARGET)

$(TEST_TARGET): $(TEST_OBJECTS) $(LIBRARY) | $(BINDIR)
	$(CXX) $(TEST_OBJECTS) -L$(LIBDIR) -lmyapp -o $@ $(LDFLAGS) $(LIBS)

# Directory creation
$(BUILDDIR) $(BINDIR) $(LIBDIR):
	@mkdir -p $@

# Convenience targets
debug:
	$(MAKE) DEBUG=1

release:
	$(MAKE) DEBUG=0

profile:
	$(MAKE) PROFILE=1

# Installation
PREFIX ?= /usr/local
DESTDIR ?=

install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/
	install -d $(DESTDIR)$(PREFIX)/share/man/man1/
	install -m644 docs/$(notdir $(TARGET)).1 $(DESTDIR)$(PREFIX)/share/man/man1/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(notdir $(TARGET))
	rm -f $(DESTDIR)$(PREFIX)/share/man/man1/$(notdir $(TARGET)).1

# Development tools
format:
	find $(SRCDIR) $(INCDIR) $(TESTDIR) -name "*.cpp" -o -name "*.h" -o -name "*.hpp" | \
	xargs clang-format -i

lint:
	cppcheck --enable=all --std=c++17 --suppress=missingIncludeSystem \
  $(SRCDIR) $(INCDIR) $(TESTDIR)

docs:
	doxygen Doxyfile

# Cleanup
clean:
	rm -rf $(BUILDDIR) $(BINDIR) $(LIBDIR)

distclean: clean
	rm -rf docs/html docs/latex

# Help target
help:
	@echo "Available targets:"
	@echo "  all      - Build the main executable (default)"
	@echo "  test     - Build and run tests"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install the application"
	@echo "  format   - Format source code"
	@echo "  lint     - Run static analysis"
	@echo ""
	@echo "Configuration options:"
	@echo "  DEBUG=1  - Build with debug symbols"
	@echo "  STATIC=1 - Build static binary"

# Dependency tracking
-include $(OBJECTS:.o=.d)
-include $(TEST_OBJECTS:.o=.d)

# Generate dependency files
$(BUILDDIR)/%.d: $(SRCDIR)/%.cpp | $(BUILDDIR)
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) -MM -MT $(BUILDDIR)/$*.o $< > $@