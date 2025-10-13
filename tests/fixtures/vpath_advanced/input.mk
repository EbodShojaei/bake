# VPATH with function calls
VPATH = $(wildcard src/*) $(wildcard include/*)
VPATH = $(patsubst %/,%,$(dir $(wildcard src/*.c)))

# VPATH in target-specific context
debug: VPATH = src:include:build
release: VPATH = src include build
test: VPATH = src: include:build

# VPATH with complex variable references
BASE_DIRS = src include
EXTRA_DIRS = build test
VPATH = $(BASE_DIRS):$(EXTRA_DIRS)

# VPATH with substitution references
DIRS = src:include:build
VPATH = $(DIRS)

# VPATH with conditional assignment and function calls
VPATH ?= $(wildcard src/*) $(wildcard include/*)
