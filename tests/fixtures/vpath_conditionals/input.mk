# VPATH in conditional blocks
ifeq ($(PLATFORM),linux)
VPATH = src:include:build
else
VPATH = src include build
endif

# VPATH with different assignment operators
VPATH := src:include:build
VPATH += src:include:build
VPATH ?= src:include:build

# VPATH with variable references
SRC_DIRS = src include build
VPATH = $(SRC_DIRS)

# VPATH in nested conditionals
ifdef DEBUG
ifeq ($(OS),windows)
VPATH = src: include:build
else
VPATH = src include build
endif
endif
