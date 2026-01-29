# Test alignment across comments
CC=gcc
CXX  :=  g++
# This is a comment inside the block
CFLAGS   =   -Wall -Wextra -O2
# Another comment
LDFLAGS=-lpthread

# A block with comments between
SHORT = value
# Comment in middle
MEDIUM_VAR = another
# Another comment
VERY_LONG_VARIABLE_NAME := something

.PHONY: all
all:
	@echo "Done"
