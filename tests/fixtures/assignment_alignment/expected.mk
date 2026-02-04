# Test variable alignment formatting
CC      = gcc
CXX     := g++
CFLAGS  = -Wall -Wextra -O2
LDFLAGS = -lpthread

# A block with varying variable name lengths
SHORT                   = value
MEDIUM_VAR              = another
VERY_LONG_VARIABLE_NAME := something

# This comment breaks the block
AFTER_COMMENT = test
SECOND        = second

# Test with different operators
A     := something
BB    ?= something-else
CCC   += -more
DDDD  != $(shell echo hi)
EEEEE = regular

# URL assignments should still align
URL1       = http://www.github.com
LONGER_URL = http://www.example.com/path

.PHONY: all
all:
	@echo "Done"
