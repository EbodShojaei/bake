# Test variable assignment formatting
CC=gcc
CXX  :=  g++
LD=$(CC)
CFLAGS   =   -Wall -Wextra -O2
CXXFLAGS=$(CFLAGS) -std=c++17
LDFLAGS=-lpthread

# Multi-line variable assignment
SOURCES = main.c \
  utils.c \
	parser.c

# Function with nested calls
OBJECTS=$(patsubst %.c,%.o,$(filter %.c,$(SOURCES)))

# Add a default target
.PHONY: all
all:
	@echo "Makefile processed successfully."

# URL assignments should remain unchanged aside from spacing normalization
VARIABLE = http://www.github.com
VARIABLE = http://www.github.com

# Variants with uneven spacing should normalize consistently
VARIABLE= http://www.github.com
VARIABLE =http://www.github.com