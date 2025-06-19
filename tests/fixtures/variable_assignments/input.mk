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