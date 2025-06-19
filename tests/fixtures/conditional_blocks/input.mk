# Test conditional block formatting
ifeq ($(DEBUG),yes)
CFLAGS=-g -O0
else
CFLAGS=-O2
endif

# Nested conditionals with inconsistent indentation
ifeq ($(OS),Windows_NT)
    PLATFORM = windows
ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
    ARCH = x86_64
else
        ARCH = x86
endif
    EXE_EXT = .exe
else
UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
PLATFORM = linux
    else ifeq ($(UNAME_S),Darwin)
        PLATFORM = macos
    endif
endif 