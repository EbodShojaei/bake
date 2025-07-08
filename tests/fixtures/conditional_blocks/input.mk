# Test conditional block formatting
ifeq ($(DEBUG),yes)
CFLAGS=-g -O0
# Recipe lines should always use tabs
    gcc -c file.c -o file.o
else
CFLAGS=-O2
        gcc -c file.c -o file.o
endif

# Nested conditionals with inconsistent indentation
ifeq ($(OS),Windows_NT)
    PLATFORM = windows
ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
    ARCH = x86_64
    # Recipe in nested conditional
    gcc -m64 file.c
else
        ARCH = x86
    gcc -m32 file.c
endif
    EXE_EXT = .exe
else
UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
PLATFORM = linux
    gcc -fPIC file.c
    else ifeq ($(UNAME_S),Darwin)
        PLATFORM = macos
      gcc -arch x86_64 file.c
    endif
endif

# Test complex shell commands in conditionals
ifdef GITHUB_ACTIONS
    uv run ruff check --fix . \
        --exclude tests/* \
        --ignore E501
endif 