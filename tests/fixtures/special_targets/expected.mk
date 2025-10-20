# Test special target handling
.POSIX:
.SUFFIXES: .c .o .h

# Global directives (should not be duplicated)
.EXPORT_ALL_VARIABLES
.NOTPARALLEL
.ONESHELL

# Declarative targets (can be duplicated)
.PHONY: all clean
.PHONY: test install

.SUFFIXES: .cpp .obj
.SUFFIXES: .py .pyc

# Rule behavior targets (can be duplicated)
.PRECIOUS: *.o
.INTERMEDIATE: temp.*
.SECONDARY: backup.*
.IGNORE: clean
.SILENT: install

# Utility targets
.VARIABLES:
.MAKE:
.WAIT:
.INCLUDE_DIRS:
.LIBPATTERNS: lib%.a

# Regular targets
all: main.o
	$(CC) -o main main.o

main.o: main.c
	$(CC) -c main.c

clean:
	rm -f *.o main

test:
	@echo "Running tests"

install: main
	cp main /usr/local/bin/
