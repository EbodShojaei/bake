# Error handling and edge cases
$(info Building project...)
$(warning This is a warning message)
$(error   Build failed!)

# Commands with error handling
build:
	-mkdir -p build/
	@echo "Creating directories"
	+$(MAKE) -C subdir all
	$(CC) $(CFLAGS) -o main main.c || exit 1

# Multiple commands on one line (should be separated)
quick-build: ; $(CC) -o main main.c; echo "Done"

# Commands with different prefixes
test:
	-rm -f test.log
	@echo "Running tests..." > test.log
	+$(MAKE) run-tests
	@-cat test.log || true

# Target with suppressed errors and output
silent-build:
	@-$(CC) $(CFLAGS) -o main main.c 2>/dev/null || echo "Build failed"

# Commands with complex error handling
deploy:
	if ! [ -f main ]; then \
	echo "Binary not found" >&2; \
	exit 1; \
	fi
	@cp main /usr/local/bin/ || { echo "Install failed"; exit 1; }

# Empty targets and comments
empty-target:

# Target with only comments
comment-only:
	# This target only has comments
	# No actual commands

# Targets with weird spacing around semicolons
one-liner: ;echo "Hello"
another: ; echo "World"

# Function calls with error conditions
CHECK_FILE = $(if $(wildcard $(1)),$(1),$(error File $(1) not found))
REQUIRED_FILE = $(call CHECK_FILE,important.h)