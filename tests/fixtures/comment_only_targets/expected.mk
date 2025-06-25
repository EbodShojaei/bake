# Test comment-only targets (documentation targets)
# These should not trigger duplicate target errors

# Real targets with actual implementations
build: $(OBJECTS)
	$(CC) -o $@ $^

clean:
	rm -f *.o main

test:
	./main --test

install: build
	cp main /usr/local/bin/

# Documentation section with comment-only targets
# These lines look like targets but are just documentation
build: ## Build the project
clean: ## Clean build artifacts
test: ## Run unit tests
install: ## Install to system
help: ## Show this help message

# Mixed scenario - real target after comment target
help:
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?##' Makefile | awk 'BEGIN {FS = ":.*?##"}; {printf "  %-18s %s\n", $$1, $$2}'

# More comment variations
debug: ## Build with debug symbols
release: ## Build optimized version
package: ## Create distribution package
