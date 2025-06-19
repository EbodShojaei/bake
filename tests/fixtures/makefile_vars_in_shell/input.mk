# Test Makefile variables in shell commands
TARGET = myapp
SOURCES = $(wildcard *.c)

build:
	@echo "Building $(TARGET)"
	for src in $(SOURCES); do \
		echo "Compiling $$src"; \
		$(CC) -c $$src -o $${src%.c}.o; \
	done
	$(CC) -o $(TARGET) *.o

test:
	./$(TARGET) --test-mode
	if [ $$? -eq 0 ]; then \
		echo "$(TARGET) tests passed"; \
	else \
		echo "$(TARGET) tests failed"; \
		exit 1; \
	fi 