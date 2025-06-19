# Test phony target formatting with scattered declarations
.PHONY: all clean help install test

all: $(TARGET)
	@echo "Build complete"

clean:
	rm -f *.o $(TARGET)

test: $(TARGET)
	./run_tests.sh

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

help:
	@echo "Available targets: all, clean, test, install, help"