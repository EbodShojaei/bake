# Test phony target formatting with scattered declarations
all: $(TARGET)
	@echo "Build complete"

.PHONY: clean
clean:
	rm -f *.o $(TARGET)

test: $(TARGET)
	./run_tests.sh

.PHONY: test install
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

.PHONY: all
help:
	@echo "Available targets: all, clean, test, install, help" 