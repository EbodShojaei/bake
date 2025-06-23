# Test duplicate target detection in conditional blocks
ifneq ($(SYSTEMC_EXISTS),)
default: run
else
default: nosc
endif

# Nested conditionals with same target names
ifeq ($(OS),Windows)
ifeq ($(ARCH),x64)
build: build-windows-x64
else
build: build-windows-x86
endif
else
ifeq ($(OS),Linux)
build: build-linux
endif
endif

# Targets after conditional blocks
ifneq ($(FEATURE_X),)
test: test-with-x
else
test: test-without-x
endif

clean:
	rm -f *.o

# Real duplicate targets (should be flagged)
install:
	echo "First install"

install:
	echo "Second install" 