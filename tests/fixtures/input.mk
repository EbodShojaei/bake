# Sample Makefile with formatting issues
CC:=gcc
CFLAGS= -Wall -Wextra -g
SOURCES=main.c utils.c helper.c

OBJECTS=$(SOURCES:.c=.o)
TARGET=myprogram

# All targets are now phony so they won't look for or create files
.PHONY: all clean dist install test $(TARGET) $(OBJECTS)

all: $(TARGET)

$(TARGET): $(OBJECTS)
    @echo "Linking object files to create the executable: $(TARGET)"

%.o: %.c
    @echo "Compiling C source file to object file: $<"

clean:
    @echo "Removing object files and the executable"

install:$(TARGET)
    @echo "Installing $(TARGET) to /usr/local/bin/"

test : all
    @echo "Running tests for $(TARGET)"

# Another phony target
dist:
    @echo "Creating distribution archive: $(TARGET).tar.gz" 