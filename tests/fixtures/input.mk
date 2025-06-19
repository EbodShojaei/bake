# Sample Makefile with formatting issues
CC:=gcc
CFLAGS= -Wall -Wextra -g
SOURCES=main.c \
  utils.c \
    helper.c

OBJECTS=$(SOURCES:.c=.o)
TARGET=myprogram

.PHONY: clean
all: $(TARGET)

$(TARGET): $(OBJECTS)
    $(CC) $(CFLAGS) -o $@ $^

%.o: %.c
    $(CC) $(CFLAGS) -c -o $@ $<

.PHONY: install
clean:
    rm -f $(OBJECTS) $(TARGET)

install:$(TARGET)
    cp $(TARGET) /usr/local/bin/
    chmod +x /usr/local/bin/$(TARGET)

test : all
    ./$(TARGET) --test

# Another phony target
.PHONY: dist



dist:
    tar -czf $(TARGET).tar.gz *.c *.h Makefile 