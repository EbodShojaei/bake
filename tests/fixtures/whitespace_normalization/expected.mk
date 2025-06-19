# Test whitespace normalization
CC = gcc
CFLAGS = -Wall -Wextra

all: $(TARGET)
	echo "Building..."

clean:
	rm -f *.o

install:
	cp $(TARGET) /usr/local/bin/