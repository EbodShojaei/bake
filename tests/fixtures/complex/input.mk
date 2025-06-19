# Complex Makefile with multiple formatting issues
CC=gcc
CFLAGS  :=  -Wall -Wextra
LDFLAGS= -lpthread

SOURCES = main.c \  
    utils.c \	
        parser.c

.PHONY: clean
all: $(TARGET)
    echo "Building project"
    $(CC) $(CFLAGS) -o $(TARGET) $(SOURCES)

.PHONY: test
# Conditional with poor formatting
ifeq ($(DEBUG),yes)
EXTRA_FLAGS=-g -O0
else
    EXTRA_FLAGS=-O2
endif

test: $(TARGET)
	if [ -f $(TARGET) ]; then \
	echo "Running tests"; \
	  ./$(TARGET) --test; \
	else \
	    echo "Binary not found"; \
	    exit 1; \
	fi

clean:
  rm -f *.o $(TARGET)  

.PHONY: all install
install   :    $(TARGET)  
	cp $(TARGET) /usr/local/bin/ 