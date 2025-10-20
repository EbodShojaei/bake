# Test suffix rules and SUFFIXES handling
.POSIX:
.SUFFIXES: .a .b .c .o

# Phony targets
all: foo.b bar.o
clean:
	rm -f *.b *.o

# File targets (should NOT be phony)
foo.b: foo.a
bar.o: bar.c

# Suffix rules (should NOT be phony)
.a.b:
	cp $< $@

.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<

# Pattern rules (should NOT be phony)
%.h: %.c
	@echo "Generating $@ from $<"

# Static pattern rules (should NOT be phony)
objects: %.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

.PHONY: all clean
