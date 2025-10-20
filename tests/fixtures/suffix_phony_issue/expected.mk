# Original issue: suffix rules should NOT be suggested as phony
.POSIX:
.SUFFIXES: .a .b

all: foo.b
foo.b: foo.a

.a.b:
	cp $< $@

.PHONY: all
