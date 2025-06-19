# Test that recipes use tabs, not spaces
all: build test

build:
	echo "This line should use a tab, not spaces"
	gcc -o hello hello.c

test: build
	echo "This line already has a tab"
	echo "This line has spaces but should be converted to tab"

clean:
	rm -f hello
	# This comment has spaces instead of a tab
