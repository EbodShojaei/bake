# Test that recipes use tabs, not spaces
all: build test

build:
	echo "This line should use a tab, not spaces"
	gcc -o hello hello.c \
			-Wall \
			-Werror

test: build
	echo "This line already has a tab"
	echo "This line has spaces but should be converted to tab" \
		--long-arg \
		--another-arg

clean:
	rm -f hello
  # This comment has spaces instead of a tab

# Test shell command indentation preservation
complex-cmd:
	perl -p -i -e 'use File::Spec;' \
               -e' $$path = File::Spec->abs2rel("$(path)");' \
               -e's/my \$$var = .*/my \$$var = "$$path";/g' \
			-- "$(file)"
