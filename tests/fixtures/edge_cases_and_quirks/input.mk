#Edge cases and Makefile quirks

#Variables with special characters
WEIRD_VAR=value with spaces
PATH_VAR=/path/with/$(DOLLAR)sign
QUOTE_VAR="quoted value"
ESCAPE_VAR=value\ with\ escapes

#Variables with complex substitutions
NESTED=$(subst $(SPACE),_,$(strip $(SOURCES)))
SPACE:=
SPACE+=  

#Dollar sign handling
DOLLAR=$$
DOUBLE_DOLLAR=$$(echo hello)
LITERAL_DOLLAR=$$$$

#Targets with special characters
target-with-dashes:dependency
    @echo "Building target with dashes"

target_with_underscores:dependency
      @echo "Building target with underscores"

#Targets with variables in names
$(TARGET).backup:$(TARGET)
        cp $< $@

#Pattern rules with edge cases
%.out:%.in
    cp $< $@

src/%.o:src/%.c
      $(CC) -c $< -o $@

#Multiple targets on one line
target1 target2 target3:common-dep
      @echo "Multiple targets"

#Targets with no dependencies
standalone:
    @echo "Standalone target"

#Empty recipe
empty-recipe:

#Recipe with only whitespace
whitespace-only:
	

#Long lines that might need wrapping
very-long-target-name-that-might-cause-formatting-issues:very-long-dependency-name-that-also-might-cause-issues
    very-long-command-line-that-extends-beyond-normal-width-and-might-need-special-handling-by-the-formatter

#Conditional assignments with complex conditions
ifeq ($(origin CC),undefined)
CC=gcc
endif

ifneq (,$(findstring gcc,$(CC)))
COMPILER_FLAGS=-Wall -Wextra
endif

#Complex shell constructs in recipes
complex-shell:
      for i in 1 2 3; do \
        echo "Processing $$i"; \
          if [ $$i -eq 2 ]; then \
              continue; \
      fi; \
    echo "Done with $$i"; \
      done

#Variable assignments with functions
FILES:=$(wildcard *.c)
OBJS=$(FILES:.c=.o)
DEPS=$(OBJS:.o=.d)

#Immediate vs deferred evaluation edge cases
NOW:=$(shell date)
LATER=$(shell date)

#Include with variables and functions
-include $(DEPS)
include $(wildcard config/*.mk)

#Comments in weird places
CC=gcc#inline comment
#CFLAGS=-Wall#commented out assignment

#Tab vs spaces in recipes (this tests tab handling)
tab-test:
    echo "This line uses tab"
        echo "This line uses spaces (should be converted to tab)"
	    echo "This line uses mixed tab and spaces"

#Function calls with complex arguments
FILTERED=$(filter-out $(EXCLUDE_PATTERNS),$(ALL_FILES))
TRANSFORMED=$(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SOURCES))

#Export with complex expressions
export PATH:=$(PATH):$(shell pwd)/bin
export CFLAGS+=$(if $(DEBUG),-g -O0,-O2) 