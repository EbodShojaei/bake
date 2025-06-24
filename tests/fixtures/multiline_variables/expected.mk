# Test multiline variable assignments with complex scenarios
SOURCES = \
  src/main.c \
  src/utils.c \
  src/parser.c \
  src/lexer.c

# Variables with mixed line continuations
CFLAGS = -Wall -Wextra \
  -Werror \
  -std=c99 \
  -pedantic

# Complex variable with embedded quotes and spaces
DEFINES = -DVERSION=\"$(VERSION)\" \
  -DBUILD_DATE="$(shell date)" \
  -DDEBUG=1 \
  -DPLATFORM=\"$(PLATFORM)\"

# Variable with function calls and complex syntax
OBJECTS = $(patsubst %.c,%.o,$(SOURCES)) \
  $(patsubst %.cpp,%.o,$(wildcard *.cpp)) \
  $(shell find . -name "*.s" | sed 's/\.s/\.o/g')

# Multiline variable with mixed operators
INSTALL_DIRS += /usr/local/bin \
  /usr/local/share/man/man1 \
  /usr/local/share/doc/$(PACKAGE)

# Complex substitution with line continuation
CLEANED_SOURCES = $(subst src/,,$(SOURCES:.c=.o)) \
  $(subst tests/,,$(TEST_SOURCES:.c=.o)) \
  $(subst examples/,,$(EXAMPLE_SOURCES:.c=.o))

# Variable with conditional assignment and continuation
EXTRA_LIBS ?= -lm \
  -lpthread \
  -ldl

# Test: Assignment spacing with multi-line values (from demo.mk)
CPPCHECK_FLAGS = --enable=all --inline-suppr \
  --suppress=cstyleCast --suppress=useInitializationList \
  --suppress=nullPointer --suppress=nullPointerRedundantCheck --suppress=ctunullpointer \
  --suppress=unusedFunction --suppress=unusedScopedObject \
  --suppress=useStlAlgorithm \

CLANGTIDY_FLAGS = -config='' \
  -header-filter='.*' \
  -checks='-fuchsia-*,-cppcoreguidelines-avoid-c-arrays,-cppcoreguidelines-init-variables,-cppcoreguidelines-avoid-goto,-modernize-avoid-c-arrays,-readability-magic-numbers,-readability-simplify-boolean-expr,-cppcoreguidelines-macro-usage' \