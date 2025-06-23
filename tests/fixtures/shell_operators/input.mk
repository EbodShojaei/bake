# Test shell operators and assignments formatting

# The original bug case - != should not be changed
check-repo:
	@test "${REPO}" != "tailscale/tailscale" || (echo "REPO=... must not be tailscale/tailscale" && exit 1)

validate-user:
	@test "$(USER)" != "root" || (echo "Cannot run as root" && exit 1)

# Other comparison operators that should not be changed
numeric-checks:
	@test $(NUMBER) -ge 100 || echo "too small"
	@test $(VALUE) -le 1000 || echo "too big"
	if [ $(COUNT) -eq 0 ]; then echo "empty"; fi
	[ $(SIZE) -ne $(EXPECTED) ] && echo "mismatch"

# Bash-style comparison operators
bash-comparisons:
	if [[ "$VAR" == "expected" ]]; then echo "match"; fi
	if [[ $(NUM) <= $(MAX) ]]; then echo "within limit"; fi
	if [[ $(NUM) >= $(MIN) ]]; then echo "above minimum"; fi

# Complex expressions with multiple operators
complex-test:
	@test "$A" != "$B" && test "$C" == "$D" || exit 1
	if [ "$X" <= "$Y" ] && [ "$Y" >= "$Z" ]; then echo "range ok"; fi

# Regular Make variable assignments that should be formatted
CC=gcc
CXX:=g++
CFLAGS+=-Wall -Wextra
DEBUG?=0

# Assignments with poor spacing
LDFLAGS  =  -lpthread
VERSION    :=    1.0.0
SOURCES   +=   main.c utils.c
PREFIX?=/usr/local

# Mixed case with assignments and shell operators
install: all
	@test "$(PREFIX)" != "" || (echo "PREFIX not set" && exit 1)
	DESTDIR="$(DESTDIR)" $(MAKE) install-files

install-files:
	install -m755 $(TARGET) $(DESTDIR)$(bindir)/ 