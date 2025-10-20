# 🍞 mbake

<!-- markdownlint-disable MD033 -->
<div align="center">
    <img src="https://raw.githubusercontent.com/ebodshojaei/bake/main/vscode-mbake-extension/icon.png" alt="mbake logo" width="128" height="128">
    <br/>
    <em>A Makefile formatter and linter. It only took 50 years!</em>
    <br/><br/>
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"/>
    </a>
    <a href="https://www.python.org/downloads/">
        <img src="https://img.shields.io/badge/python-3.9+-blue.svg" alt="Python 3.9+"/>
    </a>
    <a href="https://pypi.org/project/mbake/">
        <img src="https://img.shields.io/pypi/v/mbake.svg" alt="PyPI - mbake"/>
    </a>
    <a href="https://github.com/psf/black">
        <img src="https://img.shields.io/badge/code%20style-black-000000.svg" alt="Code style: black"/>
    </a>
    <a href="https://pepy.tech/projects/mbake">
        <img src="https://static.pepy.tech/badge/mbake" alt="PyPI Downloads"/>
    </a>
</div>
<!-- markdownlint-enable MD033 -->

## Features

- **Smart formatting**: Tabs for recipes, consistent spacing, line continuation cleanup
- **Intelligent .PHONY detection**: Automatically identifies and manages phony targets
- **Syntax validation**: Ensures Makefiles are valid before and after formatting
- **Configurable rules**: Customize behavior via `~/.bake.toml`
- **CI/CD ready**: Check mode for automated formatting validation
- **VSCode extension**: Full editor integration available

## Installation

```bash
# Install from PyPI
pip install mbake

# Or install VSCode extension
# Search for "mbake Makefile Formatter" in VSCode Extensions
```

## Quick Start

```bash
# Format a Makefile
mbake format Makefile

# Check if formatting is needed (CI/CD mode)
mbake format --check Makefile

# Validate Makefile syntax
mbake validate Makefile

# Initialize configuration
mbake init
```

## Usage

### Basic Commands

```bash
# Format files
mbake format Makefile                   # Format single file
mbake format --check Makefile           # Check formatting (CI/CD)
mbake format --diff Makefile            # Show changes without modifying

# Validate syntax
mbake validate Makefile                 # Check Makefile syntax with GNU make

# Configuration
mbake init                              # Create config file
mbake config                            # Show current settings
mbake update                            # Update to latest version
```

### Key Options

- `--check`: Check formatting without making changes (perfect for CI/CD)
- `--diff`: Show what changes would be made
- `--backup`: Create backup before formatting
- `--validate`: Validate syntax after formatting
- `--config`: Use custom configuration file

## Configuration

Create a config file with `mbake init`. Key settings:

```toml
[formatter]
# Spacing and formatting
space_around_assignment = true          # CC=gcc to CC = gcc
space_after_colon = true                # myapp.o:myapp.c to myapp.o: myapp.c
normalize_line_continuations = true     # Clean up backslash continuations
remove_trailing_whitespace = true       # Remove trailing spaces
fix_missing_recipe_tabs = true          # Convert spaces to tabs in recipes

# .PHONY management
auto_insert_phony_declarations = false  # Auto-detect and insert .PHONY
group_phony_declarations = false        # Group multiple .PHONY lines
phony_at_top = false                    # Place .PHONY at file top
```

## Smart .PHONY Detection

mbake intelligently detects phony targets by analyzing recipe commands:

```makefile
# These are automatically detected as phony
test:
 npm test

clean:
 rm -f *.o

deploy:
 ssh user@server 'systemctl restart app'

# This creates a file, so it's NOT phony
myapp.o: myapp.c
 gcc -c myapp.c -o myapp.o
```

Enable auto-insertion in your config:

```toml
[formatter]
auto_insert_phony_declarations = true
```

## Examples

### Before and After

```makefile
# Before: Inconsistent spacing and indentation
CC:=gcc
CFLAGS= -Wall -g
SOURCES=main.c \
  utils.c \
    helper.c

all: $(TARGET)
    $(CC) $(CFLAGS) -o $@ $^

clean:
    rm -f *.o
```

<!-- markdownlint-disable MD010 -->
```makefile
# After: Clean, consistent formatting
CC := gcc
CFLAGS = -Wall -g
SOURCES = main.c \
  utils.c \
    helper.c

all: $(TARGET)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f *.o
```
<!-- markdownlint-enable MD010 -->

### Disable Formatting

Use special comments to disable formatting in specific regions:

```makefile
# bake-format off
CUSTOM_FORMAT= \
      1 \
  45678 \
#bake-format on
```

## CI/CD Integration

```yaml
# GitHub Actions example
- name: Check Makefile formatting
  run: |
    pip install mbake
    mbake format --check Makefile
```

Exit codes: `0` (success), `1` (needs formatting), `2` (error)

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

```bash
# Development setup
git clone https://github.com/ebodshojaei/bake.git
cd mbake
pip install -e ".[dev]"
pytest  # Run tests
```

## License

MIT License - see [LICENSE](LICENSE) for details.
