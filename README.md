# 🍞 mbake

A **Python-based Makefile formatter and linter** that enforces consistent formatting according to Makefile best practices. It only took 50 years!

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![PyPI - mbake](https://img.shields.io/pypi/v/mbake.svg)](https://pypi.org/project/mbake/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## ✨ Features

- **🔧 Comprehensive Formatting**: Automatically formats Makefiles according to community best practices
- **📋 Configurable Rules**: Customize formatting behavior via `~/.bake.toml`
- **🚦 CI/CD Integration**: Check mode for continuous integration pipelines
- **🔌 Plugin Architecture**: Extensible rule system for custom formatting needs
- **🎨 Beautiful CLI**: Rich terminal output with colors and progress indicators
- **⚡ Fast & Reliable**: Written in Python with comprehensive test coverage
- **✅ Syntax Validation**: Ensures Makefiles have correct syntax before and after formatting
- **🔄 Shell Completion**: Auto-completion support for bash, zsh, and fish
- **🎯 Smart .PHONY Detection**: Automatically inserts and enhances `.PHONY` declarations using dynamic analysis

## 🛠️ Formatting Rules

mbake applies the following formatting rules:

### Indentation & Spacing

- **Tabs for recipes**: Ensures all recipe lines use tabs instead of spaces
- **Assignment operators**: Normalizes spacing around `:=`, `=`, `+=`, `?=`
- **Target colons**: Consistent spacing around target dependency colons
- **Trailing whitespace**: Removes unnecessary trailing spaces

### Line Continuations

- **Backslash normalization**: Proper spacing around backslash continuations
- **Smart joining**: Consolidates simple continuations while preserving complex structures

### .PHONY Declarations

- **Grouping**: Consolidates multiple `.PHONY` declarations
- **Auto-insertion**: Automatically detects and inserts `.PHONY` declarations when missing (opt-in)
- **Dynamic enhancement**: Enhances existing `.PHONY` declarations with additional detected phony targets
- **Rule-based analysis**: Uses command analysis to determine if targets are phony (no hardcoded lists)
- **Minimal changes**: Only modifies `.PHONY` lines, preserves file structure

## 📦 Installation

### Option 1: PyPI (Recommended)

```bash
pip install mbake
```

### Option 2: VSCode Extension

1. Open VSCode
2. Go to Extensions (Ctrl+Shift+X)
3. Search for "mbake Makefile Formatter"
4. Click Install

### Option 3: From Source

```bash
git clone https://github.com/ebodshojaei/mbake.git
cd mbake
pip install -e .
```

### Development Installation

```bash
git clone https://github.com/ebodshojaei/mbake.git
cd mbake
pip install -e ".[dev]"
```

## 🚀 Usage

mbake uses a subcommand-based CLI structure. All commands support both `bake` and `mbake` aliases.

### Quick Start

```bash
# Check version
bake --version

# Initialize configuration (optional)
bake init

# Format a Makefile
bake format Makefile

# Validate Makefile syntax
bake validate Makefile
```

### Configuration Management

```bash
# Initialize configuration file with defaults
bake init

# Initialize with custom path or force overwrite
bake init --config /path/to/config.toml --force

# Show current configuration
bake config

# Show configuration file path
bake config --path

# Use custom configuration file
bake config --config /path/to/config.toml
```

### Formatting Files

```bash
# Format a single Makefile
bake format Makefile

# Format multiple files
bake format Makefile src/Makefile tests/*.mk

# Check if files need formatting (CI/CD mode)
bake format --check Makefile

# Show diff of changes without modifying files
bake format --diff Makefile

# Format with verbose output
bake format --verbose Makefile

# Create backup before formatting
bake format --backup Makefile

# Validate syntax after formatting
bake format --validate Makefile

# Use custom configuration
bake format --config /path/to/config.toml Makefile
```

### Syntax Validation

```bash
# Validate single file
bake validate Makefile

# Validate multiple files
bake validate Makefile src/Makefile tests/*.mk

# Validate with verbose output
bake validate --verbose Makefile

# Use custom configuration
bake validate --config /path/to/config.toml Makefile
```

### Shell Completion

```bash
# Install completion for current shell
bake --install-completion

# Show completion script (for manual installation)
bake --show-completion
```

## ⚙️ Configuration

mbake works with sensible defaults out-of-the-box. Generate a configuration file with:

```bash
bake init
```

### Sample Configuration

```toml
[formatter]
# Indentation settings
use_tabs = true
tab_width = 4

# Spacing settings
space_around_assignment = true
space_before_colon = false
space_after_colon = true

# Line continuation settings
normalize_line_continuations = true
max_line_length = 120

# PHONY settings
group_phony_declarations = true
phony_at_top = true
auto_insert_phony_declarations = false  # Enable to auto-insert .PHONY declarations

# General settings
remove_trailing_whitespace = true
ensure_final_newline = true
normalize_empty_lines = true
max_consecutive_empty_lines = 2

# Global settings
debug = false
verbose = false
```

## 🎯 Smart .PHONY Detection

mbake includes intelligent `.PHONY` detection that can automatically identify and manage phony targets in your Makefiles.

### How It Works

The detection uses **dynamic analysis** of recipe commands rather than hardcoded target names:

- **Command Analysis**: Examines what each target's recipe actually does
- **File Creation Detection**: Identifies if commands create files with the target name
- **Pattern Recognition**: Understands compilation patterns, redirections, and common tools

### Examples

#### Docker/Container Targets

```makefile
# These are detected as phony because they manage containers, not files
up:
 docker compose up -d

down:
 docker compose down -v

logs:
 docker compose logs -f
```

#### Build/Development Targets  

```makefile
# These are detected as phony because they don't create files with their names
test:
 npm test

lint:
 eslint src/

deploy:
 ssh user@server 'systemctl restart myapp'
```

#### File vs Phony Target Detection

```makefile
# NOT phony - creates myapp.o file
myapp.o: myapp.c
 gcc -c myapp.c -o myapp.o

# Phony - removes files, doesn't create "clean"
clean:
 rm -f *.o myapp
```

### Configuration

Enable auto-insertion in your `~/.bake.toml`:

```toml
[formatter]
auto_insert_phony_declarations = true
```

### Behavior Modes

**Default (Conservative)**:

- Groups existing `.PHONY` declarations
- No automatic insertion or enhancement
- Backwards compatible

**Enhanced (auto_insert_phony_declarations = true)**:

- Automatically inserts `.PHONY` when missing
- Enhances existing `.PHONY` with detected targets
- Uses dynamic analysis for accurate detection

### Before and After

**Input** (no `.PHONY`):

```makefile
setup:
 docker compose up -d
 npm install

test:
 npm test

clean:
 docker compose down -v
 rm -rf node_modules
```

**Output** (with auto-insertion enabled):

```makefile
.PHONY: clean setup test

setup:
 docker compose up -d
 npm install

test:
 npm test

clean:
 docker compose down -v
 rm -rf node_modules
```

## 🔧 Examples

### Basic Formatting

**Before Formatting:**

```makefile
# Inconsistent spacing and indentation
CC:=gcc
CFLAGS= -Wall -g
SOURCES=main.c \
  utils.c \
    helper.c

.PHONY: clean
all: $(TARGET)
    $(CC) $(CFLAGS) -o $@ $^

.PHONY: install
clean:
    rm -f *.o
```

**After Formatting:**

```makefile
# Clean, consistent formatting
CC := gcc
CFLAGS = -Wall -g
SOURCES = main.c utils.c helper.c

.PHONY: all clean install

all: $(TARGET)
 $(CC) $(CFLAGS) -o $@ $^

clean:
 rm -f *.o
```

### Auto-Insertion Example

**Before** (with `auto_insert_phony_declarations = true`):

```makefile
# Docker development workflow
setup:
 docker compose down -v
 docker compose up -d
 @echo "Services ready!"

build:
 docker compose build --no-cache

test:
 docker compose exec app npm test

clean:
 docker compose down -v
 docker system prune -af
```

**After**:

```makefile
# Docker development workflow
.PHONY: build clean setup test

setup:
 docker compose down -v
 docker compose up -d
 @echo "Services ready!"

build:
 docker compose build --no-cache

test:
 docker compose exec app npm test

clean:
 docker compose down -v
 docker system prune -af
```

## 🚦 CI/CD Integration

Use mbake in your continuous integration pipelines:

```yaml
# GitHub Actions example
- name: Check Makefile formatting
  run: |
    pip install mbake
    bake format --check Makefile
```

```bash
# Exit codes:
# 0 - No formatting needed or formatting successful
# 1 - Files need formatting (--check mode) or validation failed
# 2 - Error occurred
```

## 🧪 Development

### Setup

```bash
git clone https://github.com/ebodshojaei/mbake.git
cd mbake
pip install -e ".[dev]"
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=bake --cov-report=html

# Run specific test file
pytest tests/test_formatter.py -v
```

### Code Quality

```bash
# Format code
black bake tests

# Lint code
ruff check bake tests

# Type checking
mypy bake
```

## 🏗️ Architecture

mbake follows a modular, plugin-based architecture:

```text
bake/
├── __init__.py          # Package initialization
├── cli.py               # Command-line interface with subcommands
├── config.py            # Configuration management
├── core/
│   ├── formatter.py     # Main formatting engine
│   └── rules/           # Individual formatting rules
│       ├── tabs.py      # Tab/indentation handling
│       ├── spacing.py   # Spacing normalization
│       ├── continuation.py # Line continuation formatting
│       └── phony.py     # .PHONY declaration management
└── plugins/
    └── base.py          # Plugin interface
```

### Adding Custom Rules

Extend the `FormatterPlugin` base class:

```python
from bake.plugins.base import FormatterPlugin, FormatResult

class MyCustomRule(FormatterPlugin):
    def __init__(self):
        super().__init__("my_rule", priority=50)
    
    def format(self, lines: List[str], config: dict) -> FormatResult:
        # Your formatting logic here
        return FormatResult(
            lines=modified_lines,
            changed=True,
            errors=[],
            warnings=[]
        )
```

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on:

- Code of conduct
- Development process
- Submitting pull requests
- Reporting issues

### Quick Start for Contributors

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Run the test suite (`pytest`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📊 Project Status

- ✅ **Core formatting engine** (100% test coverage)
- ✅ **Configuration system**
- ✅ **Command-line interface with subcommands**
- ✅ **Plugin architecture**
- ✅ **Assignment spacing normalization**
- ✅ **Tab indentation handling**
- ✅ **Whitespace management**
- ✅ **Line continuation formatting**
- ✅ **Smart .PHONY detection and auto-insertion**
- ✅ **Makefile syntax validation**
- ✅ **Shell completion support**
- ✅ **CI/CD integration**
- 🚧 Advanced rule customization
- 🚧 IDE integrations

## 🎯 Design Philosophy

- **Minimal changes**: Only modify what needs to be fixed, preserve file structure
- **Predictable behavior**: Consistent formatting rules across all Makefiles
- **Fast execution**: Efficient processing of large Makefiles
- **Reliable validation**: Ensure formatted Makefiles have correct syntax
- **Developer-friendly**: Rich CLI with helpful error messages and progress indicators

This approach ensures a **reliable, maintainable formatter** that handles common Makefile formatting needs while preserving the structure and functionality of your build files.
