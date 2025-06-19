# mbake

A **Python-based Makefile formatter and linter** that enforces consistent formatting according to Makefile best practices. It only took 50 years!

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![PyPI - mbake](https://img.shields.io/pypi/v/mbake.svg)](https://pypi.org/project/mbake/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Downloads](https://img.shields.io/pypi/dm/mbake.svg)](https://pypi.org/project/mbake/)

## ✨ Features

- **🔧 Comprehensive Formatting**: Automatically formats Makefiles according to community best practices
- **📋 Configurable Rules**: Customize formatting behavior via `~/.bake.toml`
- **🚦 CI/CD Integration**: Check mode for continuous integration pipelines
- **🔌 Plugin Architecture**: Extensible rule system for custom formatting needs
- **🎨 Beautiful CLI**: Rich terminal output with colors and progress indicators
- **⚡ Fast & Reliable**: Written in Python with comprehensive test coverage (100% pass rate)
- **✅ Execution Validated**: Ensures formatted Makefiles run correctly with proper cleanup

## 🛠️ Formatting Rules

bake applies the following formatting rules:

### Indentation

- **Tabs for recipes**: Ensures all recipe lines use tabs instead of spaces
- **Configurable tab width**: Customize tab-to-space conversion (default: 4)

### Spacing

- **Assignment operators**: Normalizes spacing around `:=`, `=`, `+=`, `?=`
- **Target colons**: Consistent spacing around target dependency colons
- **Trailing whitespace**: Removes unnecessary trailing spaces

### Line Continuations

- **Backslash normalization**: Proper spacing around backslash continuations
- **Smart joining**: Consolidates simple continuations while preserving complex structures
- **Multi-line formatting**: Clean alignment of continuation lines

### .PHONY Declarations

- **Grouping**: Consolidates multiple `.PHONY` declarations
- **Placement**: Configurable positioning (top of file or near targets)
- **Sorting**: Alphabetical ordering of PHONY targets

## 📦 Installation

### Option 1: PyPI (Recommended)

```bash
pip install mbake
```

### Option 2: Homebrew (macOS/Linux)

```bash
brew tap ebodshojaei/mbake
brew install mbake
```

### Option 3: VSCode Extension

1. Open VSCode
2. Go to Extensions (Ctrl+Shift+X)
3. Search for "mbake Makefile Formatter"
4. Click Install

### Option 4: From Source

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

## ⚙️ Configuration

bake can work with default settings out-of-the-box, but you can customize it with a configuration file. Generate one with:

```bash
bake init
```

If no configuration file exists, bake will use sensible defaults and continue working. You can also view your current configuration:

```bash
# Show current configuration
bake config

# Show config file path
bake config --path
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

# General settings
remove_trailing_whitespace = true
ensure_final_newline = true
normalize_empty_lines = true
max_consecutive_empty_lines = 2

# Global settings
debug = false
verbose = false
```

## 🚀 Usage

### Format Files

```bash
# Format a single Makefile
bake Makefile

# Format multiple files
bake Makefile src/Makefile tests/*.mk

# Format with verbose output
bake --verbose Makefile

# Create backup before formatting
bake --backup Makefile

# Format in-place (default behavior)
bake Makefile
```

### Check Mode (CI/CD)

```bash
# Check if files need formatting (exit code 1 if changes needed)
bake --check Makefile

# Dry run to see what changes would be made
bake --diff Makefile
```

### Validation & Testing

```bash
# Validate Makefile syntax after formatting
bake format --validate Makefile

# Check Makefile syntax separately
bake validate Makefile

# Get improved timestamps for backups
bake format --backup Makefile
```

### Configuration Management

```bash
# Initialize configuration file with defaults
bake init

# Show current configuration
bake config

# Show configuration file path
bake config --path

# Use custom configuration file
bake format --config /path/to/config.toml Makefile
```

## 🔧 Examples

### Before Formatting

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

### After Formatting

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

## ✅ Execution Validation

bake ensures that formatted Makefiles not only look good but also **execute correctly**:

### Validation Features

- **Syntax verification**: Ensures make can parse the formatted file
- **Target execution**: Tests that common targets (build, clean, test) work
- **Cleanup verification**: Confirms temporary files are properly cleaned up
- **Error handling**: Reports any execution issues with clear diagnostics

### Temporary File Management

```bash
# bake automatically manages temporary files in ./temp/ subdirectory
# All test artifacts are cleaned up after validation
bake --test Makefile  # Creates temp/, runs tests, cleans up temp/

# Manual cleanup if needed
rm -rf ./temp/
```

### Integration Testing

```makefile
# Example Makefile that bake validates
TARGET = hello
TEMP_DIR = ./temp

.PHONY: all clean test

all: $(TARGET)
 $(CC) -o $(TARGET) main.c

test: $(TARGET)
 mkdir -p $(TEMP_DIR)
 ./$(TARGET) > $(TEMP_DIR)/output.txt
 @echo "Test completed"

clean:
 rm -f $(TARGET) *.o
 rm -rf $(TEMP_DIR)
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

# Test makefile execution
pytest tests/test_bake.py -v
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

bake follows a modular, plugin-based architecture:

```
bake/
├── __init__.py          # Package initialization
├── cli.py               # Command-line interface
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
- ✅ **Command-line interface**
- ✅ **Plugin architecture**
- ✅ **Assignment spacing normalization**
- ✅ **Tab indentation handling**
- ✅ **Whitespace management**
- ✅ **Line continuation formatting**
- ✅ **Makefile execution validation**
- ✅ **Temporary file cleanup**
- 🚧 Advanced rule customization
- 🚧 IDE integrations
- 📋 Additional output formats (JSON, XML)

## 🎯 Design Philosophy

- ✅ **Consistent core functionality** over edge case perfection
- ✅ **Predictable behavior** over complex configuration
- ✅ **Maintainable codebase** over comprehensive feature coverage
- ✅ **Fast execution** over handling every possible Makefile variant
- ✅ **Execution validation** ensuring formatted files actually work

This approach ensures a **reliable, maintainable formatter** that handles **100% of tested use cases** perfectly, with execution validation to guarantee that formatted Makefiles not only look good but also run correctly with proper cleanup.
