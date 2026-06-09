# 🍞 mbake Makefile Formatter - Complete Installation Guide

This guide covers how to set up both the terminal command and VS Code extension for the mbake Makefile formatter.

## 📦 Terminal Installation

### 1. Package Installation

Install from PyPI:

```bash
pip install mbake
```

### 2. Configuration

Your configuration file is located at `{XDG_CONFIG_HOME}/bake.toml`. It contains sensible defaults for Makefile formatting:

```toml
# Global settings
debug = false
verbose = false

# Error message formatting
gnu_error_format = true
wrap_error_messages = false

[formatter]
# Spacing settings - enable proper spacing
space_around_assignment = true
space_before_colon = false
space_after_colon = true

# Line continuation settings
normalize_line_continuations = true
max_line_length = 120

# PHONY settings
group_phony_declarations = false
phony_at_top = false
auto_insert_phony_declarations = false

# General settings - enable proper formatting
remove_trailing_whitespace = true
ensure_final_newline = true
normalize_empty_lines = true
max_consecutive_empty_lines = 2
fix_missing_recipe_tabs = true

# Conditional formatting settings (Default disabled)
indent_nested_conditionals = false
# Indentation settings
tab_width = 2

# Variable alignment settings
align_variable_assignments = false
align_across_comments = false
```

### 3. Terminal Usage

```bash
# Format a Makefile
bake Makefile

# Check if formatting is needed (non-destructive)
bake --check Makefile

# Show what changes would be made
bake --diff Makefile

# Validate Makefile syntax using GNU make
bake validate Makefile

# Format with verbose output
bake --verbose Makefile

# Format with backup
bake --backup Makefile

# Use custom config
bake --config /path/to/custom.toml Makefile

# Show all options
bake --help
```

### 4. What bake does

The formatter applies these improvements:

- ✅ **Tabs**: Converts spaces to tabs in recipe lines
- ✅ **Assignment spacing**: Normalizes spacing around variable assignments (`CC=gcc` → `CC = gcc`)
- ✅ **Assignment alignment**: Aligns consecutive variable assignments for readability (optional)
- ✅ **Target spacing**: Fixes spacing around colons in targets (`install:$(TARGET)` → `install: $(TARGET)`)
- ✅ **PHONY declarations**: Groups and organizes `.PHONY` declarations
- ✅ **Line continuations**: Normalizes multi-line variable assignments
- ✅ **Whitespace**: Removes trailing whitespace and ensures consistent empty lines
- ✅ **Final newline**: Ensures files end with a newline

## 💻 VS Code Extension Installation

The VS Code extension provides seamless integration with your editor.

### Option A: Install from VSIX (Recommended for Testing)

1. **Package the extension:**

   ```bash
   cd vscode-bake-extension
   npm install -g vsce
   vsce package
   ```

2. **Install the generated VSIX file:**

   ```bash
   code --install-extension bake-makefile-formatter-1.0.0.vsix
   ```

### Option B: Developer Mode

1. **Copy to VS Code extensions directory:**

   ```bash
   # On macOS/Linux:
   cp -r vscode-bake-extension ~/.vscode/extensions/bake-makefile-formatter-1.0.0
   
   # On Windows:
   copy vscode-bake-extension %USERPROFILE%\.vscode\extensions\bake-makefile-formatter-1.0.0
   ```

2. **Restart VS Code**

### 3. Extension Usage

Once installed, the extension provides:

#### Commands

- **Bake: Format Makefile** - Format the current Makefile
- **Bake: Check Makefile Formatting** - Check if formatting is needed

#### Keyboard Shortcuts

- `Shift+Alt+F` - Format the current Makefile (when editing a Makefile)

#### Context Menu

- Right-click in a Makefile and select "Format Makefile" or "Check Makefile Formatting"

#### Format on Save

- Enable `bake.formatOnSave` in VS Code settings to auto-format on save

### 4. Extension Configuration

Access these settings through VS Code preferences (`Cmd/Ctrl + ,`) and search for "bake":

- **`bake.executablePath`**: Path to bake executable (default: `"bake"`)
- **`bake.configPath`**: Path to config file (default: uses `{XDG_CONFIG_HOME}/bake.toml`)
- **`bake.formatOnSave`**: Auto-format on save (default: `false`)
- **`bake.showDiff`**: Show diff when formatting (default: `false`)
- **`bake.verbose`**: Enable verbose output (default: `false`)

#### Example VS Code settings.json

```json
{
    "bake.executablePath": "bake",
    "bake.formatOnSave": true,
    "bake.verbose": false
}
```

## 🧪 Testing

We've created comprehensive tests to verify functionality:

### Simple Functionality Test

```bash
python simple_test.py
```

This test demonstrates:

- ✅ Creating a messy Makefile
- ✅ Running bake formatter
- ✅ Verifying improvements (spacing, tabs, formatting)
- ✅ Showing before/after comparison

### Expected Output

```text
🍞 Simple Bake Functionality Test
==================================================
Original content:
# Test Makefile
CC=gcc
CFLAGS   =   -Wall
all: main
    echo "building"
        gcc -o main main.c
clean:
  rm -f main

Formatted content:
# Test Makefile
CC = gcc
CFLAGS = -Wall
all: main
        echo "building"
                gcc -o main main.c
clean:
        rm -f main

✅ Fixed assignment spacing
✅ Normalized variable assignment
✅ Converted spaces to tabs in recipes
🎉 Bake formatter is working correctly!
```

## 🏗️ Project Structure

```text
bake_fmt/
├── bake/                          # Main Python package
│   ├── cli.py                     # Command-line interface
│   ├── config.py                  # Configuration management
│   ├── core/                      # Core formatting logic
│   └── plugins/                   # Formatting rule plugins
├── tests/                         # Test suite
├── vscode-bake-extension/         # VS Code extension
│   ├── package.json               # Extension manifest
│   ├── extension.js               # Extension logic
│   └── README.md                  # Extension documentation
├── pyproject.toml                 # Python package configuration
├── .bake.toml.example             # Example configuration
└── {XDG_CONFIG_HOME}/bake.toml    # Your configuration file
```

## 🚀 Quick Start Examples

### Example 1: Basic Formatting

```bash
# Create a test Makefile
cat > test.mk << 'EOF'
CC=gcc
all:main
    echo "building"
EOF

# Format it
bake test.mk

# Result:
# CC = gcc
# all: main
#         echo "building"
```

### Example 2: VS Code Integration

1. Open any Makefile in VS Code
2. Press `Shift+Alt+F` or right-click → "Format Makefile"
3. Watch your Makefile get beautifully formatted!

### Example 3: Format on Save

```json
// In VS Code settings.json
{
    "bake.formatOnSave": true
}
```

Now every time you save a Makefile, it's automatically formatted!

## 🔧 Troubleshooting

### Terminal Issues

**"bake command not found":**

- Check if bake is in your PATH: `which bake`
- Reinstall if needed: `pip install -e .`

**Configuration errors:**

- Ensure `{XDG_CONFIG_HOME}/bake.toml` exists and is valid TOML
- Use the provided example: `cp .bake.toml.example ${XDG_CONFIG_HOME}/bake.toml`
  or `cp .bake.toml.example ~/.config/bake.toml`

### VS Code Extension Issues

**Extension not activating:**

- Ensure your file is recognized as a Makefile
- Check the language mode in VS Code's bottom-right corner
- Manually set language to "Makefile" if needed

**Command not found:**

- Set `bake.executablePath` to the full path: `/path/to/bake`
- Verify bake is accessible: open terminal in VS Code and run `bake --help`

## 🎉 You're All Set

Both the terminal command and VS Code extension are now ready to use. The bake formatter will help you maintain clean, consistent, and professional Makefiles across all your projects.

### What's Next?

- Try formatting your existing Makefiles
- Customize the configuration to match your team's style
- Enable format-on-save in VS Code for automatic formatting
- Share the extension with your team!

---

**Happy formatting!** 🍞✨
