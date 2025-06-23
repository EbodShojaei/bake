# mbake Makefile Formatter - VS Code Extension

A VS Code extension that integrates the [mbake](https://github.com/ebodshojaei/bake) Makefile formatter directly into your editor.

## Features

- **Format Makefiles**: Format your Makefiles according to best practices with a single command or keyboard shortcut
- **Check Formatting**: Verify if your Makefiles are properly formatted without making changes
- **Format on Save**: Automatically format Makefiles when you save them (optional)
- **Right-click Context Menu**: Access formatting commands directly from the editor context menu
- **Command Palette**: Run mbake commands from the VS Code command palette
- **Configurable**: Customize mbake settings through VS Code preferences

## Requirements

- **mbake** must be installed and available in your system PATH
- Alternatively, you can specify a custom path to the bake executable in the extension settings

### Installing mbake

```bash
# Install mbake using pip
pip install mbake

# Or install from source
git clone https://github.com/ebodshojaei/bake.git
cd mbake
pip install -e .
```

## Quick Start

1. Install the extension
2. Open a Makefile in VS Code
3. Right-click and select "Format Makefile" or use `Shift+Alt+F`

## Commands

- **mbake: Format Makefile** (`mbake.formatMakefile`) - Format the current Makefile
- **mbake: Check Makefile Formatting** (`mbake.checkMakefile`) - Check if the current Makefile needs formatting

## Keyboard Shortcuts

- `Shift+Alt+F` - Format the current Makefile (when editing a Makefile)

## Configuration

Access these settings through VS Code's settings (`Cmd/Ctrl + ,`) and search for "mbake":

### `mbake.executablePath`

- **Type**: `string`
- **Default**: `"bake"`
- **Description**: Path to the bake executable. Use 'bake' if it's in your PATH, or provide the full path.

### `mbake.configPath`

- **Type**: `string`
- **Default**: `""`
- **Description**: Path to the bake configuration file. Leave empty to use default (~/.bake.toml).

### `mbake.formatOnSave`

- **Type**: `boolean`
- **Default**: `false`
- **Description**: Automatically format Makefiles on save.

### `mbake.showDiff`

- **Type**: `boolean`
- **Default**: `false`
- **Description**: Show diff of changes when formatting.

### `mbake.verbose`

- **Type**: `boolean`
- **Default**: `false`
- **Description**: Enable verbose output.

## Configuration Example

Add these settings to your VS Code `settings.json`:

```json
{
    "mbake.executablePath": "/usr/local/bin/bake",
    "mbake.configPath": "/path/to/your/.bake.toml",
    "mbake.formatOnSave": true,
    "mbake.verbose": true,
    "mbake.showDiff": false
}
```

## Supported File Types

The extension automatically activates for:

- Files with `.mk` or `.make` extensions
- Files named `Makefile`, `makefile`, or `GNUmakefile`
- Files with the `makefile` language ID

## Usage

### Format a Makefile

1. **Using keyboard shortcut**: Press `Shift+Alt+F` while editing a Makefile
2. **Using command palette**: Press `Cmd/Ctrl+Shift+P` and type "mbake: Format Makefile"
3. **Using context menu**: Right-click in the editor and select "Format Makefile"
4. **Using format document**: Press `Shift+Alt+F` or `Cmd/Ctrl+Shift+I`

### Check Makefile Formatting

1. **Using command palette**: Press `Cmd/Ctrl+Shift+P` and type "mbake: Check Makefile Formatting"
2. **Using context menu**: Right-click in the editor and select "Check Makefile Formatting"

### Format on Save

Enable the `mbake.formatOnSave` setting to automatically format Makefiles when you save them.

## What mbake does

The mbake formatter applies these improvements to your Makefiles:

- **Tabs**: Converts spaces to tabs in recipe lines
- **Assignment spacing**: Normalizes spacing around variable assignments
- **Target spacing**: Fixes spacing around colons in targets
- **PHONY declarations**: Groups and organizes .PHONY declarations
- **Line continuations**: Normalizes multi-line variable assignments
- **Whitespace**: Removes trailing whitespace and ensures consistent empty lines
- **Final newline**: Ensures files end with a newline
- **Error formatting**: Provides GNU standard error format for perfect

## Troubleshooting

### "bake command not found"

Make sure mbake is installed and available in your PATH, or set the full path in `mbake.executablePath`.

```bash
# Check if mbake is installed
which bake
bake --help
```

### Configuration file not found

If you see errors about missing configuration files, either:

1. Create a `~/.bake.toml` configuration file
2. Set a custom path in `mbake.configPath`
3. Use the example configuration provided in the mbake repository

### Extension not activating

Make sure your file is recognized as a Makefile:

1. Check the language mode in the bottom-right corner of VS Code
2. Manually set the language to "Makefile" if needed
3. Ensure your file has the correct name or extension

## Example Configuration File

Create `~/.bake.toml` with these contents:

```toml
# Global settings
debug = false
verbose = false

# Error message formatting
gnu_error_format = true         # Use GNU standard error format (file:line: Error: message)
wrap_error_messages = false     # Wrap long error messages (can interfere with IDE parsing)

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
fix_missing_recipe_tabs = true
```

## Contributing

Found a bug or want to contribute? Visit the [GitHub repository](https://github.com/ebodshojaei/bake).

## License

This extension is licensed under the MIT License. See the LICENSE file for details.
