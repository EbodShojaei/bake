# Changelog

All notable changes to this project will be documented in this file.

## [1.2.4]

<!-- markdownlint-disable MD024 -->
### Added

- Disabling formatting on a piece of code to turn off formatting within a region. This should suppress all changes (See [#26](https://github.com/EbodShojaei/bake/issues/26). Thanks @wsnyder!)
- Resolve `typer` install error (reproduced on version `0.16.0`) (See [#25](https://github.com/EbodShojaei/bake/issues/25). Thanks @Dobatymo!)

## [1.2.3]

<!-- markdownlint-disable MD024 -->
### Added

- Provides error when config is explicitly specified but not found.

### Fixes

- Adaptive indentation for define blocks matches the indentation style within each block (Issue #24).
- Centralized define block tracking, error formatting, and standard rule processing into utility functions.
- Added support for Make patterns: `$< $@, $^ $@, command $@`.
- Improved file vs. phony target identification (Issue #23).
  - Avoids assumptions (e.g., removing hard-coded extensions).
  - Variable references (e.g., `$(foo)`) are not incorrectly marked as .PHONY.
- Avoids comment interference when parsing (Issue #24).

## [1.2.2]

<!-- markdownlint-disable MD024 -->
### Fixes

- Nested if indentations correctly resolved (Issue #17).
- Indentations for directives corrected (Issue #12).
- Resolve hang on long lines (Issue #6).

## [1.2.1]

### Added

- GNU Standard Error Format: Error messages now include filename and line numbers for IDE integration
  - Format: `filename:line: Error: message`
  - Configurable via `gnu_error_format = true/false` (default: true)
- Configurable Error Message Line Wrapping: Control line wrapping for better IDE compatibility
  - `wrap_error_messages = false` (default) prevents line wrapping that interferes with IDE parsing
  - Can be enabled for terminal-friendly wrapped output

### Changed

- The != operator is correctly preserved as !=
  - No unwanted space insertion in shell comparison operators
  - Regular Make assignments still get proper spacing
- Place .PHONY after file header but before section comments
- Conditional targets properly excluded
  - default and build targets inside conditionals are no longer included in .PHONY
- Non-conditional targets properly included (clean, install, test targets outside conditionals)
- Normalized tab indentation for consistency in edge-cases (e.g., mixed tabs+spaces)
- Added `context` param to `format` method in `base.py` for passing references to any rule (e.g., original .mk content)

## [1.1.3]

<!-- markdownlint-disable MD024 -->
### Added

- Version checking and update functionality
  - `bake update --check` flag to check for newer versions on PyPI
  - `bake update` command to update mbake to the latest version
  - Automatic update notification when using `bake --version`
  - Development installation detection to prevent update conflicts
  - Support for both pip-based installations and development setups

### Changed

- Version callback now includes update availability information
- Version synchronization between `__init__.py` and `pyproject.toml`

### Technical

- New `version_utils.py` module with comprehensive version management
- Unit tests for version checking functionality
- Enhanced error handling for network-related version operations

## [1.1.1]

- **Smart .PHONY Detection**: Intelligent automatic detection and insertion of `.PHONY` declarations
  - Dynamic analysis of recipe commands to determine if targets are phony
  - Rule-based detection without hardcoded target lists
  - Supports modern development workflows (Docker, npm, build tools)
  - Opt-in via `auto_insert_phony_declarations = true` configuration
- **Enhanced .PHONY Management**:
  - Automatic enhancement of existing `.PHONY` declarations with detected targets
  - Preserves backwards compatibility with conservative default behavior
  - Sophisticated command analysis for accurate file creation detection

### Improved

- **DRY Code Architecture**: Refactored phony-related rules to use centralized utilities
  - New `MakefileParser` class for target parsing
  - New `PhonyAnalyzer` class for phony target analysis  
  - Reduced code duplication by 52% (359 lines eliminated)
  - Improved maintainability and testability
- **Detection Accuracy**: Fixed variable cleaning bug in command analysis
- **Documentation**: Updated README with comprehensive Smart .PHONY Detection section

<!-- markdownlint-disable MD024 -->
### Technical

- **Separated Concerns**: Split phony functionality into focused plugins:
  - `PhonyRule`: Groups existing `.PHONY` declarations (original behavior)
  - `PhonyInsertionRule`: Auto-inserts `.PHONY` when missing
  - `PhonyDetectionRule`: Enhances existing `.PHONY` with detected targets
- **Comprehensive Testing**: Added 12 new auto-insertion specific tests
- **Edge Case Coverage**: Handles Docker targets, compilation patterns, shell commands

## [1.0.0]

- **Core Formatting Engine**: Complete Makefile formatter with rule-based architecture
- **Command Line Interface**: Rich CLI with Typer framework
- **Configuration System**: TOML-based configuration with `~/.bake.toml`
- **Comprehensive Formatting Rules**:
  - Tab indentation for recipes
  - Assignment operator spacing normalization
  - Target spacing consistency
  - Line continuation handling
  - .PHONY declaration grouping and placement
  - Whitespace normalization
  - Shell command formatting within recipes
- **Execution Validation**: Ensures formatted Makefiles execute correctly
- **CI/CD Integration**: Check mode for continuous integration
- **Plugin Architecture**: Extensible rule system for custom formatting
- **VSCode Extension**: Full VSCode integration with formatting commands
- **Rich Terminal Output**: Beautiful CLI with colors and progress indicators
- **Backup Support**: Optional backup creation before formatting
- **Comprehensive Test Suite**: 100% test coverage with 39 test cases
- **Cross-Platform Support**: Windows, macOS, and Linux compatibility
- **Python Version Support**: Python 3.9+ compatibility

### Features

- **Smart Formatting**: Preserves Makefile semantics while improving readability
- **Configuration Options**:
  - Customizable tab width
  - Assignment operator spacing
  - Line continuation behavior
  - .PHONY placement preferences
  - Whitespace handling rules
- **Multiple Output Modes**:
  - In-place formatting (default)
  - Check-only mode for CI/CD
  - Diff preview mode
  - Verbose and debug output options
- **Robust Error Handling**: Clear error messages and validation
- **Fast Performance**: Optimized for large Makefiles

### Documentation

- **Comprehensive README**: Installation, usage, and examples
- **Installation Guide**: Multi-platform installation instructions
- **Contributing Guide**: Development setup and contribution workflow
- **Publishing Guide**: Complete publication workflow for all platforms
- **Configuration Examples**: Sample configuration files
- **API Documentation**: Plugin development guide

### Package Distribution

- **PyPI Package**: `pip install mbake`
- **Homebrew Formula**: Ready for Homebrew publication
- **VSCode Extension**: Ready for Visual Studio Code Marketplace
- **GitHub Actions**: Automated CI/CD and publishing workflows

[1.2.4]: https://github.com/ebodshojaei/bake/releases/tag/v1.2.4
[1.2.3]: https://github.com/ebodshojaei/bake/releases/tag/v1.2.3
[1.2.2]: https://github.com/ebodshojaei/bake/releases/tag/v1.2.2
[1.2.1]: https://github.com/ebodshojaei/bake/releases/tag/v1.2.1
[1.1.3]: https://github.com/ebodshojaei/bake/releases/tag/v1.1.3
[1.1.1]: https://github.com/ebodshojaei/bake/releases/tag/v1.1.1
[1.0.0]: https://github.com/ebodshojaei/bake/releases/tag/v1.0.0
