# Changelog

All notable changes to this project will be documented in this file.

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

[1.1.1]: https://github.com/ebodshojaei/mbake/releases/tag/v1.1.1
[1.0.0]: https://github.com/ebodshojaei/mbake/releases/tag/v1.0.0
