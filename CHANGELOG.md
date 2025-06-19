# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2024-01-XX

### Added

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

[1.0.0]: https://github.com/ebodshojaei/mbake/releases/tag/v1.0.0
