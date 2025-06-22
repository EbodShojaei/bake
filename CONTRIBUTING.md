# Contributing to mbake

We love your input! We want to make contributing to mbake as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## Development Process

We use GitHub to host code, to track issues and feature requests, as well as accept pull requests.

### Pull Requests

1. Fork the repo and create your branch from `main`
2. If you've added code that should be tested, add tests
3. If you've changed APIs, update the documentation
4. Ensure the test suite passes
5. Make sure your code lints
6. Issue that pull request!

### Development Setup

```bash
# Clone your fork
git clone https://github.com/ebodshojaei/bake.git
cd mbake

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=bake --cov-report=html

# Run specific test file
pytest tests/test_bake.py -v

# Run formatting tests
pytest tests/test_comprehensive.py -v
```

### Code Style

We use several tools to maintain code quality:

```bash
# Format code
black bake tests

# Sort imports
ruff check --fix bake tests

# Type checking
mypy bake

# Run all quality checks
pre-commit run --all-files
```

### Adding New Formatting Rules

1. Create a new rule in `bake/core/rules/`
2. Inherit from `FormatterPlugin`
3. Implement the `format` method
4. Add tests in `tests/fixtures/`
5. Update documentation

Example:

```python
from bake.plugins.base import FormatterPlugin, FormatResult

class MyRule(FormatterPlugin):
    def __init__(self):
        super().__init__("my_rule", priority=50)
    
    def format(self, lines: List[str], config: dict) -> FormatResult:
        # Your formatting logic
        return FormatResult(
            lines=modified_lines,
            changed=True,
            errors=[],
            warnings=[]
        )
```

### Testing Your Changes

Always add tests for new functionality:

```bash
# Create test fixtures
mkdir tests/fixtures/my_feature
echo "input content" > tests/fixtures/my_feature/input.mk
echo "expected output" > tests/fixtures/my_feature/expected.mk

# Add test case
# Edit tests/test_comprehensive.py to include your test
```

## Any contributions you make will be under the MIT Software License

In short, when you submit code changes, your submissions are understood to be under the same [MIT License](LICENSE) that covers the project.

## Report bugs using GitHub's issue tracker

We use GitHub issues to track public bugs. Report a bug by [opening a new issue](https://github.com/ebodshojaei/bake/issues).

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

## Feature Requests

We welcome feature requests! Please open an issue with:

- Clear description of the feature
- Why it would be useful
- Example use cases
- Proposed implementation (if you have ideas)

## Code of Conduct

### Our Pledge

We pledge to make participation in our project a harassment-free experience for everyone.

### Our Standards

Examples of behavior that contributes to creating a positive environment include:

- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported by contacting the project team. All complaints will be reviewed and investigated.

## License

By contributing, you agree that your contributions will be licensed under its MIT License.
