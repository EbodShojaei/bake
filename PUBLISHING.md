# Publishing Guide for mbake

This document outlines the steps to publish mbake to PyPI, Homebrew, and VSCode Marketplace.

## Prerequisites

1. Ensure all tests pass: `pytest tests/`
2. Ensure package builds: `python -m build`
3. Update version number in `pyproject.toml`
4. Update CHANGELOG.md with release notes
5. Commit all changes and tag the release

## Publishing to PyPI

### Manual Publishing

1. **Build the package:**
   ```bash
   python -m build
   ```

2. **Check the package:**
   ```bash
   twine check dist/*
   ```

3. **Upload to PyPI:**
   ```bash
   twine upload dist/*
   ```

### Automated Publishing (Recommended)

The repository includes GitHub Actions for automatic publishing:

1. **Create a PyPI API token:**
   - Go to https://pypi.org/manage/account/token/
   - Create a new API token with scope limited to this project
   - Copy the token

2. **Add token to GitHub Secrets:**
   - Go to your repository Settings > Secrets and variables > Actions
   - Add new secret: `PYPI_API_TOKEN` with your PyPI token

3. **Create a release:**
   - Go to GitHub repository > Releases > Create a new release
   - Tag version: `v1.0.0` (must match version in pyproject.toml)
   - Release title: `v1.0.0`
   - Describe the changes
   - Publish release

4. **Automatic publishing:**
   - GitHub Actions will automatically build and publish to PyPI
   - Monitor the Actions tab for progress

## Publishing to Homebrew

### Option 1: Homebrew Core (Recommended for popular packages)

1. **Wait for PyPI publication**
2. **Calculate SHA256:**
   ```bash
   curl -sL https://files.pythonhosted.org/packages/source/m/mbake/mbake-1.0.0.tar.gz | shasum -a 256
   ```

3. **Fork homebrew-core:**
   ```bash
   brew tap homebrew/core
   cd $(brew --repo homebrew/core)
   git checkout -b mbake
   ```

4. **Create formula:**
   - Copy `mbake.rb` to `Formula/mbake.rb`
   - Update the SHA256 hash
   - Update the URL to point to PyPI

5. **Test formula:**
   ```bash
   brew install --build-from-source ./Formula/mbake.rb
   brew test mbake
   brew audit --strict mbake
   ```

6. **Submit PR to homebrew-core**

### Option 2: Personal Tap (Easier for initial publication)

1. **Create a homebrew tap repository:**
   ```bash
   git clone https://github.com/ebodshojaei/homebrew-mbake.git
   cd homebrew-mbake
   ```

2. **Add the formula:**
   - Copy `mbake.rb` to `Formula/mbake.rb`
   - Update SHA256 and URLs
   - Commit and push

3. **Users can install with:**
   ```bash
   brew tap ebodshojaei/mbake
   brew install mbake
   ```

## Publishing to VSCode Marketplace

### Prerequisites

1. **Install vsce:**
   ```bash
   npm install -g vsce
   ```

2. **Create publisher account:**
   - Go to https://marketplace.visualstudio.com/manage
   - Create a publisher account
   - Generate a Personal Access Token (PAT)

### Publishing Steps

1. **Navigate to extension directory:**
   ```bash
   cd vscode-mbake-extension
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Update extension version:**
   - Edit `package.json` version field
   - Ensure version matches main package

4. **Package the extension:**
   ```bash
   vsce package
   ```

5. **Login to marketplace:**
   ```bash
   vsce login your-publisher-name
   ```

6. **Publish:**
   ```bash
   vsce publish
   ```

### VSCode Extension Assets

The extension should include:
- `icon.png` - 128x128px icon
- Screenshots in README
- Proper keywords for discoverability

## Release Checklist

### Pre-release
- [ ] All tests pass (`pytest tests/`)
- [ ] Package builds successfully (`python -m build`)
- [ ] Version updated in `pyproject.toml`
- [ ] Version updated in `vscode-mbake-extension/package.json`
- [ ] CHANGELOG.md updated
- [ ] Documentation updated
- [ ] All repository URLs updated in configs

### PyPI Release
- [ ] Package uploaded to PyPI
- [ ] Installation verified: `pip install mbake`
- [ ] Basic functionality tested

### Homebrew Release
- [ ] Formula created/updated
- [ ] SHA256 hash updated
- [ ] Formula tested locally
- [ ] Submitted to appropriate tap

### VSCode Release
- [ ] Extension packaged
- [ ] Extension published to marketplace
- [ ] Extension tested in VS Code

### Post-release
- [ ] GitHub release created with changelog
- [ ] Documentation updated with new version
- [ ] Social media announcement (optional)

## Troubleshooting

### PyPI Issues
- **"File already exists"**: Version already published, increment version
- **"Invalid distribution"**: Check package metadata and structure
- **"Authentication failed"**: Verify API token

### Homebrew Issues
- **Audit failures**: Check formula syntax and dependencies
- **Build failures**: Test locally with `--build-from-source`
- **Hash mismatches**: Recalculate SHA256

### VSCode Issues
- **Package too large**: Check file exclusions in `.vscodeignore`
- **Invalid manifest**: Validate `package.json` schema
- **Authentication issues**: Regenerate PAT token

## Version Management

We follow [Semantic Versioning](https://semver.org/):
- **MAJOR.MINOR.PATCH**
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

Example progression: `1.0.0` → `1.0.1` → `1.1.0` → `2.0.0`

## Support

For publishing issues:
1. Check GitHub Actions logs
2. Review package manager documentation
3. Open an issue in the repository 