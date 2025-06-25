"""Version checking and update utilities for mbake."""

import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

from .. import __version__ as current_version


class VersionError(Exception):
    """Raised when there's an error with version operations."""

    pass


def parse_version(version_str: str) -> tuple[int, ...]:
    """Parse a version string into a tuple of integers for comparison.

    Args:
        version_str: Version string like '1.2.3' or '1.2.3.post1'

    Returns:
        tuple of integers representing version components (including post-release)
    """
    try:
        # Split on .post to handle post-release versions
        if ".post" in version_str:
            base_version, post_part = version_str.split(".post", 1)
            base_tuple = tuple(map(int, base_version.split(".")))
            post_number = int(post_part)
            # Add the post-release number as an additional component
            # This ensures 1.2.3.post1 > 1.2.3 (which becomes 1.2.3.0 internally)
            return base_tuple + (post_number,)
        else:
            # For non-post versions, add 0 as the post component for comparison
            base_tuple = tuple(map(int, version_str.split(".")))
            return base_tuple + (0,)
    except ValueError as e:
        raise VersionError(f"Invalid version format: {version_str}") from e


def get_pypi_version(package_name: str = "mbake", timeout: int = 5) -> Optional[str]:
    """Get the latest version of a package from PyPI.

    Args:
        package_name: Name of the package to check
        timeout: Request timeout in seconds

    Returns:
        Latest version string, or None if unable to fetch
    """
    try:
        url = f"https://pypi.org/pypi/{package_name}/json"
        with urllib.request.urlopen(url, timeout=timeout) as response:
            data = json.loads(response.read().decode())
            version = data["info"]["version"]
            if isinstance(version, str):
                return version
            return None
    except (urllib.error.URLError, json.JSONDecodeError, KeyError, OSError):
        return None


def check_for_updates(package_name: str = "mbake") -> tuple[bool, Optional[str], str]:
    """Check if there's a newer version available on PyPI.

    Args:
        package_name: Name of the package to check

    Returns:
        tuple of (update_available, latest_version, current_version)
    """
    latest_version = get_pypi_version(package_name)

    if latest_version is None:
        return False, None, current_version

    try:
        current_parsed = parse_version(current_version)
        latest_parsed = parse_version(latest_version)

        update_available = latest_parsed > current_parsed
        return update_available, latest_version, current_version
    except VersionError:
        return False, latest_version, current_version


def update_package(package_name: str = "mbake", use_pip: bool = True) -> bool:
    """Update the package using pip.

    Args:
        package_name: Name of the package to update
        use_pip: Whether to use pip for updating

    Returns:
        True if update was successful, False otherwise
    """
    if not use_pip:
        raise NotImplementedError("Only pip updates are currently supported")

    try:
        # Use pip to update the package
        cmd = [sys.executable, "-m", "pip", "install", "--upgrade", package_name]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,  # 1 minute timeout for update
        )

        return result.returncode == 0
    except (subprocess.SubprocessError, subprocess.TimeoutExpired):
        return False


def get_installed_location() -> Optional[Path]:
    """Get the installation location of the current package.

    Returns:
        Path to the package installation, or None if not found
    """
    try:
        import bake

        package_path = Path(bake.__file__).parent
        return package_path
    except (ImportError, AttributeError):
        return None


def is_development_install() -> bool:
    """Check if this is a development installation (editable install).

    Returns:
        True if this appears to be a development install
    """
    install_location = get_installed_location()
    if install_location is None:
        return False

    # Check if we're in a development directory structure
    # (presence of pyproject.toml, setup.py, or .git in parent directories)
    current = install_location
    for _ in range(3):  # Check up to 3 levels up
        current = current.parent
        if any(
            (current / file).exists() for file in ["pyproject.toml", "setup.py", ".git"]
        ):
            return True

    return False
