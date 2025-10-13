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
        version_str: Version string like '1.2.3', '1.2.3.post1', '1.2.3rc0', or '1.2.3.pre'

    Returns:
        tuple of integers representing version components (including post-release and pre-release)
    """
    try:
        # Handle post-release versions first (e.g., 1.2.3.post1)
        if ".post" in version_str:
            base_version, post_part = version_str.split(".post", 1)
            base_tuple = tuple(map(int, base_version.split(".")))
            post_number = int(post_part)
            # Add the post-release number as an additional component
            # This ensures 1.2.3.post1 > 1.2.3 (which becomes 1.2.3.0 internally)
            return base_tuple + (post_number,)

        # Handle pre-release versions (e.g., 1.2.3rc0, 1.2.3.rc1, 1.2.3-alpha1, 1.2.3-beta2, 1.2.3.pre)
        prerelease_suffixes = ["rc", "alpha", "beta", "a", "b", "pre"]
        for suffix in prerelease_suffixes:
            if suffix in version_str:
                # For pre-release versions, we'll treat them as the base version
                # This is a simplified approach - in a full implementation you might want
                # to handle pre-release ordering more sophisticatedly
                parts = version_str.split(suffix, 1)
                if len(parts) == 2:
                    # Extract just the base version part and clean up any trailing dots
                    version_str = parts[0].rstrip(".")
                    break

        # Parse the base version
        base_tuple = tuple(map(int, version_str.split(".")))
        # Add 0 as the post component for comparison
        return base_tuple + (0,)
    except ValueError as e:
        raise VersionError(f"Invalid version format: {version_str}") from e


def get_pypi_version(
    package_name: str = "mbake", timeout: int = 5, include_prerelease: bool = False
) -> Optional[str]:
    """Get the latest version of a package from PyPI.

    Args:
        package_name: Name of the package to check
        timeout: Request timeout in seconds
        include_prerelease: Whether to include pre-release versions

    Returns:
        Latest version string, or None if unable to fetch
    """
    try:
        url = f"https://pypi.org/pypi/{package_name}/json"
        with urllib.request.urlopen(url, timeout=timeout) as response:
            data = json.loads(response.read().decode())

            if include_prerelease:
                # Get all available versions from releases
                releases = data.get("releases", {})
                if not releases:
                    return None

                # Parse all versions and find the latest
                versions = []
                for version_str in releases:
                    try:
                        parsed = parse_version(version_str)
                        versions.append((parsed, version_str))
                    except VersionError:
                        # Skip invalid versions
                        continue

                if not versions:
                    return None

                # Sort by parsed version and return the latest
                versions.sort(key=lambda x: x[0])
                latest_version: str = versions[-1][1]
                return latest_version
            else:
                # Return only the latest stable version
                version = data["info"]["version"]
                if isinstance(version, str):
                    return version
                return None
    except (urllib.error.URLError, json.JSONDecodeError, KeyError, OSError):
        return None


def check_for_updates(
    package_name: str = "mbake", include_prerelease: bool = False
) -> tuple[bool, Optional[str], str]:
    """Check if there's a newer version available on PyPI.

    Args:
        package_name: Name of the package to check
        include_prerelease: Whether to include pre-release versions

    Returns:
        tuple of (update_available, latest_version, current_version)
    """
    latest_version = get_pypi_version(
        package_name, include_prerelease=include_prerelease
    )

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
        import mbake

        package_path = Path(mbake.__file__).parent
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
