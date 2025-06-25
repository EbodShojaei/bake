"""Tests for version utilities."""

from unittest.mock import MagicMock, patch

import pytest

from bake.utils.version_utils import (
    VersionError,
    check_for_updates,
    get_pypi_version,
    is_development_install,
    parse_version,
)


class TestParseVersion:
    """Test version parsing functionality."""

    def test_simple_version(self):
        """Test parsing simple version numbers."""
        assert parse_version("1.2.3") == (1, 2, 3, 0)
        assert parse_version("0.1.0") == (0, 1, 0, 0)
        assert parse_version("10.20.30") == (10, 20, 30, 0)

    def test_post_version(self):
        """Test parsing version with post suffix."""
        assert parse_version("1.2.3.post1") == (1, 2, 3, 1)
        assert parse_version("1.0.0.post5") == (1, 0, 0, 5)

    def test_post_version_comparison(self):
        """Test that post-release versions are considered newer."""
        base_version = parse_version("1.2.3")
        post_version = parse_version("1.2.3.post1")
        post_version_2 = parse_version("1.2.3.post2")

        assert post_version > base_version
        assert post_version_2 > post_version
        assert post_version_2 > base_version

    def test_invalid_version(self):
        """Test parsing invalid version strings."""
        with pytest.raises(VersionError):
            parse_version("invalid")

        with pytest.raises(VersionError):
            parse_version("1.2.x")


class TestGetPypiVersion:
    """Test PyPI version fetching."""

    @patch("urllib.request.urlopen")
    def test_successful_fetch(self, mock_urlopen):
        """Test successful version fetch from PyPI."""
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"info": {"version": "1.2.3"}}'
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        version = get_pypi_version("test-package")
        assert version == "1.2.3"

    @patch("urllib.request.urlopen")
    def test_network_error(self, mock_urlopen):
        """Test handling of network errors."""
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError("Network error")

        version = get_pypi_version("test-package")
        assert version is None

    @patch("urllib.request.urlopen")
    def test_invalid_json(self, mock_urlopen):
        """Test handling of invalid JSON response."""
        mock_response = MagicMock()
        mock_response.read.return_value = b"invalid json"
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        version = get_pypi_version("test-package")
        assert version is None


class TestCheckForUpdates:
    """Test update checking functionality."""

    @patch("bake.utils.version_utils.get_pypi_version")
    @patch("bake.utils.version_utils.current_version", "1.0.0")
    def test_update_available(self, mock_get_version):
        """Test when update is available."""
        mock_get_version.return_value = "1.1.0"

        update_available, latest, current = check_for_updates()

        assert update_available is True
        assert latest == "1.1.0"
        assert current == "1.0.0"

    @patch("bake.utils.version_utils.get_pypi_version")
    @patch("bake.utils.version_utils.current_version", "1.1.0")
    def test_no_update_needed(self, mock_get_version):
        """Test when no update is needed."""
        mock_get_version.return_value = "1.1.0"

        update_available, latest, current = check_for_updates()

        assert update_available is False
        assert latest == "1.1.0"
        assert current == "1.1.0"

    @patch("bake.utils.version_utils.get_pypi_version")
    @patch("bake.utils.version_utils.current_version", "1.1.0")
    def test_current_newer(self, mock_get_version):
        """Test when current version is newer than PyPI."""
        mock_get_version.return_value = "1.0.0"

        update_available, latest, current = check_for_updates()

        assert update_available is False
        assert latest == "1.0.0"
        assert current == "1.1.0"

    @patch("bake.utils.version_utils.get_pypi_version")
    @patch("bake.utils.version_utils.current_version", "1.0.0")
    def test_network_error(self, mock_get_version):
        """Test handling of network errors."""
        mock_get_version.return_value = None

        update_available, latest, current = check_for_updates()

        assert update_available is False
        assert latest is None
        assert current == "1.0.0"

    @patch("bake.utils.version_utils.get_pypi_version")
    @patch("bake.utils.version_utils.current_version", "1.2.3")
    def test_post_release_update_available(self, mock_get_version):
        """Test that post-release versions are detected as updates."""
        mock_get_version.return_value = "1.2.3.post1"

        update_available, latest, current = check_for_updates()

        assert update_available is True
        assert latest == "1.2.3.post1"
        assert current == "1.2.3"

    @patch("bake.utils.version_utils.get_pypi_version")
    @patch("bake.utils.version_utils.current_version", "1.2.3.post1")
    def test_current_is_post_release(self, mock_get_version):
        """Test when current version is a post-release."""
        mock_get_version.return_value = "1.2.3"

        update_available, latest, current = check_for_updates()

        assert update_available is False
        assert latest == "1.2.3"
        assert current == "1.2.3.post1"


class TestIsDevelopmentInstall:
    """Test development installation detection."""

    @patch("bake.utils.version_utils.get_installed_location")
    def test_development_install_detected(self, mock_get_location):
        """Test detection of development installation."""
        # Mock a path that has pyproject.toml in parent directory
        mock_path = MagicMock()
        mock_path.parent.parent.__truediv__.return_value.exists.return_value = True
        mock_get_location.return_value = mock_path

        result = is_development_install()
        assert isinstance(result, bool)

    @patch("bake.utils.version_utils.get_installed_location")
    def test_no_install_location(self, mock_get_location):
        """Test when installation location cannot be determined."""
        mock_get_location.return_value = None

        result = is_development_install()
        assert result is False
