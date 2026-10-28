"""Tests that pre-release installs are offered their final release."""

import json
from unittest.mock import MagicMock, patch

import pytest

from mbake.utils.version_utils import check_for_updates, get_pypi_version


def _pypi_response(payload: dict) -> MagicMock:
    response = MagicMock()
    response.read.return_value = json.dumps(payload).encode()
    response.__enter__.return_value = response
    return response


class TestCheckForUpdatesPrerelease:
    """An installed pre-release is offered its final release."""

    @pytest.mark.parametrize("installed", ["1.5.0a1", "1.5.0b2", "1.5.0rc1"])
    def test_final_release_offered_to_prerelease_install(self, installed):
        with (
            patch("mbake.utils.version_utils.current_version", installed),
            patch("mbake.utils.version_utils.get_pypi_version", return_value="1.5.0"),
        ):
            update_available, latest, current = check_for_updates()

        assert update_available is True
        assert latest == "1.5.0"
        assert current == installed

    def test_same_prerelease_is_not_an_update(self):
        with (
            patch("mbake.utils.version_utils.current_version", "1.5.0a1"),
            patch("mbake.utils.version_utils.get_pypi_version", return_value="1.5.0a1"),
        ):
            update_available, _, _ = check_for_updates(include_prerelease=True)

        assert update_available is False

    def test_prerelease_is_not_offered_to_its_final_release(self):
        with (
            patch("mbake.utils.version_utils.current_version", "1.5.0"),
            patch("mbake.utils.version_utils.get_pypi_version", return_value="1.5.0a1"),
        ):
            update_available, _, _ = check_for_updates(include_prerelease=True)

        assert update_available is False

    def test_post_release_install_is_not_offered_the_base_release(self):
        with (
            patch("mbake.utils.version_utils.current_version", "1.5.0.post1"),
            patch("mbake.utils.version_utils.get_pypi_version", return_value="1.5.0"),
        ):
            update_available, _, _ = check_for_updates()

        assert update_available is False


class TestLatestPrereleaseLookup:
    """With pre-releases included, a final release wins over its pre-releases."""

    @pytest.mark.parametrize(
        "order",
        [["1.5.0a1", "1.5.0"], ["1.5.0", "1.5.0a1"]],
        ids=["a1-first", "final-first"],
    )
    def test_final_release_ranks_above_its_prerelease(self, order):
        payload = {"releases": {version: [] for version in order}}
        with patch("urllib.request.urlopen", return_value=_pypi_response(payload)):
            assert get_pypi_version("mbake", include_prerelease=True) == "1.5.0"

    def test_newer_prerelease_still_wins(self):
        payload = {"releases": {"1.4.6": [], "1.5.0a1": []}}
        with patch("urllib.request.urlopen", return_value=_pypi_response(payload)):
            assert get_pypi_version("mbake", include_prerelease=True) == "1.5.0a1"
