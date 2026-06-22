"""Tests for the venv-aware sudo hint helper and the init error path.

Regression coverage for the reported issue where ``sudo nssec init`` fails with
``sudo: nssec: command not found`` when nssec is installed in a virtualenv,
because sudo resets PATH and drops the venv's bin directory.
"""

from unittest.mock import patch

import pytest
from click.testing import CliRunner

from nssec.cli import sudo_hint
from nssec.cli.main import cli


@pytest.fixture
def runner():
    """Click CLI test runner."""
    return CliRunner()


class TestSudoHint:
    """Tests for nssec.cli.sudo_hint."""

    def test_plain_form_outside_venv(self):
        with patch("nssec.cli._running_in_venv", return_value=False):
            assert sudo_hint("init") == "sudo nssec init"

    def test_path_preserving_form_inside_venv(self):
        with patch("nssec.cli._running_in_venv", return_value=True):
            assert sudo_hint("init") == 'sudo env "PATH=$PATH" nssec init'

    def test_empty_command(self):
        with patch("nssec.cli._running_in_venv", return_value=False):
            assert sudo_hint() == "sudo nssec"
        with patch("nssec.cli._running_in_venv", return_value=True):
            assert sudo_hint("") == 'sudo env "PATH=$PATH" nssec'

    def test_normalizes_legacy_full_string(self):
        """Call sites that pass the whole 'sudo nssec ...' hint still work."""
        with patch("nssec.cli._running_in_venv", return_value=False):
            assert sudo_hint("sudo nssec waf enable") == "sudo nssec waf enable"
        with patch("nssec.cli._running_in_venv", return_value=True):
            assert sudo_hint("sudo nssec waf enable") == 'sudo env "PATH=$PATH" nssec waf enable'

    def test_normalizes_bare_nssec_prefix(self):
        with patch("nssec.cli._running_in_venv", return_value=False):
            assert sudo_hint("nssec waf restrict init") == "sudo nssec waf restrict init"

    def test_preserves_placeholders(self):
        with patch("nssec.cli._running_in_venv", return_value=False):
            assert sudo_hint("mtls allowlist add <IP>") == "sudo nssec mtls allowlist add <IP>"


class TestInitPermissionError:
    """The init command must guide the user to a command that actually works."""

    def _invoke_with_permission_error(self, runner):
        with (
            patch("nssec.cli.main.detect_server_type") as detect,
            patch(
                "nssec.core.config.create_default_config",
                side_effect=PermissionError("denied"),
            ),
        ):
            detect.return_value.value = "combo"
            return runner.invoke(cli, ["init"])

    def test_venv_error_shows_path_preserving_command(self, runner):
        with patch("nssec.cli._running_in_venv", return_value=True):
            result = self._invoke_with_permission_error(runner)
        assert 'sudo env "PATH=$PATH" nssec init' in result.output
        # Never tells venv users to run the command that fails for them.
        assert "\n    sudo nssec init" not in result.output

    def test_offers_sudo_free_alternative(self, runner):
        with patch("nssec.cli._running_in_venv", return_value=False):
            result = self._invoke_with_permission_error(runner)
        assert "--config-dir ~/.config/nssec" in result.output
