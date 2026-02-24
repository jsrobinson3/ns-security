"""Tests for WAF CLI commands."""

import pytest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

from nssec.cli.waf_commands import waf


@pytest.fixture
def runner():
    """Click CLI test runner."""
    return CliRunner()


@pytest.fixture
def mock_installer():
    """Mock ModSecurityInstaller for CLI tests."""
    with patch("nssec.modules.waf.ModSecurityInstaller") as mock_class:
        installer = MagicMock()
        mock_class.return_value = installer

        # Default preflight result
        pf = MagicMock()
        pf.is_root = True
        pf.modsec_installed = True
        pf.modsec_enabled = True
        pf.modsec_mode = "On"
        installer.preflight.return_value = pf

        # Default step result
        step = MagicMock()
        step.success = True
        step.message = "Success"
        installer.set_mode.return_value = step
        installer.validate_config.return_value = step
        installer.reload_apache.return_value = step

        yield installer


class TestWafDisable:
    """Tests for waf disable command."""

    def test_switches_to_detectiononly(self, runner, mock_installer):
        """Should switch to DetectionOnly mode."""
        result = runner.invoke(waf, ["disable", "-y"])

        assert result.exit_code == 0
        mock_installer.set_mode.assert_called_once_with("DetectionOnly")

    def test_skips_if_already_detectiononly(self, runner, mock_installer):
        """Should skip if already in DetectionOnly mode."""
        mock_installer.preflight.return_value.modsec_mode = "DetectionOnly"

        result = runner.invoke(waf, ["disable", "-y"])

        assert result.exit_code == 0
        assert "already in DetectionOnly" in result.output
        mock_installer.set_mode.assert_not_called()

    def test_requires_root(self, runner, mock_installer):
        """Should fail if not root."""
        mock_installer.preflight.return_value.is_root = False

        result = runner.invoke(waf, ["disable", "-y"])

        assert result.exit_code == 1
        assert "root" in result.output.lower()

    def test_requires_modsec_installed(self, runner, mock_installer):
        """Should fail if ModSecurity not installed."""
        mock_installer.preflight.return_value.modsec_installed = False

        result = runner.invoke(waf, ["disable", "-y"])

        assert result.exit_code == 1
        assert "not installed" in result.output.lower()

    def test_prompts_without_yes_flag(self, runner, mock_installer):
        """Should prompt for confirmation without -y flag."""
        result = runner.invoke(waf, ["disable"], input="n\n")

        assert "Aborted" in result.output
        mock_installer.set_mode.assert_not_called()


class TestWafRemove:
    """Tests for waf remove command."""

    def test_disables_security2_module(self, runner):
        """Should disable security2 Apache module."""
        with patch("nssec.core.ssh.is_root", return_value=True), \
             patch("nssec.modules.waf.utils.file_exists", return_value=True), \
             patch("nssec.modules.waf.utils.run_cmd") as mock_run:
            mock_run.return_value = ("", "", 0)

            result = runner.invoke(waf, ["remove", "-y"])

            assert result.exit_code == 0
            # Check a2dismod was called
            calls = [str(c) for c in mock_run.call_args_list]
            assert any("a2dismod" in c for c in calls)

    def test_skips_if_already_disabled(self, runner):
        """Should skip if module already disabled."""
        with patch("nssec.core.ssh.is_root", return_value=True), \
             patch("nssec.modules.waf.utils.file_exists", return_value=False):
            result = runner.invoke(waf, ["remove", "-y"])

            assert result.exit_code == 0
            assert "already disabled" in result.output

    def test_requires_root(self, runner):
        """Should fail if not root."""
        with patch("nssec.core.ssh.is_root", return_value=False):
            result = runner.invoke(waf, ["remove", "-y"])

            assert result.exit_code == 1
            assert "root" in result.output.lower()

    def test_prompts_without_yes_flag(self, runner):
        """Should prompt for confirmation without -y flag."""
        with patch("nssec.core.ssh.is_root", return_value=True), \
             patch("nssec.modules.waf.utils.file_exists", return_value=True):
            result = runner.invoke(waf, ["remove"], input="n\n")

            assert "Aborted" in result.output


class TestWafAllowlistAdd:
    """Tests for waf allowlist add command."""

    def test_adds_ip_to_allowlist(self, runner, mock_installer):
        """Should add IP to allowlist."""
        with patch("nssec.modules.waf.get_allowlisted_ips", return_value=[]), \
             patch("nssec.modules.waf.add_allowlisted_ip") as mock_add:
            mock_add.return_value = MagicMock(success=True, message="Added")

            result = runner.invoke(waf, ["allowlist", "add", "192.168.1.100", "-y"])

            assert result.exit_code == 0
            mock_add.assert_called_once_with("192.168.1.100")

    def test_skips_duplicate_ip(self, runner, mock_installer):
        """Should skip if IP already allowlisted."""
        with patch("nssec.modules.waf.get_allowlisted_ips", return_value=["192.168.1.100"]):
            result = runner.invoke(waf, ["allowlist", "add", "192.168.1.100", "-y"])

            assert result.exit_code == 0
            assert "already allowlisted" in result.output

    def test_requires_root(self, runner, mock_installer):
        """Should fail if not root."""
        mock_installer.preflight.return_value.is_root = False

        result = runner.invoke(waf, ["allowlist", "add", "192.168.1.100", "-y"])

        assert result.exit_code == 1


class TestWafAllowlistDelete:
    """Tests for waf allowlist delete command."""

    def test_removes_ip_from_allowlist(self, runner, mock_installer):
        """Should remove IP from allowlist."""
        with patch("nssec.modules.waf.get_allowlisted_ips", return_value=["192.168.1.100"]), \
             patch("nssec.modules.waf.remove_allowlisted_ip") as mock_remove:
            mock_remove.return_value = MagicMock(success=True, message="Removed")

            result = runner.invoke(waf, ["allowlist", "delete", "192.168.1.100", "-y"])

            assert result.exit_code == 0
            mock_remove.assert_called_once_with("192.168.1.100")

    def test_skips_nonexistent_ip(self, runner, mock_installer):
        """Should skip if IP not in allowlist."""
        with patch("nssec.modules.waf.get_allowlisted_ips", return_value=[]):
            result = runner.invoke(waf, ["allowlist", "delete", "192.168.1.100", "-y"])

            assert result.exit_code == 0
            assert "not in the allowlist" in result.output

    def test_requires_root(self, runner, mock_installer):
        """Should fail if not root."""
        mock_installer.preflight.return_value.is_root = False

        result = runner.invoke(waf, ["allowlist", "delete", "192.168.1.100", "-y"])

        assert result.exit_code == 1


class TestWafAllowlistShow:
    """Tests for waf allowlist show command."""

    def test_shows_allowlisted_ips(self, runner):
        """Should display allowlisted IPs."""
        with patch("nssec.modules.waf.get_allowlisted_ips", return_value=["192.168.1.100", "10.0.0.0/8"]):
            result = runner.invoke(waf, ["allowlist", "show"])

            assert result.exit_code == 0
            assert "192.168.1.100" in result.output
            assert "10.0.0.0/8" in result.output

    def test_shows_empty_message(self, runner):
        """Should show message when no IPs allowlisted."""
        with patch("nssec.modules.waf.get_allowlisted_ips", return_value=[]):
            result = runner.invoke(waf, ["allowlist", "show"])

            assert result.exit_code == 0
            assert "No IPs" in result.output

    def test_default_subcommand_shows_list(self, runner):
        """Running 'waf allowlist' without subcommand should show list."""
        with patch("nssec.modules.waf.get_allowlisted_ips", return_value=["192.168.1.100"]):
            result = runner.invoke(waf, ["allowlist"])

            assert result.exit_code == 0
            assert "192.168.1.100" in result.output
