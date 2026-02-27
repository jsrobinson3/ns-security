"""Tests for mTLS CLI commands."""

from unittest.mock import patch

import pytest
from click.testing import CliRunner

from nssec.cli.mtls_commands import mtls
from nssec.modules.mtls import StepResult


@pytest.fixture
def runner():
    """Click CLI test runner."""
    return CliRunner()


@pytest.fixture
def mock_mtls_file_ops():
    """Mock file operations for mTLS module."""
    with (
        patch("nssec.modules.mtls.file_exists") as exists,
        patch("nssec.modules.mtls.read_file") as read,
        patch("nssec.modules.mtls.write_file") as write,
        patch("nssec.modules.mtls.backup_file") as backup,
    ):
        exists.return_value = True
        read.return_value = ""
        write.return_value = True
        backup.return_value = "/tmp/backup"
        yield {
            "exists": exists,
            "read": read,
            "write": write,
            "backup": backup,
        }


SAMPLE_CONF_WITH_IPS = """\
<Location /cfg>
    SSLVerifyClient require
    <RequireAny>
        Require ip 10.0.0.1
        Require ip 192.168.1.0/24

    # BEGIN nssec-managed NodePing IPs (do not edit)
        Require ip 1.2.3.4
        Require ip 5.6.7.8
    # END nssec-managed NodePing IPs
    </RequireAny>
</Location>
"""


class TestMtlsHelp:
    """Tests for mtls group help output."""

    def test_shows_commands_when_no_subcommand(self, runner):
        result = runner.invoke(mtls, [])
        assert result.exit_code == 0
        assert "Allowlist Commands" in result.output
        assert "NodePing Commands" in result.output
        assert "allowlist show" in result.output
        assert "nodeping show" in result.output


class TestAllowlistShow:
    """Tests for mtls allowlist show command."""

    def test_shows_all_ips(self, runner):
        with (
            patch("nssec.modules.mtls.utils.file_exists", return_value=True),
            patch(
                "nssec.modules.mtls.get_allowlist_ips",
                return_value=[
                    {"ip": "10.0.0.1", "managed": False},
                    {"ip": "1.2.3.4", "managed": True},
                ],
            ),
        ):
            result = runner.invoke(mtls, ["allowlist", "show"])

        assert result.exit_code == 0
        assert "10.0.0.1" in result.output
        assert "1.2.3.4" in result.output
        assert "Manual Allowlist" in result.output
        assert "NodePing" in result.output

    def test_shows_config_not_found(self, runner):
        with patch("nssec.modules.mtls.utils.file_exists", return_value=False):
            result = runner.invoke(mtls, ["allowlist", "show"])

        assert result.exit_code == 0
        assert "not found" in result.output

    def test_shows_empty_allowlist(self, runner):
        with (
            patch("nssec.modules.mtls.utils.file_exists", return_value=True),
            patch("nssec.modules.mtls.get_allowlist_ips", return_value=[]),
        ):
            result = runner.invoke(mtls, ["allowlist", "show"])

        assert result.exit_code == 0
        assert "No IPs" in result.output

    def test_default_subcommand_shows_allowlist(self, runner):
        """Running 'mtls allowlist' without subcommand should show IPs."""
        with (
            patch("nssec.modules.mtls.utils.file_exists", return_value=True),
            patch("nssec.modules.mtls.get_allowlist_ips", return_value=[]),
        ):
            result = runner.invoke(mtls, ["allowlist"])

        assert result.exit_code == 0
        assert "No IPs" in result.output


class TestAllowlistAdd:
    """Tests for mtls allowlist add command."""

    def test_adds_ip(self, runner):
        with (
            patch("nssec.core.ssh.is_root", return_value=True),
            patch(
                "nssec.modules.mtls.add_allowlist_ip",
                return_value=StepResult(message="Added 203.0.113.1 to mTLS allowlist"),
            ),
            patch(
                "nssec.modules.mtls.validate_apache_config",
                return_value=StepResult(message="Apache config test passed"),
            ),
            patch(
                "nssec.modules.mtls.reload_apache",
                return_value=StepResult(message="Apache reloaded"),
            ),
        ):
            result = runner.invoke(mtls, ["allowlist", "add", "203.0.113.1", "-y"])

        assert result.exit_code == 0
        assert "Added" in result.output

    def test_requires_root(self, runner):
        with patch("nssec.core.ssh.is_root", return_value=False):
            result = runner.invoke(mtls, ["allowlist", "add", "203.0.113.1", "-y"])

        assert result.exit_code == 1
        assert "root" in result.output.lower()

    def test_rejects_invalid_ip(self, runner):
        with patch("nssec.core.ssh.is_root", return_value=True):
            result = runner.invoke(mtls, ["allowlist", "add", "not-an-ip", "-y"])

        assert result.exit_code == 1
        assert "not a valid IP" in result.output

    def test_shows_error_for_duplicate(self, runner):
        with (
            patch("nssec.core.ssh.is_root", return_value=True),
            patch(
                "nssec.modules.mtls.add_allowlist_ip",
                return_value=StepResult(
                    success=False, error="IP 10.0.0.1 is already in the allowlist"
                ),
            ),
        ):
            result = runner.invoke(mtls, ["allowlist", "add", "10.0.0.1", "-y"])

        assert result.exit_code == 1
        assert "already" in result.output


class TestAllowlistRemove:
    """Tests for mtls allowlist remove command."""

    def test_removes_ip(self, runner):
        with (
            patch("nssec.core.ssh.is_root", return_value=True),
            patch(
                "nssec.modules.mtls.remove_allowlist_ip",
                return_value=StepResult(message="Removed 10.0.0.1 from mTLS allowlist"),
            ),
            patch(
                "nssec.modules.mtls.validate_apache_config",
                return_value=StepResult(message="Apache config test passed"),
            ),
            patch(
                "nssec.modules.mtls.reload_apache",
                return_value=StepResult(message="Apache reloaded"),
            ),
        ):
            result = runner.invoke(mtls, ["allowlist", "remove", "10.0.0.1", "-y"])

        assert result.exit_code == 0
        assert "Removed" in result.output

    def test_requires_root(self, runner):
        with patch("nssec.core.ssh.is_root", return_value=False):
            result = runner.invoke(mtls, ["allowlist", "remove", "10.0.0.1", "-y"])

        assert result.exit_code == 1
        assert "root" in result.output.lower()

    def test_prompts_without_yes_flag(self, runner):
        with (
            patch("nssec.core.ssh.is_root", return_value=True),
        ):
            result = runner.invoke(mtls, ["allowlist", "remove", "10.0.0.1"], input="n\n")

        assert result.exit_code == 0
        assert "Aborted" in result.output

    def test_blocks_removal_of_managed_ip(self, runner):
        with (
            patch("nssec.core.ssh.is_root", return_value=True),
            patch(
                "nssec.modules.mtls.remove_allowlist_ip",
                return_value=StepResult(
                    success=False,
                    error="IP 1.2.3.4 is managed by NodePing auto-updates.",
                ),
            ),
        ):
            result = runner.invoke(mtls, ["allowlist", "remove", "1.2.3.4", "-y"])

        assert result.exit_code == 1
        assert "managed by NodePing" in result.output
