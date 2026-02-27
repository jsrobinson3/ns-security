"""Tests for WAF restrict CLI commands."""

import pytest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

from nssec.cli.waf_commands import waf


@pytest.fixture
def runner():
    """Click CLI test runner."""
    return CliRunner()


class TestWafRestrictShow:
    """Tests for waf restrict show command."""

    def test_shows_status_table(self, runner):
        """Should display restriction status for applicable paths."""
        statuses = [
            {
                "name": "SiPbx Admin UI",
                "path": "/usr/local/NetSapiens/SiPbx/html/SiPbx/.htaccess",
                "exists": True,
                "managed": True,
                "ips": ["127.0.0.1", "192.168.1.100"],
            },
            {
                "name": "ns-api",
                "path": "/usr/local/NetSapiens/SiPbx/html/ns-api/.htaccess",
                "exists": False,
                "managed": False,
                "ips": [],
            },
        ]
        with patch("nssec.core.server_types.detect_server_type") as mock_detect, \
             patch("nssec.modules.waf.restrict.get_restrict_status", return_value=statuses):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "show"])

        assert result.exit_code == 0
        assert "SiPbx Admin UI" in result.output
        assert "ns-api" in result.output

    def test_shows_empty_message(self, runner):
        """Should show message when no targets apply."""
        with patch("nssec.core.server_types.detect_server_type") as mock_detect, \
             patch("nssec.modules.waf.restrict.get_restrict_status", return_value=[]):
            mock_detect.return_value = MagicMock(value="unknown")
            result = runner.invoke(waf, ["restrict", "show"])

        assert result.exit_code == 0
        assert "No applicable" in result.output

    def test_default_subcommand_shows_status(self, runner):
        """Running 'waf restrict' without subcommand should show status."""
        statuses = [
            {
                "name": "SiPbx Admin UI",
                "path": "/usr/local/NetSapiens/SiPbx/html/SiPbx/.htaccess",
                "exists": True,
                "managed": True,
                "ips": ["127.0.0.1"],
            },
        ]
        with patch("nssec.core.server_types.detect_server_type") as mock_detect, \
             patch("nssec.modules.waf.restrict.get_restrict_status", return_value=statuses):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict"])

        assert result.exit_code == 0
        assert "SiPbx Admin UI" in result.output

    def test_lists_ips_from_first_managed_file(self, runner):
        """Should list IPs from the first managed file."""
        statuses = [
            {
                "name": "SiPbx Admin UI",
                "path": "/usr/local/NetSapiens/SiPbx/html/SiPbx/.htaccess",
                "exists": True,
                "managed": True,
                "ips": ["127.0.0.1", "10.0.0.1"],
            },
        ]
        with patch("nssec.core.server_types.detect_server_type") as mock_detect, \
             patch("nssec.modules.waf.restrict.get_restrict_status", return_value=statuses):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "show"])

        assert result.exit_code == 0
        assert "127.0.0.1" in result.output
        assert "10.0.0.1" in result.output


class TestWafRestrictInit:
    """Tests for waf restrict init command."""

    def test_requires_root(self, runner):
        """Should fail if not root."""
        with patch("nssec.core.ssh.is_root", return_value=False):
            result = runner.invoke(waf, ["restrict", "init", "--ip", "10.0.0.1", "-y"])

        assert result.exit_code == 1
        assert "root" in result.output.lower()

    def test_creates_htaccess_files(self, runner):
        """Should create .htaccess files with provided IPs."""
        from nssec.modules.waf.types import StepResult

        mock_results = [
            ("SiPbx Admin UI", StepResult(message="Created file")),
            ("ns-api", StepResult(message="Created file")),
        ]

        with patch("nssec.core.ssh.is_root", return_value=True), \
             patch("nssec.core.server_types.detect_server_type") as mock_detect, \
             patch("nssec.modules.waf.restrict.collect_existing_ips", return_value=[]), \
             patch("nssec.modules.waf.restrict.init_restrictions", return_value=mock_results) as mock_init, \
             patch("nssec.modules.waf.utils.run_cmd", return_value=("", "", 0)):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "init", "--ip", "192.168.1.100", "-y"])

        assert result.exit_code == 0
        mock_init.assert_called_once()
        call_args = mock_init.call_args
        assert "192.168.1.100" in call_args[0][1]  # ips list

    def test_validates_ip_address(self, runner):
        """Should reject invalid IP addresses."""
        with patch("nssec.core.ssh.is_root", return_value=True), \
             patch("nssec.core.server_types.detect_server_type") as mock_detect, \
             patch("nssec.modules.waf.restrict.collect_existing_ips", return_value=[]):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "init", "--ip", "not-an-ip", "-y"])

        assert result.exit_code == 1
        assert "Invalid" in result.output

    def test_dry_run(self, runner):
        """Should show what would be done in dry run."""
        from nssec.modules.waf.types import StepResult

        mock_results = [
            ("SiPbx Admin UI", StepResult(message="Would create file")),
        ]

        with patch("nssec.core.ssh.is_root", return_value=True), \
             patch("nssec.core.server_types.detect_server_type") as mock_detect, \
             patch("nssec.modules.waf.restrict.collect_existing_ips", return_value=[]), \
             patch("nssec.modules.waf.restrict.init_restrictions", return_value=mock_results):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "init", "--ip", "10.0.0.1", "--dry-run"])

        assert result.exit_code == 0
        assert "Dry run" in result.output

    def test_accepts_cidr_notation(self, runner):
        """Should accept CIDR notation IPs."""
        from nssec.modules.waf.types import StepResult

        mock_results = [
            ("SiPbx Admin UI", StepResult(message="Created file")),
        ]

        with patch("nssec.core.ssh.is_root", return_value=True), \
             patch("nssec.core.server_types.detect_server_type") as mock_detect, \
             patch("nssec.modules.waf.restrict.collect_existing_ips", return_value=[]), \
             patch("nssec.modules.waf.restrict.init_restrictions", return_value=mock_results), \
             patch("nssec.modules.waf.utils.run_cmd", return_value=("", "", 0)):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "init", "--ip", "10.0.0.0/8", "-y"])

        assert result.exit_code == 0

    def test_shows_existing_ips_and_keeps_by_default(self, runner):
        """Should show existing IPs and keep them when user confirms."""
        from nssec.modules.waf.types import StepResult

        mock_results = [
            ("SiPbx Admin UI", StepResult(message="Created file")),
        ]

        with patch("nssec.core.ssh.is_root", return_value=True), \
             patch("nssec.core.server_types.detect_server_type") as mock_detect, \
             patch("nssec.modules.waf.restrict.collect_existing_ips", return_value=["10.0.0.5", "172.16.0.1"]), \
             patch("nssec.modules.waf.restrict.init_restrictions", return_value=mock_results) as mock_init, \
             patch("nssec.modules.waf.utils.run_cmd", return_value=("", "", 0)):
            mock_detect.return_value = MagicMock(value="core")
            # Confirm keep=Yes, create=Yes, reload=Yes
            result = runner.invoke(waf, ["restrict", "init", "--ip", "192.168.1.100"],
                                   input="y\ny\ny\n")

        assert result.exit_code == 0
        assert "10.0.0.5" in result.output
        assert "172.16.0.1" in result.output
        # merge_existing should be True (keeping existing)
        call_kwargs = mock_init.call_args[1]
        assert call_kwargs.get("merge_existing") is True

    def test_shows_existing_ips_and_overwrites_on_no(self, runner):
        """Should overwrite existing IPs when user says no to keeping."""
        from nssec.modules.waf.types import StepResult

        mock_results = [
            ("SiPbx Admin UI", StepResult(message="Created file")),
        ]

        with patch("nssec.core.ssh.is_root", return_value=True), \
             patch("nssec.core.server_types.detect_server_type") as mock_detect, \
             patch("nssec.modules.waf.restrict.collect_existing_ips", return_value=["10.0.0.5"]), \
             patch("nssec.modules.waf.restrict.init_restrictions", return_value=mock_results) as mock_init, \
             patch("nssec.modules.waf.utils.run_cmd", return_value=("", "", 0)):
            mock_detect.return_value = MagicMock(value="core")
            # Confirm keep=No, create=Yes, reload=Yes
            result = runner.invoke(waf, ["restrict", "init", "--ip", "192.168.1.100"],
                                   input="n\ny\ny\n")

        assert result.exit_code == 0
        assert "Overwriting" in result.output
        # merge_existing should be False
        call_kwargs = mock_init.call_args[1]
        assert call_kwargs.get("merge_existing") is False

    def test_yes_flag_keeps_existing_ips_by_default(self, runner):
        """With --yes, should keep existing IPs without prompting."""
        from nssec.modules.waf.types import StepResult

        mock_results = [
            ("SiPbx Admin UI", StepResult(message="Created file")),
        ]

        with patch("nssec.core.ssh.is_root", return_value=True), \
             patch("nssec.core.server_types.detect_server_type") as mock_detect, \
             patch("nssec.modules.waf.restrict.collect_existing_ips", return_value=["10.0.0.5"]), \
             patch("nssec.modules.waf.restrict.init_restrictions", return_value=mock_results) as mock_init, \
             patch("nssec.modules.waf.utils.run_cmd", return_value=("", "", 0)):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "init", "--ip", "192.168.1.100", "-y"])

        assert result.exit_code == 0
        assert "Keeping" in result.output
        call_kwargs = mock_init.call_args[1]
        assert call_kwargs.get("merge_existing") is True


class TestWafRestrictAdd:
    """Tests for waf restrict add command."""

    def test_requires_root(self, runner):
        """Should fail if not root."""
        with patch("nssec.core.ssh.is_root", return_value=False):
            result = runner.invoke(waf, ["restrict", "add", "192.168.1.100", "-y"])

        assert result.exit_code == 1
        assert "root" in result.output.lower()

    def test_adds_ip_to_managed_files(self, runner):
        """Should add IP to all managed .htaccess files."""
        from nssec.modules.waf.types import StepResult

        mock_results = [
            ("SiPbx Admin UI", StepResult(message="Added 192.168.1.100")),
        ]

        with patch("nssec.core.ssh.is_root", return_value=True), \
             patch("nssec.core.server_types.detect_server_type") as mock_detect, \
             patch("nssec.modules.waf.restrict.add_restricted_ip", return_value=mock_results) as mock_add, \
             patch("nssec.modules.waf.utils.run_cmd", return_value=("", "", 0)):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "add", "192.168.1.100", "-y"])

        assert result.exit_code == 0
        mock_add.assert_called_once_with("core", "192.168.1.100")

    def test_validates_ip_address(self, runner):
        """Should reject invalid IP addresses."""
        with patch("nssec.core.ssh.is_root", return_value=True), \
             patch("nssec.core.server_types.detect_server_type") as mock_detect:
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "add", "not-valid", "-y"])

        assert result.exit_code == 1
        assert "Invalid" in result.output


class TestWafRestrictRemove:
    """Tests for waf restrict remove command."""

    def test_requires_root(self, runner):
        """Should fail if not root."""
        with patch("nssec.core.ssh.is_root", return_value=False):
            result = runner.invoke(waf, ["restrict", "remove", "192.168.1.100", "-y"])

        assert result.exit_code == 1
        assert "root" in result.output.lower()

    def test_removes_ip_from_managed_files(self, runner):
        """Should remove IP from managed .htaccess files."""
        from nssec.modules.waf.types import StepResult

        mock_results = [
            ("SiPbx Admin UI", StepResult(message="Removed 192.168.1.100")),
        ]

        with patch("nssec.core.ssh.is_root", return_value=True), \
             patch("nssec.core.server_types.detect_server_type") as mock_detect, \
             patch("nssec.modules.waf.restrict.remove_restricted_ip", return_value=mock_results) as mock_remove, \
             patch("nssec.modules.waf.utils.run_cmd", return_value=("", "", 0)):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "remove", "192.168.1.100", "-y"])

        assert result.exit_code == 0
        mock_remove.assert_called_once_with("core", "192.168.1.100")

    def test_blocks_localhost_removal(self, runner):
        """Should block removal of 127.0.0.1."""
        from nssec.modules.waf.types import StepResult

        mock_results = [
            ("", StepResult(success=False, error="Cannot remove 127.0.0.1 (localhost must always be allowed)")),
        ]

        with patch("nssec.core.ssh.is_root", return_value=True), \
             patch("nssec.core.server_types.detect_server_type") as mock_detect, \
             patch("nssec.modules.waf.restrict.remove_restricted_ip", return_value=mock_results):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "remove", "127.0.0.1", "-y"])

        assert result.exit_code == 1
        assert "Cannot remove" in result.output


class TestWafRestrictReapply:
    """Tests for waf restrict reapply command."""

    def test_requires_root(self, runner):
        """Should fail if not root."""
        with patch("nssec.core.ssh.is_root", return_value=False):
            result = runner.invoke(waf, ["restrict", "reapply", "-y"])

        assert result.exit_code == 1
        assert "root" in result.output.lower()

    def test_restores_from_cache(self, runner):
        """Should restore .htaccess files from cached IPs."""
        from nssec.modules.waf.types import StepResult

        mock_results = [
            ("SiPbx Admin UI", StepResult(message="Restored file")),
        ]

        with patch("nssec.core.ssh.is_root", return_value=True), \
             patch("nssec.core.server_types.detect_server_type") as mock_detect, \
             patch("nssec.modules.waf.restrict.load_cached_ips", return_value=["127.0.0.1", "10.0.0.1"]), \
             patch("nssec.modules.waf.restrict.reapply_restrictions", return_value=mock_results) as mock_reapply, \
             patch("nssec.modules.waf.utils.run_cmd", return_value=("", "", 0)):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "reapply", "-y"])

        assert result.exit_code == 0
        mock_reapply.assert_called_once()

    def test_shows_cached_ips(self, runner):
        """Should display cached IPs before reapplying."""
        from nssec.modules.waf.types import StepResult

        mock_results = [
            ("SiPbx Admin UI", StepResult(message="Restored file")),
        ]

        with patch("nssec.core.ssh.is_root", return_value=True), \
             patch("nssec.core.server_types.detect_server_type") as mock_detect, \
             patch("nssec.modules.waf.restrict.load_cached_ips", return_value=["127.0.0.1", "10.0.0.1"]), \
             patch("nssec.modules.waf.restrict.reapply_restrictions", return_value=mock_results), \
             patch("nssec.modules.waf.utils.run_cmd", return_value=("", "", 0)):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "reapply", "-y"])

        assert "10.0.0.1" in result.output

    def test_dry_run(self, runner):
        """Should show what would be done in dry run."""
        from nssec.modules.waf.types import StepResult

        mock_results = [
            ("SiPbx Admin UI", StepResult(message="Would write file")),
        ]

        with patch("nssec.core.ssh.is_root", return_value=True), \
             patch("nssec.core.server_types.detect_server_type") as mock_detect, \
             patch("nssec.modules.waf.restrict.load_cached_ips", return_value=["127.0.0.1"]), \
             patch("nssec.modules.waf.restrict.reapply_restrictions", return_value=mock_results):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "reapply", "--dry-run"])

        assert result.exit_code == 0
        assert "Dry run" in result.output
