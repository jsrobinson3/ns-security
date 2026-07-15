"""Tests for WAF restrict CLI commands (Apache-config method)."""

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from nssec.cli.waf_commands import waf


@pytest.fixture
def runner():
    """Click CLI test runner."""
    return CliRunner()


def _status(
    exists=True,
    managed=True,
    ips=None,
    components=None,
    segments=None,
    legacy=None,
):
    """Build a get_restrict_status() return value."""
    return {
        "path": "/etc/apache2/conf.d/nssec-restrict.conf",
        "exists": exists,
        "managed": managed,
        "ips": ips if ips is not None else ["127.0.0.1", "192.168.1.100"],
        "components": components if components is not None else ["SiPbx Admin UI"],
        "segments": segments if segments is not None else ["SiPbx"],
        "legacy": legacy if legacy is not None else [],
    }


class TestWafRestrictShow:
    """Tests for waf restrict show command."""

    def test_shows_status(self, runner):
        with patch("nssec.core.server_types.detect_server_type") as mock_detect, patch(
            "nssec.modules.waf.restrict.get_restrict_status", return_value=_status()
        ), patch("nssec.modules.waf.restrict.load_cached_ips", return_value=[]):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "show"])

        assert result.exit_code == 0
        assert "SiPbx Admin UI" in result.output
        assert "nssec-restrict.conf" in result.output
        assert "192.168.1.100" in result.output

    def test_shows_empty_message(self, runner):
        empty = _status(exists=False, managed=False, ips=[], components=[], segments=[], legacy=[])
        with patch("nssec.core.server_types.detect_server_type") as mock_detect, patch(
            "nssec.modules.waf.restrict.get_restrict_status", return_value=empty
        ), patch("nssec.modules.waf.restrict.load_cached_ips", return_value=[]):
            mock_detect.return_value = MagicMock(value="unknown")
            result = runner.invoke(waf, ["restrict", "show"])

        assert result.exit_code == 0
        assert "No applicable" in result.output

    def test_default_subcommand_shows_status(self, runner):
        with patch("nssec.core.server_types.detect_server_type") as mock_detect, patch(
            "nssec.modules.waf.restrict.get_restrict_status", return_value=_status()
        ), patch("nssec.modules.waf.restrict.load_cached_ips", return_value=[]):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict"])

        assert result.exit_code == 0
        assert "SiPbx Admin UI" in result.output

    def test_warns_about_leftover_legacy_htaccess(self, runner):
        status = _status(legacy=["/usr/local/NetSapiens/SiPbx/html/SiPbx/.htaccess"])
        with patch("nssec.core.server_types.detect_server_type") as mock_detect, patch(
            "nssec.modules.waf.restrict.get_restrict_status", return_value=status
        ), patch("nssec.modules.waf.restrict.load_cached_ips", return_value=[]):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "show"])

        assert result.exit_code == 0
        assert "Legacy .htaccess" in result.output
        assert "/usr/local/NetSapiens/SiPbx/html/SiPbx/.htaccess" in result.output


class TestWafRestrictInit:
    """Tests for waf restrict init command."""

    def test_requires_root(self, runner):
        with patch("nssec.core.ssh.is_root", return_value=False):
            result = runner.invoke(waf, ["restrict", "init", "--ip", "10.0.0.1", "-y"])

        assert result.exit_code == 1
        assert "root" in result.output.lower()

    def test_writes_config(self, runner):
        from nssec.modules.waf.types import StepResult

        mock_results = [("Admin UI restrictions (SiPbx)", StepResult(message="Wrote config"))]
        with patch("nssec.core.ssh.is_root", return_value=True), patch(
            "nssec.core.server_types.detect_server_type"
        ) as mock_detect, patch(
            "nssec.modules.waf.restrict.collect_existing_ips", return_value=[]
        ), patch(
            "nssec.modules.waf.restrict.init_restrictions", return_value=mock_results
        ) as mock_init, patch(
            "nssec.modules.waf.restrict.remove_legacy_htaccess", return_value=[]
        ), patch(
            "nssec.modules.waf.utils.run_cmd", return_value=("", "", 0)
        ):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "init", "--ip", "192.168.1.100", "-y"])

        assert result.exit_code == 0
        mock_init.assert_called_once()
        assert "192.168.1.100" in mock_init.call_args[0][1]

    def test_removes_legacy_htaccess_after_reload(self, runner):
        """On migrate, legacy nssec-managed .htaccess files are cleaned up."""
        from nssec.modules.waf.types import StepResult

        mock_results = [("Admin UI restrictions (SiPbx)", StepResult(message="Wrote config"))]
        cleanup = [
            (
                "/usr/local/NetSapiens/SiPbx/html/SiPbx/.htaccess",
                StepResult(
                    message="Removed legacy /usr/local/NetSapiens/SiPbx/html/SiPbx/.htaccess"
                ),
            )
        ]
        with patch("nssec.core.ssh.is_root", return_value=True), patch(
            "nssec.core.server_types.detect_server_type"
        ) as mock_detect, patch(
            "nssec.modules.waf.restrict.collect_existing_ips", return_value=[]
        ), patch(
            "nssec.modules.waf.restrict.init_restrictions", return_value=mock_results
        ), patch(
            "nssec.modules.waf.restrict.remove_legacy_htaccess", return_value=cleanup
        ) as mock_cleanup, patch(
            "nssec.modules.waf.utils.run_cmd", return_value=("", "", 0)
        ):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "init", "--ip", "192.168.1.100", "-y"])

        assert result.exit_code == 0
        mock_cleanup.assert_called_once_with()
        assert "Removed legacy" in result.output

    def test_validates_ip_address(self, runner):
        with patch("nssec.core.ssh.is_root", return_value=True), patch(
            "nssec.core.server_types.detect_server_type"
        ) as mock_detect, patch("nssec.modules.waf.restrict.collect_existing_ips", return_value=[]):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "init", "--ip", "not-an-ip", "-y"])

        assert result.exit_code == 1
        assert "Invalid" in result.output

    def test_dry_run(self, runner):
        from nssec.modules.waf.types import StepResult

        mock_results = [("Admin UI restrictions (SiPbx)", StepResult(message="Would write config"))]
        with patch("nssec.core.ssh.is_root", return_value=True), patch(
            "nssec.core.server_types.detect_server_type"
        ) as mock_detect, patch(
            "nssec.modules.waf.restrict.collect_existing_ips", return_value=[]
        ), patch(
            "nssec.modules.waf.restrict.init_restrictions", return_value=mock_results
        ), patch(
            "nssec.modules.waf.restrict.remove_legacy_htaccess", return_value=[]
        ):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "init", "--ip", "10.0.0.1", "--dry-run"])

        assert result.exit_code == 0
        assert "Dry run" in result.output

    def test_accepts_cidr_notation(self, runner):
        from nssec.modules.waf.types import StepResult

        mock_results = [("Admin UI restrictions (SiPbx)", StepResult(message="Wrote config"))]
        with patch("nssec.core.ssh.is_root", return_value=True), patch(
            "nssec.core.server_types.detect_server_type"
        ) as mock_detect, patch(
            "nssec.modules.waf.restrict.collect_existing_ips", return_value=[]
        ), patch(
            "nssec.modules.waf.restrict.init_restrictions", return_value=mock_results
        ), patch(
            "nssec.modules.waf.restrict.remove_legacy_htaccess", return_value=[]
        ), patch(
            "nssec.modules.waf.utils.run_cmd", return_value=("", "", 0)
        ):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "init", "--ip", "10.0.0.0/8", "-y"])

        assert result.exit_code == 0

    def test_shows_existing_ips_and_keeps_by_default(self, runner):
        from nssec.modules.waf.types import StepResult

        mock_results = [("Admin UI restrictions (SiPbx)", StepResult(message="Wrote config"))]
        with patch("nssec.core.ssh.is_root", return_value=True), patch(
            "nssec.core.server_types.detect_server_type"
        ) as mock_detect, patch(
            "nssec.modules.waf.restrict.collect_existing_ips",
            return_value=["10.0.0.5", "172.16.0.1"],
        ), patch(
            "nssec.modules.waf.restrict.init_restrictions", return_value=mock_results
        ) as mock_init, patch(
            "nssec.modules.waf.restrict.remove_legacy_htaccess", return_value=[]
        ), patch(
            "nssec.modules.waf.utils.run_cmd", return_value=("", "", 0)
        ):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(
                waf, ["restrict", "init", "--ip", "192.168.1.100"], input="y\ny\ny\n"
            )

        assert result.exit_code == 0
        assert "10.0.0.5" in result.output
        assert mock_init.call_args[1].get("merge_existing") is True

    def test_shows_existing_ips_and_overwrites_on_no(self, runner):
        from nssec.modules.waf.types import StepResult

        mock_results = [("Admin UI restrictions (SiPbx)", StepResult(message="Wrote config"))]
        with patch("nssec.core.ssh.is_root", return_value=True), patch(
            "nssec.core.server_types.detect_server_type"
        ) as mock_detect, patch(
            "nssec.modules.waf.restrict.collect_existing_ips", return_value=["10.0.0.5"]
        ), patch(
            "nssec.modules.waf.restrict.init_restrictions", return_value=mock_results
        ) as mock_init, patch(
            "nssec.modules.waf.restrict.remove_legacy_htaccess", return_value=[]
        ), patch(
            "nssec.modules.waf.utils.run_cmd", return_value=("", "", 0)
        ):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(
                waf, ["restrict", "init", "--ip", "192.168.1.100"], input="n\ny\ny\n"
            )

        assert result.exit_code == 0
        assert "Overwriting" in result.output
        assert mock_init.call_args[1].get("merge_existing") is False


class TestWafRestrictAdd:
    """Tests for waf restrict add command."""

    def test_requires_root(self, runner):
        with patch("nssec.core.ssh.is_root", return_value=False):
            result = runner.invoke(waf, ["restrict", "add", "192.168.1.100", "-y"])

        assert result.exit_code == 1
        assert "root" in result.output.lower()

    def test_adds_ip(self, runner):
        from nssec.modules.waf.types import StepResult

        mock_results = [("", StepResult(message="Added 192.168.1.100"))]
        with patch("nssec.core.ssh.is_root", return_value=True), patch(
            "nssec.core.server_types.detect_server_type"
        ) as mock_detect, patch(
            "nssec.modules.waf.restrict.add_restricted_ip", return_value=mock_results
        ) as mock_add, patch(
            "nssec.modules.waf.utils.run_cmd", return_value=("", "", 0)
        ):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "add", "192.168.1.100", "-y"])

        assert result.exit_code == 0
        mock_add.assert_called_once_with("core", "192.168.1.100")

    def test_validates_ip_address(self, runner):
        with patch("nssec.core.ssh.is_root", return_value=True), patch(
            "nssec.core.server_types.detect_server_type"
        ) as mock_detect:
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "add", "not-valid", "-y"])

        assert result.exit_code == 1
        assert "Invalid" in result.output


class TestWafRestrictRemove:
    """Tests for waf restrict remove command."""

    def test_requires_root(self, runner):
        with patch("nssec.core.ssh.is_root", return_value=False):
            result = runner.invoke(waf, ["restrict", "remove", "192.168.1.100", "-y"])

        assert result.exit_code == 1
        assert "root" in result.output.lower()

    def test_removes_ip(self, runner):
        from nssec.modules.waf.types import StepResult

        mock_results = [("", StepResult(message="Removed 192.168.1.100"))]
        with patch("nssec.core.ssh.is_root", return_value=True), patch(
            "nssec.core.server_types.detect_server_type"
        ) as mock_detect, patch(
            "nssec.modules.waf.restrict.remove_restricted_ip", return_value=mock_results
        ) as mock_remove, patch(
            "nssec.modules.waf.utils.run_cmd", return_value=("", "", 0)
        ):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "remove", "192.168.1.100", "-y"])

        assert result.exit_code == 0
        mock_remove.assert_called_once_with("core", "192.168.1.100")

    def test_blocks_localhost_removal(self, runner):
        from nssec.modules.waf.types import StepResult

        mock_results = [
            (
                "",
                StepResult(
                    success=False,
                    error="Cannot remove 127.0.0.1 (localhost must always be allowed)",
                ),
            )
        ]
        with patch("nssec.core.ssh.is_root", return_value=True), patch(
            "nssec.core.server_types.detect_server_type"
        ) as mock_detect, patch(
            "nssec.modules.waf.restrict.remove_restricted_ip", return_value=mock_results
        ):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "remove", "127.0.0.1", "-y"])

        assert result.exit_code == 1
        assert "Cannot remove" in result.output


class TestWafRestrictReapply:
    """Tests for waf restrict reapply command."""

    def test_requires_root(self, runner):
        with patch("nssec.core.ssh.is_root", return_value=False):
            result = runner.invoke(waf, ["restrict", "reapply", "-y"])

        assert result.exit_code == 1
        assert "root" in result.output.lower()

    def test_restores_from_cache(self, runner):
        from nssec.modules.waf.types import StepResult

        mock_results = [("Admin UI restrictions (SiPbx)", StepResult(message="Restored config"))]
        with patch("nssec.core.ssh.is_root", return_value=True), patch(
            "nssec.core.server_types.detect_server_type"
        ) as mock_detect, patch(
            "nssec.modules.waf.restrict.load_cached_ips", return_value=["127.0.0.1", "10.0.0.1"]
        ), patch(
            "nssec.modules.waf.restrict.reapply_restrictions", return_value=mock_results
        ) as mock_reapply, patch(
            "nssec.modules.waf.utils.run_cmd", return_value=("", "", 0)
        ):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "reapply", "-y"])

        assert result.exit_code == 0
        mock_reapply.assert_called_once()
        assert "10.0.0.1" in result.output

    def test_dry_run(self, runner):
        from nssec.modules.waf.types import StepResult

        mock_results = [("Admin UI restrictions (SiPbx)", StepResult(message="Would write config"))]
        with patch("nssec.core.ssh.is_root", return_value=True), patch(
            "nssec.core.server_types.detect_server_type"
        ) as mock_detect, patch(
            "nssec.modules.waf.restrict.load_cached_ips", return_value=["127.0.0.1"]
        ), patch(
            "nssec.modules.waf.restrict.reapply_restrictions", return_value=mock_results
        ):
            mock_detect.return_value = MagicMock(value="core")
            result = runner.invoke(waf, ["restrict", "reapply", "--dry-run"])

        assert result.exit_code == 0
        assert "Dry run" in result.output
