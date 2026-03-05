"""Tests for WAF CLI commands."""

from unittest.mock import MagicMock, patch

import pytest
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
        with patch("nssec.core.ssh.is_root", return_value=True), patch(
            "nssec.modules.waf.utils.file_exists", return_value=True
        ), patch("nssec.modules.waf.utils.run_cmd") as mock_run:
            mock_run.return_value = ("", "", 0)

            result = runner.invoke(waf, ["remove", "-y"])

            assert result.exit_code == 0
            # Check a2dismod was called
            calls = [str(c) for c in mock_run.call_args_list]
            assert any("a2dismod" in c for c in calls)

    def test_skips_if_already_disabled(self, runner):
        """Should skip if module already disabled."""
        with patch("nssec.core.ssh.is_root", return_value=True), patch(
            "nssec.modules.waf.utils.file_exists", return_value=False
        ):
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
        with patch("nssec.core.ssh.is_root", return_value=True), patch(
            "nssec.modules.waf.utils.file_exists", return_value=True
        ):
            result = runner.invoke(waf, ["remove"], input="n\n")

            assert "Aborted" in result.output


class TestWafAllowlistAdd:
    """Tests for waf allowlist add command."""

    def test_adds_ip_to_allowlist(self, runner, mock_installer):
        """Should add IP to allowlist."""
        with patch("nssec.modules.waf.get_allowlisted_ips", return_value=[]), patch(
            "nssec.modules.waf.add_allowlisted_ip"
        ) as mock_add:
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
        with patch("nssec.modules.waf.get_allowlisted_ips", return_value=["192.168.1.100"]), patch(
            "nssec.modules.waf.remove_allowlisted_ip"
        ) as mock_remove:
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
        with patch(
            "nssec.modules.waf.get_allowlisted_ips", return_value=["192.168.1.100", "10.0.0.0/8"]
        ):
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


class TestWafEvasiveEnable:
    """Tests for waf evasive enable command."""

    def test_enables_evasive(self, runner, mock_installer):
        """Should enable mod_evasive."""
        mock_installer.set_evasive_state.return_value = MagicMock(
            success=True, skipped=False, message="Enabled mod_evasive"
        )

        with patch("nssec.modules.waf.utils.package_installed", return_value=True):
            result = runner.invoke(waf, ["evasive", "enable", "-y"])

        assert result.exit_code == 0
        mock_installer.set_evasive_state.assert_called_once_with(enable=True)

    def test_skips_if_already_enabled(self, runner, mock_installer):
        """Should report already enabled."""
        mock_installer.set_evasive_state.return_value = MagicMock(
            success=True, skipped=True, message="mod_evasive already enabled"
        )

        with patch("nssec.modules.waf.utils.package_installed", return_value=True):
            result = runner.invoke(waf, ["evasive", "enable", "-y"])

        assert result.exit_code == 0
        assert "already enabled" in result.output

    def test_requires_root(self, runner, mock_installer):
        """Should fail if not root."""
        mock_installer.preflight.return_value.is_root = False

        result = runner.invoke(waf, ["evasive", "enable", "-y"])

        assert result.exit_code == 1
        assert "root" in result.output.lower()

    def test_requires_package_installed(self, runner, mock_installer):
        """Should fail if mod_evasive package not installed."""
        with patch("nssec.modules.waf.utils.package_installed", return_value=False):
            result = runner.invoke(waf, ["evasive", "enable", "-y"])

        assert result.exit_code == 1
        assert "not installed" in result.output.lower()


class TestWafEvasiveDisable:
    """Tests for waf evasive disable command."""

    def test_disables_evasive(self, runner, mock_installer):
        """Should disable mod_evasive."""
        mock_installer.set_evasive_state.return_value = MagicMock(
            success=True, skipped=False, message="Disabled mod_evasive"
        )

        with patch("nssec.core.ssh.is_root", return_value=True):
            result = runner.invoke(waf, ["evasive", "disable", "-y"])

        assert result.exit_code == 0
        mock_installer.set_evasive_state.assert_called_once_with(enable=False)

    def test_prompts_without_yes_flag(self, runner, mock_installer):
        """Should prompt for confirmation without -y flag."""
        with patch("nssec.core.ssh.is_root", return_value=True):
            result = runner.invoke(waf, ["evasive", "disable"], input="n\n")

        assert "Aborted" in result.output
        mock_installer.set_evasive_state.assert_not_called()

    def test_requires_root(self, runner):
        """Should fail if not root."""
        with patch("nssec.core.ssh.is_root", return_value=False):
            result = runner.invoke(waf, ["evasive", "disable", "-y"])

        assert result.exit_code == 1
        assert "root" in result.output.lower()


class TestWafEvasiveStatus:
    """Tests for waf evasive status command."""

    def test_shows_enabled_status(self, runner):
        """Should show enabled status when evasive is active."""
        with patch("nssec.modules.waf.utils.package_installed", return_value=True), patch(
            "nssec.modules.waf.utils.file_exists", return_value=True
        ):
            result = runner.invoke(waf, ["evasive", "status"])

        assert result.exit_code == 0
        assert "enabled" in result.output

    def test_shows_not_installed(self, runner):
        """Should indicate when not installed."""
        with patch("nssec.modules.waf.utils.package_installed", return_value=False):
            result = runner.invoke(waf, ["evasive", "status"])

        assert result.exit_code == 0
        assert "no" in result.output.lower()

    def test_default_subcommand_shows_status(self, runner):
        """Running 'waf evasive' without subcommand should show status."""
        with patch("nssec.modules.waf.utils.package_installed", return_value=True), patch(
            "nssec.modules.waf.utils.file_exists", return_value=True
        ):
            result = runner.invoke(waf, ["evasive"])

        assert result.exit_code == 0
        assert "mod_evasive Status" in result.output


class TestWafInitNodeping:
    """Tests for waf init command with NodePing IP fetching."""

    def test_fetches_nodeping_ips_during_init(self, runner, mock_installer):
        """Should fetch NodePing IPs and pass to run()."""
        pf = mock_installer.preflight.return_value
        pf.can_proceed = True
        pf.crs_installed = True
        pf.crs_version = "4.8.0"
        pf.warnings = []

        run_result = MagicMock()
        run_result.success = True
        run_result.steps_completed = ["Done"]
        run_result.steps_skipped = []
        run_result.warnings = []
        run_result.errors = []
        mock_installer.run.return_value = run_result
        mock_installer.reload_apache.return_value = MagicMock(success=True, message="Reloaded")

        with patch(
            "nssec.modules.waf.fetch_nodeping_probe_ips",
            return_value=(["52.71.195.82"], ""),
        ):
            result = runner.invoke(waf, ["init", "-y"])

        assert result.exit_code == 0
        # Verify NodePing IPs were passed to run()
        mock_installer.run.assert_called_once()
        call_kwargs = mock_installer.run.call_args
        assert call_kwargs.kwargs.get("nodeping_ips") == ["52.71.195.82"]

    def test_warns_on_nodeping_fetch_failure(self, runner, mock_installer):
        """Should warn but continue when NodePing fetch fails."""
        pf = mock_installer.preflight.return_value
        pf.can_proceed = True
        pf.crs_installed = True
        pf.crs_version = "4.8.0"
        pf.warnings = []

        run_result = MagicMock()
        run_result.success = True
        run_result.steps_completed = ["Done"]
        run_result.steps_skipped = []
        run_result.warnings = []
        run_result.errors = []
        mock_installer.run.return_value = run_result
        mock_installer.reload_apache.return_value = MagicMock(success=True, message="Reloaded")

        with patch(
            "nssec.modules.waf.fetch_nodeping_probe_ips",
            return_value=([], "Connection error"),
        ):
            result = runner.invoke(waf, ["init", "-y"])

        assert result.exit_code == 0
        assert "Warning" in result.output


class TestWafUpdateExclusionsNodeping:
    """Tests for waf update-exclusions command with NodePing IPs."""

    def test_fetches_nodeping_ips_during_update(self, runner, mock_installer):
        """Should fetch NodePing IPs and pass to install_exclusions()."""
        step = MagicMock()
        step.success = True
        step.message = "Updated"
        mock_installer.install_exclusions.return_value = step
        mock_installer.validate_config.return_value = step
        mock_installer.reload_apache.return_value = step

        with patch(
            "nssec.modules.waf.fetch_nodeping_probe_ips",
            return_value=(["52.71.195.82", "3.21.118.250"], ""),
        ):
            result = runner.invoke(waf, ["update-exclusions", "-y"])

        assert result.exit_code == 0
        mock_installer.install_exclusions.assert_called_once()
        call_kwargs = mock_installer.install_exclusions.call_args
        assert call_kwargs.kwargs.get("nodeping_ips") == ["52.71.195.82", "3.21.118.250"]

    def test_warns_on_nodeping_fetch_failure_update(self, runner, mock_installer):
        """Should warn but continue when NodePing fetch fails during update."""
        step = MagicMock()
        step.success = True
        step.message = "Updated"
        mock_installer.install_exclusions.return_value = step
        mock_installer.validate_config.return_value = step
        mock_installer.reload_apache.return_value = step

        with patch(
            "nssec.modules.waf.fetch_nodeping_probe_ips",
            return_value=([], "Timeout"),
        ):
            result = runner.invoke(waf, ["update-exclusions", "-y"])

        assert result.exit_code == 0
        assert "Warning" in result.output


class TestWafUpdate:
    """Tests for waf update command."""

    def test_requires_root(self, runner, mock_installer):
        """Should fail if not root."""
        mock_installer.preflight.return_value.is_root = False

        with patch("nssec.modules.waf.utils.detect_modsec_version", return_value="2.9.5"), patch(
            "nssec.modules.waf.utils.version_gte", return_value=False
        ):
            result = runner.invoke(waf, ["update", "-y"])

        assert result.exit_code == 1
        assert "root" in result.output.lower()

    def test_shows_instructions_when_old(self, runner, mock_installer):
        """Should show Digitalwave repo instructions when ModSec < 2.9.6."""
        with patch("nssec.modules.waf.utils.detect_modsec_version", return_value="2.9.5"), patch(
            "nssec.modules.waf.utils.version_gte", return_value=False
        ):
            result = runner.invoke(waf, ["update", "-y"])

        assert result.exit_code == 0
        assert "Digitalwave" in result.output
        assert "signed-by=" in result.output
        assert "apt-get update" in result.output

    def test_nothing_to_do_when_current_no_disabled(self, runner, mock_installer):
        """Should report nothing to do when >= 2.9.6 and no disabled rules."""
        mock_installer._reenable_crs_rules.return_value = []
        mock_installer.preflight.return_value.crs_path = "/etc/modsecurity/crs"

        with patch("nssec.modules.waf.utils.detect_modsec_version", return_value="2.9.7"), patch(
            "nssec.modules.waf.utils.version_gte", return_value=True
        ):
            result = runner.invoke(waf, ["update", "-y"])

        assert result.exit_code == 0
        assert "Nothing to do" in result.output

    def test_reenables_rules_after_upgrade(self, runner, mock_installer):
        """Should re-enable disabled rules when ModSec >= 2.9.6."""
        mock_installer._reenable_crs_rules.return_value = ["REQUEST-922-MULTIPART-ATTACK.conf"]
        mock_installer.preflight.return_value.crs_path = "/etc/modsecurity/crs"

        validate_result = MagicMock()
        validate_result.success = True
        validate_result.message = "Apache config test passed"
        mock_installer.validate_config.return_value = validate_result

        reload_result = MagicMock()
        reload_result.success = True
        reload_result.message = "Apache reloaded"
        mock_installer.reload_apache.return_value = reload_result

        with patch("nssec.modules.waf.utils.detect_modsec_version", return_value="2.9.7"), patch(
            "nssec.modules.waf.utils.version_gte", return_value=True
        ):
            result = runner.invoke(waf, ["update", "-y"])

        assert result.exit_code == 0
        mock_installer._reenable_crs_rules.assert_called_once()
        assert "Re-enabled" in result.output
