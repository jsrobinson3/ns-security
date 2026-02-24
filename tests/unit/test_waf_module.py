"""Tests for WAF module functions."""

import pytest
from unittest.mock import patch, MagicMock, call
from jinja2 import Template


class TestGetAllowlistedIps:
    """Tests for get_allowlisted_ips function."""

    def test_returns_empty_list_when_no_config(self, mock_file_ops):
        """Should return empty list when exclusions config doesn't exist."""
        from nssec.modules.waf import get_allowlisted_ips

        mock_file_ops["read"].return_value = None
        result = get_allowlisted_ips()
        assert result == []

    def test_returns_empty_list_when_no_ips(self, mock_file_ops):
        """Should return empty list when no IPs in config."""
        from nssec.modules.waf import get_allowlisted_ips

        mock_file_ops["read"].return_value = """
# Some config without allowlisted IPs
SecRule REQUEST_URI "@beginsWith /cfg/" "id:1000004"
"""
        result = get_allowlisted_ips()
        assert result == []

    def test_parses_single_ip(self, mock_file_ops):
        """Should parse a single allowlisted IP."""
        from nssec.modules.waf import get_allowlisted_ips

        mock_file_ops["read"].return_value = """
SecRule REMOTE_ADDR "@ipMatch 192.168.1.100" "id:1000101,phase:1,pass"
"""
        result = get_allowlisted_ips()
        assert result == ["192.168.1.100"]

    def test_parses_multiple_ips(self, mock_file_ops):
        """Should parse multiple allowlisted IPs."""
        from nssec.modules.waf import get_allowlisted_ips

        mock_file_ops["read"].return_value = """
SecRule REMOTE_ADDR "@ipMatch 192.168.1.100" "id:1000101,phase:1,pass"
SecRule REMOTE_ADDR "@ipMatch 10.0.0.0/8" "id:1000102,phase:1,pass"
SecRule REMOTE_ADDR "@ipMatch 74.219.23.50" "id:1000103,phase:1,pass"
"""
        result = get_allowlisted_ips()
        assert result == ["192.168.1.100", "10.0.0.0/8", "74.219.23.50"]

    def test_parses_cidr_notation(self, mock_file_ops):
        """Should correctly parse CIDR notation IPs."""
        from nssec.modules.waf import get_allowlisted_ips

        mock_file_ops["read"].return_value = """
SecRule REMOTE_ADDR "@ipMatch 10.0.0.0/8" "id:1000101,phase:1,pass"
"""
        result = get_allowlisted_ips()
        assert result == ["10.0.0.0/8"]


class TestAddAllowlistedIp:
    """Tests for add_allowlisted_ip function."""

    def test_adds_new_ip(self, mock_file_ops):
        """Should add a new IP to the allowlist."""
        from nssec.modules.waf import add_allowlisted_ip

        mock_file_ops["read"].return_value = ""
        result = add_allowlisted_ip("192.168.1.100")

        assert result.success
        assert "192.168.1.100" in result.message
        mock_file_ops["write"].assert_called_once()

    def test_skips_duplicate_ip(self, mock_file_ops):
        """Should skip if IP already in allowlist."""
        from nssec.modules.waf import add_allowlisted_ip

        mock_file_ops["read"].return_value = """
SecRule REMOTE_ADDR "@ipMatch 192.168.1.100" "id:1000101,phase:1,pass"
"""
        result = add_allowlisted_ip("192.168.1.100")

        assert result.skipped
        mock_file_ops["write"].assert_not_called()

    def test_creates_backup_before_write(self, mock_file_ops):
        """Should backup existing config before writing."""
        from nssec.modules.waf import add_allowlisted_ip

        mock_file_ops["read"].return_value = ""
        mock_file_ops["exists"].return_value = True
        add_allowlisted_ip("192.168.1.100")

        mock_file_ops["backup"].assert_called_once()

    def test_returns_error_on_write_failure(self, mock_file_ops):
        """Should return error if write fails."""
        from nssec.modules.waf import add_allowlisted_ip

        mock_file_ops["read"].return_value = ""
        mock_file_ops["write"].return_value = False
        result = add_allowlisted_ip("192.168.1.100")

        assert not result.success
        assert "Failed to write" in result.error


class TestRemoveAllowlistedIp:
    """Tests for remove_allowlisted_ip function."""

    def test_removes_existing_ip(self, mock_file_ops):
        """Should remove an existing IP from allowlist."""
        from nssec.modules.waf import remove_allowlisted_ip

        mock_file_ops["read"].return_value = """
SecRule REMOTE_ADDR "@ipMatch 192.168.1.100" "id:1000101,phase:1,pass"
SecRule REMOTE_ADDR "@ipMatch 10.0.0.1" "id:1000102,phase:1,pass"
"""
        result = remove_allowlisted_ip("192.168.1.100")

        assert result.success
        assert "192.168.1.100" in result.message
        mock_file_ops["write"].assert_called_once()

    def test_skips_nonexistent_ip(self, mock_file_ops):
        """Should skip if IP not in allowlist."""
        from nssec.modules.waf import remove_allowlisted_ip

        mock_file_ops["read"].return_value = ""
        result = remove_allowlisted_ip("192.168.1.100")

        assert result.skipped
        mock_file_ops["write"].assert_not_called()

    def test_creates_backup_before_write(self, mock_file_ops):
        """Should backup existing config before writing."""
        from nssec.modules.waf import remove_allowlisted_ip

        mock_file_ops["read"].return_value = """
SecRule REMOTE_ADDR "@ipMatch 192.168.1.100" "id:1000101,phase:1,pass"
"""
        mock_file_ops["exists"].return_value = True
        remove_allowlisted_ip("192.168.1.100")

        mock_file_ops["backup"].assert_called_once()

    def test_returns_error_on_write_failure(self, mock_file_ops):
        """Should return error if write fails."""
        from nssec.modules.waf import remove_allowlisted_ip

        mock_file_ops["read"].return_value = """
SecRule REMOTE_ADDR "@ipMatch 192.168.1.100" "id:1000101,phase:1,pass"
"""
        mock_file_ops["write"].return_value = False
        result = remove_allowlisted_ip("192.168.1.100")

        assert not result.success
        assert "Failed to write" in result.error


class TestEvasiveConfTemplate:
    """Tests for the evasive.conf Jinja2 template."""

    def test_template_renders_with_required_directives(self):
        """Should render a valid evasive.conf with all key directives."""
        from nssec.modules.waf.config import EVASIVE_CONF_TEMPLATE

        rendered = Template(EVASIVE_CONF_TEMPLATE).render(
            timestamp="2026-01-01 00:00 UTC",
            log_dir="/var/log/apache2/mod_evasive",
        )
        assert "DOSHashTableSize" in rendered
        assert "DOSPageCount" in rendered
        assert "DOSSiteCount" in rendered
        assert "DOSBlockingPeriod" in rendered
        assert "DOSWhitelist" in rendered
        assert "127.0.0.1" in rendered
        assert "/var/log/apache2/mod_evasive" in rendered

    def test_template_whitelists_rfc1918(self):
        """Should whitelist all RFC 1918 private ranges."""
        from nssec.modules.waf.config import EVASIVE_CONF_TEMPLATE

        rendered = Template(EVASIVE_CONF_TEMPLATE).render(
            timestamp="test", log_dir="/tmp",
        )
        assert "10.*.*.*" in rendered
        assert "172.16.*.*" in rendered
        assert "172.31.*.*" in rendered
        assert "192.168.*.*" in rendered

    def test_template_has_tuned_thresholds(self):
        """Thresholds should be tuned for NetSapiens traffic patterns."""
        from nssec.modules.waf.config import EVASIVE_CONF_TEMPLATE

        rendered = Template(EVASIVE_CONF_TEMPLATE).render(
            timestamp="test",
            log_dir="/tmp",
        )
        # DOSPageCount should be > 2 (default is too aggressive)
        assert "DOSPageCount            15" in rendered
        # DOSSiteCount tuned for ~318 peak req/s across ~372 IPs
        assert "DOSSiteCount            60" in rendered
        # Extended blocking period for active scanners
        assert "DOSBlockingPeriod       60" in rendered


class TestSetupEvasiveConfig:
    """Tests for ModSecurityInstaller.setup_evasive_config."""

    def test_writes_evasive_config(self, mock_file_ops):
        """Should write evasive config with tuned thresholds."""
        from nssec.modules.waf import ModSecurityInstaller

        with patch("nssec.modules.waf.Path"):
            installer = ModSecurityInstaller(mode="On")
            result = installer.setup_evasive_config()

        assert result.success
        assert "evasive" in result.message.lower()
        mock_file_ops["write"].assert_called_once()

    def test_skips_when_evasive_disabled(self, mock_file_ops):
        """Should skip when install_evasive is False."""
        from nssec.modules.waf import ModSecurityInstaller

        installer = ModSecurityInstaller(install_evasive=False)
        result = installer.setup_evasive_config()

        assert result.skipped
        mock_file_ops["write"].assert_not_called()

    def test_dry_run_does_not_write(self, mock_file_ops):
        """Should not write in dry run mode."""
        from nssec.modules.waf import ModSecurityInstaller

        installer = ModSecurityInstaller(dry_run=True)
        result = installer.setup_evasive_config()

        assert result.success
        assert "Would write" in result.message
        mock_file_ops["write"].assert_not_called()

    def test_backs_up_existing_config(self, mock_file_ops):
        """Should backup existing evasive config before writing."""
        from nssec.modules.waf import ModSecurityInstaller

        mock_file_ops["exists"].return_value = True
        with patch("nssec.modules.waf.Path"):
            installer = ModSecurityInstaller(mode="On")
            installer.setup_evasive_config()

        mock_file_ops["backup"].assert_called()

    def test_returns_error_on_write_failure(self, mock_file_ops):
        """Should return error if write fails."""
        from nssec.modules.waf import ModSecurityInstaller

        mock_file_ops["write"].return_value = False
        installer = ModSecurityInstaller(mode="On")
        result = installer.setup_evasive_config()

        assert not result.success
        assert "Failed to write" in result.error


class TestSetEvasiveState:
    """Tests for ModSecurityInstaller.set_evasive_state."""

    def test_enables_evasive_module(self, mock_file_ops):
        """Should run a2enmod evasive when enabling."""
        from nssec.modules.waf import ModSecurityInstaller

        with patch("nssec.modules.waf.package_installed", return_value=True), \
             patch("nssec.modules.waf.run_cmd", return_value=("", "", 0)) as mock_run:
            mock_file_ops["exists"].return_value = False  # not currently enabled
            installer = ModSecurityInstaller()
            result = installer.set_evasive_state(enable=True)

        assert result.success
        assert "Enabled" in result.message
        mock_run.assert_called_once_with(["a2enmod", "evasive"])

    def test_disables_evasive_module(self, mock_file_ops):
        """Should run a2dismod evasive when disabling."""
        from nssec.modules.waf import ModSecurityInstaller

        with patch("nssec.modules.waf.package_installed", return_value=True), \
             patch("nssec.modules.waf.run_cmd", return_value=("", "", 0)) as mock_run:
            mock_file_ops["exists"].return_value = True  # currently enabled
            installer = ModSecurityInstaller()
            result = installer.set_evasive_state(enable=False)

        assert result.success
        assert "Disabled" in result.message
        mock_run.assert_called_once_with(["a2dismod", "evasive"])

    def test_skips_if_already_enabled(self, mock_file_ops):
        """Should skip if evasive already enabled and requesting enable."""
        from nssec.modules.waf import ModSecurityInstaller

        with patch("nssec.modules.waf.package_installed", return_value=True):
            mock_file_ops["exists"].return_value = True  # already enabled
            installer = ModSecurityInstaller()
            result = installer.set_evasive_state(enable=True)

        assert result.skipped
        assert "already enabled" in result.message

    def test_skips_if_already_disabled(self, mock_file_ops):
        """Should skip if evasive already disabled and requesting disable."""
        from nssec.modules.waf import ModSecurityInstaller

        with patch("nssec.modules.waf.package_installed", return_value=True):
            mock_file_ops["exists"].return_value = False  # already disabled
            installer = ModSecurityInstaller()
            result = installer.set_evasive_state(enable=False)

        assert result.skipped
        assert "already disabled" in result.message

    def test_skips_if_not_installed(self, mock_file_ops):
        """Should skip if mod_evasive package not installed."""
        from nssec.modules.waf import ModSecurityInstaller

        with patch("nssec.modules.waf.package_installed", return_value=False):
            installer = ModSecurityInstaller()
            result = installer.set_evasive_state(enable=True)

        assert result.skipped
        assert "not installed" in result.message

    def test_dry_run_does_not_change_state(self, mock_file_ops):
        """Should not run commands in dry run mode."""
        from nssec.modules.waf import ModSecurityInstaller

        with patch("nssec.modules.waf.package_installed", return_value=True), \
             patch("nssec.modules.waf.run_cmd") as mock_run:
            mock_file_ops["exists"].return_value = False
            installer = ModSecurityInstaller(dry_run=True)
            result = installer.set_evasive_state(enable=True)

        assert result.success
        assert "Would enable" in result.message
        mock_run.assert_not_called()

    def test_returns_error_on_command_failure(self, mock_file_ops):
        """Should return error if a2enmod/a2dismod fails."""
        from nssec.modules.waf import ModSecurityInstaller

        with patch("nssec.modules.waf.package_installed", return_value=True), \
             patch("nssec.modules.waf.run_cmd", return_value=("", "error", 1)):
            mock_file_ops["exists"].return_value = False
            installer = ModSecurityInstaller()
            result = installer.set_evasive_state(enable=True)

        assert not result.success
        assert "Failed to enable" in result.error


class TestSetModeEvasiveIntegration:
    """Tests for set_mode toggling mod_evasive alongside ModSecurity."""

    def test_enable_mode_enables_evasive(self, mock_file_ops):
        """Switching to On mode should enable mod_evasive."""
        from nssec.modules.waf import ModSecurityInstaller

        mock_file_ops["read"].return_value = "SecRuleEngine DetectionOnly\n"
        with patch("nssec.modules.waf.package_installed", return_value=True), \
             patch("nssec.modules.waf.run_cmd", return_value=("", "", 0)) as mock_run:
            mock_file_ops["exists"].return_value = False  # evasive not enabled
            installer = ModSecurityInstaller()
            result = installer.set_mode("On")

        assert result.success
        # Should have called a2enmod evasive
        run_calls = [str(c) for c in mock_run.call_args_list]
        assert any("a2enmod" in c and "evasive" in c for c in run_calls)

    def test_detect_mode_disables_evasive(self, mock_file_ops):
        """Switching to DetectionOnly should disable mod_evasive."""
        from nssec.modules.waf import ModSecurityInstaller

        mock_file_ops["read"].return_value = "SecRuleEngine On\n"
        with patch("nssec.modules.waf.package_installed", return_value=True), \
             patch("nssec.modules.waf.run_cmd", return_value=("", "", 0)) as mock_run:
            mock_file_ops["exists"].return_value = True  # evasive currently enabled
            installer = ModSecurityInstaller()
            result = installer.set_mode("DetectionOnly")

        assert result.success
        # Should have called a2dismod evasive
        run_calls = [str(c) for c in mock_run.call_args_list]
        assert any("a2dismod" in c and "evasive" in c for c in run_calls)
        assert "mod_evasive disabled" in result.message
