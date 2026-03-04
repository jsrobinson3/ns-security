"""Tests for WAF module functions."""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, call, ANY
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

    def _render_template(self, profile="standard", **overrides):
        """Helper to render evasive template with profile defaults."""
        from nssec.modules.waf.config import EVASIVE_CONF_TEMPLATE, EVASIVE_PROFILES

        params = {
            "timestamp": "test",
            "profile": profile,
            "log_dir": "/var/log/apache2/mod_evasive",
            "log_file": "/var/log/apache2/mod_evasive.log",
            **EVASIVE_PROFILES[profile],
            **overrides,
        }
        return Template(EVASIVE_CONF_TEMPLATE).render(**params)

    def test_template_renders_with_required_directives(self):
        """Should render a valid evasive.conf with all key directives."""
        rendered = self._render_template()
        assert "DOSHashTableSize" in rendered
        assert "DOSPageCount" in rendered
        assert "DOSSiteCount" in rendered
        assert "DOSBlockingPeriod" in rendered
        assert "DOSWhitelist" in rendered
        assert "127.0.0.1" in rendered
        assert "/var/log/apache2/mod_evasive" in rendered

    def test_template_whitelists_rfc1918(self):
        """Should whitelist all RFC 1918 private ranges."""
        rendered = self._render_template()
        assert "10.*.*.*" in rendered
        assert "172.16.*.*" in rendered
        assert "172.31.*.*" in rendered
        assert "192.168.*.*" in rendered

    def test_standard_profile_has_high_thresholds(self):
        """Standard profile should have high thresholds for safety."""
        rendered = self._render_template("standard")
        assert "DOSPageCount            100" in rendered
        assert "DOSSiteCount            500" in rendered
        assert "DOSBlockingPeriod       10" in rendered

    def test_strict_profile_has_tuned_thresholds(self):
        """Strict profile should have tighter thresholds for NS traffic."""
        rendered = self._render_template("strict")
        assert "DOSPageCount            15" in rendered
        assert "DOSSiteCount            60" in rendered
        assert "DOSBlockingPeriod       60" in rendered

    def test_template_renders_dos_system_command(self):
        """Should render DOSSystemCommand for structured logging."""
        rendered = self._render_template()
        assert "DOSSystemCommand" in rendered
        assert "/var/log/apache2/mod_evasive.log" in rendered
        assert "action=blocked" in rendered
        assert "src_ip=%s" in rendered

    def test_template_includes_profile_name(self):
        """Should include the profile name in the config comment."""
        rendered = self._render_template("strict")
        assert "Profile: strict" in rendered


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

    def test_passes_log_file_to_render(self, mock_file_ops):
        """Should pass log_file parameter to render."""
        from nssec.modules.waf import ModSecurityInstaller
        from nssec.modules.waf.config import EVASIVE_LOG_FILE

        with patch("nssec.modules.waf.Path"):
            installer = ModSecurityInstaller(mode="On")
            installer.setup_evasive_config()

        render_call = mock_file_ops["render"].call_args
        assert EVASIVE_LOG_FILE in str(render_call)


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
    """Tests for set_mode NOT toggling mod_evasive (decoupled)."""

    def test_enable_mode_does_not_toggle_evasive(self, mock_file_ops):
        """Switching to On mode should NOT enable mod_evasive."""
        from nssec.modules.waf import ModSecurityInstaller

        mock_file_ops["read"].return_value = "SecRuleEngine DetectionOnly\n"
        with patch("nssec.modules.waf.package_installed", return_value=True), \
             patch("nssec.modules.waf.run_cmd", return_value=("", "", 0)) as mock_run:
            mock_file_ops["exists"].return_value = False
            installer = ModSecurityInstaller()
            result = installer.set_mode("On")

        assert result.success
        # Should NOT have called a2enmod/a2dismod evasive
        run_calls = [str(c) for c in mock_run.call_args_list]
        assert not any("evasive" in c for c in run_calls)

    def test_detect_mode_does_not_toggle_evasive(self, mock_file_ops):
        """Switching to DetectionOnly should NOT disable mod_evasive."""
        from nssec.modules.waf import ModSecurityInstaller

        mock_file_ops["read"].return_value = "SecRuleEngine On\n"
        with patch("nssec.modules.waf.package_installed", return_value=True), \
             patch("nssec.modules.waf.run_cmd", return_value=("", "", 0)) as mock_run:
            mock_file_ops["exists"].return_value = True
            installer = ModSecurityInstaller()
            result = installer.set_mode("DetectionOnly")

        assert result.success
        run_calls = [str(c) for c in mock_run.call_args_list]
        assert not any("evasive" in c for c in run_calls)
        # Message should NOT mention mod_evasive
        assert "mod_evasive" not in result.message


class TestFetchNodepingProbeIps:
    """Tests for fetch_nodeping_probe_ips function."""

    def test_returns_ips_from_mtls_util(self):
        """Should delegate to mTLS fetch_nodeping_ips utility."""
        from nssec.modules.waf import fetch_nodeping_probe_ips

        with patch(
            "nssec.modules.mtls.utils.fetch_nodeping_ips",
            return_value=(["52.71.195.82", "3.21.118.250"], ""),
        ):
            ips, err = fetch_nodeping_probe_ips()

        assert ips == ["52.71.195.82", "3.21.118.250"]
        assert err == ""

    def test_returns_error_on_failure(self):
        """Should propagate error from mTLS utility."""
        from nssec.modules.waf import fetch_nodeping_probe_ips

        with patch(
            "nssec.modules.mtls.utils.fetch_nodeping_ips",
            return_value=([], "Failed to fetch NodePing IPs: connection error"),
        ):
            ips, err = fetch_nodeping_probe_ips()

        assert ips == []
        assert "Failed to fetch" in err


class TestInstallExclusionsWithNodeping:
    """Tests for install_exclusions with nodeping_ips parameter."""

    def test_passes_nodeping_ips_to_template(self, mock_file_ops):
        """Should pass nodeping_ips to the exclusions template."""
        from nssec.modules.waf import ModSecurityInstaller

        installer = ModSecurityInstaller()
        nodeping = ["52.71.195.82", "3.21.118.250"]
        result = installer.install_exclusions(nodeping_ips=nodeping)

        assert result.success
        render_call = mock_file_ops["render"].call_args
        assert render_call[1].get("nodeping_ips") == nodeping or \
            nodeping in render_call[0] if render_call[0] else False

    def test_defaults_to_empty_nodeping_list(self, mock_file_ops):
        """Should default to empty list when no nodeping_ips provided."""
        from nssec.modules.waf import ModSecurityInstaller

        installer = ModSecurityInstaller()
        result = installer.install_exclusions()

        assert result.success
        render_call = mock_file_ops["render"].call_args
        # nodeping_ips should be an empty list
        assert render_call[1].get("nodeping_ips") == [] or \
            render_call.kwargs.get("nodeping_ips") == []

    def test_passes_both_admin_and_nodeping_ips(self, mock_file_ops):
        """Should pass both admin_ips and nodeping_ips to template."""
        from nssec.modules.waf import ModSecurityInstaller

        installer = ModSecurityInstaller()
        admin = ["192.168.1.100"]
        nodeping = ["52.71.195.82"]
        result = installer.install_exclusions(admin_ips=admin, nodeping_ips=nodeping)

        assert result.success
        render_call = mock_file_ops["render"].call_args
        assert render_call.kwargs.get("admin_ips") == admin
        assert render_call.kwargs.get("nodeping_ips") == nodeping


class TestNodepingExclusionsTemplate:
    """Tests for NS_EXCLUSIONS_TEMPLATE with NodePing IPs."""

    def test_renders_nodeping_section(self):
        """Should render NodePing IP rules in the exclusions template."""
        from nssec.modules.waf.config import NS_EXCLUSIONS_TEMPLATE

        rendered = Template(NS_EXCLUSIONS_TEMPLATE).render(
            timestamp="test",
            admin_ips=[],
            nodeping_ips=["52.71.195.82", "3.21.118.250"],
        )
        assert "NodePing monitoring probe IPs" in rendered
        assert "52.71.195.82" in rendered
        assert "3.21.118.250" in rendered
        assert "id:1000201" in rendered
        assert "id:1000202" in rendered

    def test_omits_nodeping_section_when_empty(self):
        """Should not render NodePing section when list is empty."""
        from nssec.modules.waf.config import NS_EXCLUSIONS_TEMPLATE

        rendered = Template(NS_EXCLUSIONS_TEMPLATE).render(
            timestamp="test",
            admin_ips=[],
            nodeping_ips=[],
        )
        assert "NodePing" not in rendered

    def test_nodeping_rule_ids_separate_from_admin(self):
        """NodePing rules should use 1000200+ range, admin uses 1000100+."""
        from nssec.modules.waf.config import NS_EXCLUSIONS_TEMPLATE

        rendered = Template(NS_EXCLUSIONS_TEMPLATE).render(
            timestamp="test",
            admin_ips=["192.168.1.100"],
            nodeping_ips=["52.71.195.82"],
        )
        assert "id:1000101" in rendered  # admin IP
        assert "id:1000201" in rendered  # NodePing IP

    def test_nodeping_rules_bypass_crs(self):
        """NodePing rules should bypass all CRS rules."""
        from nssec.modules.waf.config import NS_EXCLUSIONS_TEMPLATE

        rendered = Template(NS_EXCLUSIONS_TEMPLATE).render(
            timestamp="test",
            admin_ips=[],
            nodeping_ips=["52.71.195.82"],
        )
        # Find the NodePing rule section
        lines = rendered.split("\n")
        nodeping_rule_lines = [l for l in lines if "1000201" in l]
        assert len(nodeping_rule_lines) > 0
        assert "ruleRemoveByTag=OWASP_CRS" in rendered


class TestInstallCrsV4UpdatesSetup:
    """Tests for install_crs_v4 updating crs-setup.conf when v4 already present."""

    def test_updates_crs_setup_when_v4_present(self, mock_file_ops):
        """Should update crs-setup.conf even when CRS v4 is already installed."""
        from nssec.modules.waf import ModSecurityInstaller

        installer = ModSecurityInstaller()
        pf = MagicMock()
        pf.crs_installed = True
        pf.crs_version = "4.8.0"
        pf.crs_path = "/etc/modsecurity/crs"
        pf.can_proceed = True
        installer._preflight = pf

        with patch("nssec.modules.waf.detect_modsec_version", return_value="2.9.7"), \
             patch("nssec.modules.waf.version_gte", return_value=True):
            result = installer.install_crs_v4()

        assert result.skipped
        assert "crs-setup.conf updated" in result.message
        # Should have called write_file for crs-setup.conf
        mock_file_ops["write"].assert_called_once()
        write_args = mock_file_ops["write"].call_args
        assert "crs-setup.conf" in write_args[0][0]

    def test_skips_setup_update_renders_template(self, mock_file_ops):
        """Should render the CRS_SETUP_OVERRIDES_TEMPLATE when updating."""
        from nssec.modules.waf import ModSecurityInstaller

        installer = ModSecurityInstaller()
        pf = MagicMock()
        pf.crs_installed = True
        pf.crs_version = "4.8.0"
        pf.crs_path = "/etc/modsecurity/crs"
        pf.can_proceed = True
        installer._preflight = pf

        with patch("nssec.modules.waf.detect_modsec_version", return_value="2.9.7"), \
             patch("nssec.modules.waf.version_gte", return_value=True):
            installer.install_crs_v4()

        # render should have been called for crs-setup.conf
        mock_file_ops["render"].assert_called_once()


class TestPreflightCacheRefresh:
    """Tests for preflight cache being cleared after CRS download."""

    def test_clears_preflight_after_download(self, mock_file_ops):
        """Should clear _preflight cache after successful CRS download."""
        from nssec.modules.waf import ModSecurityInstaller

        with patch("nssec.modules.waf.run_cmd", return_value=("", "", 0)), \
             patch("nssec.modules.waf.Path"):
            installer = ModSecurityInstaller()
            pf = MagicMock()
            pf.crs_installed = False
            pf.crs_version = None
            pf.crs_path = None
            pf.can_proceed = True
            installer._preflight = pf

            result = installer._download_crs_from_github()

        assert result.success
        assert installer._preflight is None

    def test_does_not_clear_preflight_on_download_failure(self, mock_file_ops):
        """Should not clear preflight cache if download fails."""
        from nssec.modules.waf import ModSecurityInstaller

        with patch("nssec.modules.waf.run_cmd", return_value=("", "error", 1)):
            installer = ModSecurityInstaller()
            pf = MagicMock()
            installer._preflight = pf

            result = installer._download_crs_from_github()

        assert not result.success
        assert installer._preflight is pf  # unchanged


class TestDisableIncompatibleCrsRules:
    """Tests for ModSecurityInstaller._disable_incompatible_crs_rules."""

    def test_disables_rules_on_old_modsec(self, tmp_path, mock_file_ops):
        """Should rename .conf to .conf.disabled when ModSec < 2.9.6."""
        from nssec.modules.waf import ModSecurityInstaller

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        rule_file = rules_dir / "REQUEST-922-MULTIPART-ATTACK.conf"
        rule_file.write_text("# rule content")

        with patch("nssec.modules.waf.detect_modsec_version", return_value="2.9.5"), \
             patch("nssec.modules.waf.version_gte", side_effect=lambda v, t: False):
            installer = ModSecurityInstaller()
            disabled = installer._disable_incompatible_crs_rules(str(tmp_path))

        assert disabled == ["REQUEST-922-MULTIPART-ATTACK.conf"]
        assert (rules_dir / "REQUEST-922-MULTIPART-ATTACK.conf.disabled").exists()
        assert not rule_file.exists()

    def test_skips_on_new_modsec(self, tmp_path, mock_file_ops):
        """Should not disable rules when ModSec >= 2.9.6."""
        from nssec.modules.waf import ModSecurityInstaller

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        rule_file = rules_dir / "REQUEST-922-MULTIPART-ATTACK.conf"
        rule_file.write_text("# rule content")

        with patch("nssec.modules.waf.detect_modsec_version", return_value="2.9.6"), \
             patch("nssec.modules.waf.version_gte", side_effect=lambda v, t: True):
            installer = ModSecurityInstaller()
            disabled = installer._disable_incompatible_crs_rules(str(tmp_path))

        assert disabled == []
        assert rule_file.exists()

    def test_skips_already_disabled(self, tmp_path, mock_file_ops):
        """Should not rename if .conf.disabled already exists."""
        from nssec.modules.waf import ModSecurityInstaller

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        # Both files exist — should not touch them
        (rules_dir / "REQUEST-922-MULTIPART-ATTACK.conf").write_text("# rule")
        (rules_dir / "REQUEST-922-MULTIPART-ATTACK.conf.disabled").write_text("# disabled")

        with patch("nssec.modules.waf.detect_modsec_version", return_value="2.9.5"), \
             patch("nssec.modules.waf.version_gte", side_effect=lambda v, t: False):
            installer = ModSecurityInstaller()
            disabled = installer._disable_incompatible_crs_rules(str(tmp_path))

        assert disabled == []

    def test_handles_missing_rule_file(self, tmp_path, mock_file_ops):
        """Should handle case where rule file doesn't exist."""
        from nssec.modules.waf import ModSecurityInstaller

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        # No rule files created

        with patch("nssec.modules.waf.detect_modsec_version", return_value="2.9.5"), \
             patch("nssec.modules.waf.version_gte", side_effect=lambda v, t: False):
            installer = ModSecurityInstaller()
            disabled = installer._disable_incompatible_crs_rules(str(tmp_path))

        assert disabled == []


class TestReenableCrsRules:
    """Tests for ModSecurityInstaller._reenable_crs_rules."""

    def test_reenables_disabled_rules(self, tmp_path, mock_file_ops):
        """Should rename .conf.disabled back to .conf."""
        from nssec.modules.waf import ModSecurityInstaller

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        disabled_file = rules_dir / "REQUEST-922-MULTIPART-ATTACK.conf.disabled"
        disabled_file.write_text("# rule content")

        installer = ModSecurityInstaller()
        reenabled = installer._reenable_crs_rules(str(tmp_path))

        assert reenabled == ["REQUEST-922-MULTIPART-ATTACK.conf"]
        assert (rules_dir / "REQUEST-922-MULTIPART-ATTACK.conf").exists()
        assert not disabled_file.exists()

    def test_skips_when_target_exists(self, tmp_path, mock_file_ops):
        """Should not rename if .conf already exists (avoid overwrite)."""
        from nssec.modules.waf import ModSecurityInstaller

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "REQUEST-922-MULTIPART-ATTACK.conf").write_text("# active")
        (rules_dir / "REQUEST-922-MULTIPART-ATTACK.conf.disabled").write_text("# old")

        installer = ModSecurityInstaller()
        reenabled = installer._reenable_crs_rules(str(tmp_path))

        assert reenabled == []

    def test_returns_empty_when_nothing_disabled(self, tmp_path, mock_file_ops):
        """Should return empty list when no disabled files found."""
        from nssec.modules.waf import ModSecurityInstaller

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "REQUEST-922-MULTIPART-ATTACK.conf").write_text("# active")

        installer = ModSecurityInstaller()
        reenabled = installer._reenable_crs_rules(str(tmp_path))

        assert reenabled == []


