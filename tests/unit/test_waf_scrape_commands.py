"""Tests for the 'nssec waf scrape-protection' CLI commands."""

from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from nssec.cli.waf_commands import waf
from nssec.modules.waf.scrape import ScrapeSettings, ScrapeStatus
from nssec.modules.waf.types import StepResult


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def installer():
    with patch("nssec.modules.waf.ModSecurityInstaller") as mock_class:
        inst = MagicMock()
        mock_class.return_value = inst
        pf = MagicMock()
        pf.is_root = True
        pf.modsec_installed = True
        pf.modsec_enabled = True
        pf.modsec_mode = "On"
        inst.preflight.return_value = pf
        inst.reload_apache.return_value = StepResult(message="Apache reloaded")
        yield inst


@pytest.fixture
def scrape_mod():
    """Patch every side-effecting function the CLI calls on the scrape module."""
    defaults = {
        "load_deployed_settings": None,
        "is_deployed": False,
        "get_local_ips": ["203.0.113.10"],
        "resolve_exempt_ips": ["127.0.0.1", "::1"],
        "ensure_security2_include": StepResult(message="Added include"),
        "write_scrape_conf": StepResult(message="Wrote conf"),
        "remove_scrape_conf": StepResult(message="Removed conf"),
        "validate_apache_config": StepResult(message="Apache config test passed"),
        "rollback_scrape": None,
        "get_scrape_status": ScrapeStatus(),
    }
    with ExitStack() as stack:
        mocks = {
            name: stack.enter_context(patch(f"nssec.modules.waf.scrape.{name}", return_value=value))
            for name, value in defaults.items()
        }
        mocks["get_allowlisted_ips"] = stack.enter_context(
            patch("nssec.modules.waf.get_allowlisted_ips", return_value=["198.51.100.1"])
        )
        yield mocks


def _written_settings(scrape_mod):
    return scrape_mod["write_scrape_conf"].call_args[0][0]


class TestScrapeEnable:
    def test_defaults_to_detect_mode(self, runner, installer, scrape_mod):
        result = runner.invoke(waf, ["scrape-protection", "enable", "-y"])

        assert result.exit_code == 0, result.output
        settings = _written_settings(scrape_mod)
        assert settings.mode == "detect"
        assert settings.profile == "standard"
        scrape_mod["validate_apache_config"].assert_called_once_with(
            conf_existed=False, security2_changed=True
        )
        installer.reload_apache.assert_called_once()

    def test_passes_allowlist_and_local_ips_to_exemption_policy(
        self, runner, installer, scrape_mod
    ):
        runner.invoke(waf, ["scrape-protection", "enable", "-y"])

        args = scrape_mod["resolve_exempt_ips"].call_args[0]
        assert args[1] == ["198.51.100.1"]
        assert args[2] == ["203.0.113.10"]
        assert scrape_mod["write_scrape_conf"].call_args[0][1] == ["127.0.0.1", "::1"]

    def test_keeps_deployed_settings_and_applies_overrides(self, runner, installer, scrape_mod):
        scrape_mod["load_deployed_settings"].return_value = ScrapeSettings(
            mode="block", profile="strict", exempt_ips=["198.51.100.9"]
        )

        result = runner.invoke(
            waf,
            [
                "scrape-protection",
                "enable",
                "--max-domains",
                "20",
                "--exempt-ip",
                "192.0.2.1",
                "-y",
            ],
        )

        assert result.exit_code == 0, result.output
        settings = _written_settings(scrape_mod)
        assert settings.mode == "block"
        assert settings.profile == "strict"
        assert settings.max_domains == 20
        assert settings.exempt_ips == ["198.51.100.9", "192.0.2.1"]

    def test_remove_exempt_ip_and_clear_overrides(self, runner, installer, scrape_mod):
        scrape_mod["load_deployed_settings"].return_value = ScrapeSettings(
            max_domains=5, max_requests=10, exempt_ips=["198.51.100.9", "192.0.2.1"]
        )

        runner.invoke(
            waf,
            [
                "scrape-protection",
                "enable",
                "--remove-exempt-ip",
                "198.51.100.9",
                "--clear-overrides",
                "-y",
            ],
        )

        settings = _written_settings(scrape_mod)
        assert settings.exempt_ips == ["192.0.2.1"]
        assert settings.max_domains is None and settings.max_requests is None

    def test_invalid_settings_rejected_before_any_change(self, runner, installer, scrape_mod):
        result = runner.invoke(
            waf, ["scrape-protection", "enable", "--exempt-ip", "not-an-ip", "-y"]
        )

        assert result.exit_code == 1
        assert "not-an-ip" in result.output
        scrape_mod["ensure_security2_include"].assert_not_called()
        scrape_mod["write_scrape_conf"].assert_not_called()

    def test_block_mode_warns_when_engine_is_detection_only(self, runner, installer, scrape_mod):
        installer.preflight.return_value.modsec_mode = "DetectionOnly"

        result = runner.invoke(waf, ["scrape-protection", "enable", "--mode", "block", "-y"])

        assert result.exit_code == 0, result.output
        assert "DetectionOnly" in result.output

    def test_dry_run_makes_no_changes(self, runner, installer, scrape_mod):
        result = runner.invoke(waf, ["scrape-protection", "enable", "--dry-run"])

        assert result.exit_code == 0, result.output
        scrape_mod["ensure_security2_include"].assert_called_once_with(dry_run=True)
        assert scrape_mod["write_scrape_conf"].call_args[1] == {"dry_run": True}
        scrape_mod["validate_apache_config"].assert_not_called()
        installer.reload_apache.assert_not_called()

    def test_write_failure_rolls_back_include(self, runner, installer, scrape_mod):
        scrape_mod["write_scrape_conf"].return_value = StepResult(success=False, error="disk full")

        result = runner.invoke(waf, ["scrape-protection", "enable", "-y"])

        assert result.exit_code == 1
        scrape_mod["rollback_scrape"].assert_called_once_with(
            conf_existed=False, security2_changed=True
        )
        scrape_mod["validate_apache_config"].assert_not_called()

    def test_configtest_failure_exits_without_reload(self, runner, installer, scrape_mod):
        scrape_mod["validate_apache_config"].return_value = StepResult(
            success=False, error="Apache config test failed (rolled back): boom"
        )

        result = runner.invoke(waf, ["scrape-protection", "enable", "-y"])

        assert result.exit_code == 1
        installer.reload_apache.assert_not_called()

    def test_unchanged_security2_is_not_rolled_back(self, runner, installer, scrape_mod):
        scrape_mod["is_deployed"].return_value = True
        scrape_mod["ensure_security2_include"].return_value = StepResult(
            skipped=True, message="already loads"
        )

        runner.invoke(waf, ["scrape-protection", "enable", "-y"])

        scrape_mod["validate_apache_config"].assert_called_once_with(
            conf_existed=True, security2_changed=False
        )

    def test_requires_root(self, runner, installer, scrape_mod):
        installer.preflight.return_value.is_root = False

        result = runner.invoke(waf, ["scrape-protection", "enable", "-y"])

        assert result.exit_code == 1
        assert "root" in result.output.lower()
        scrape_mod["write_scrape_conf"].assert_not_called()

    def test_prompt_declined_aborts(self, runner, installer, scrape_mod):
        result = runner.invoke(waf, ["scrape-protection", "enable"], input="n\n")

        assert result.exit_code == 0
        scrape_mod["write_scrape_conf"].assert_not_called()


class TestScrapeDisable:
    def test_noop_when_not_deployed(self, runner, installer, scrape_mod):
        result = runner.invoke(waf, ["scrape-protection", "disable", "-y"])

        assert result.exit_code == 0
        assert "not deployed" in result.output
        scrape_mod["remove_scrape_conf"].assert_not_called()

    def test_removes_validates_and_reloads(self, runner, installer, scrape_mod):
        scrape_mod["is_deployed"].return_value = True

        result = runner.invoke(waf, ["scrape-protection", "disable", "-y"])

        assert result.exit_code == 0, result.output
        scrape_mod["remove_scrape_conf"].assert_called_once_with(dry_run=False)
        scrape_mod["validate_apache_config"].assert_called_once_with(
            conf_existed=True, security2_changed=False
        )
        installer.reload_apache.assert_called_once()


class TestScrapeStatus:
    def test_not_deployed(self, runner, scrape_mod):
        result = runner.invoke(waf, ["scrape-protection", "status"])

        assert result.exit_code == 0
        assert "not deployed" in result.output.lower()

    def test_shows_settings(self, runner, scrape_mod):
        scrape_mod["get_scrape_status"].return_value = ScrapeStatus(
            deployed=True,
            included=True,
            current=True,
            settings=ScrapeSettings(mode="block", max_domains=9),
        )

        result = runner.invoke(waf, ["scrape-protection", "status"])

        assert result.exit_code == 0, result.output
        assert "block" in result.output
        assert "9 (override)" in result.output

    def test_group_defaults_to_status(self, runner, scrape_mod):
        result = runner.invoke(waf, ["scrape-protection"])

        assert result.exit_code == 0
        scrape_mod["get_scrape_status"].assert_called_once()
