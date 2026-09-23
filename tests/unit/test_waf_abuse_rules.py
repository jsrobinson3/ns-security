"""Tests for the abuse-protection rules in the NS exclusions template.

Covers the harvesting user-agent block and ban, v1 API device-walk limits
(short window, slow walk, repeat-offender escalation), the optional
token-endpoint audit logging (verbose mode), and the on/off toggles.
"""

import re
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from nssec.cli.waf_commands import waf
from nssec.modules.waf import render_exclusions
from nssec.modules.waf.config import ABUSE_LIMITS, EXCLUSION_TOGGLE_DEFAULTS
from nssec.modules.waf.utils import parse_exclusion_toggles

DEVICE_WALK_IDS = range(1000340, 1000354)


def _render(admin_ips=(), nodeping_ips=(), **toggles):
    return render_exclusions(
        admin_ips=list(admin_ips),
        nodeping_ips=list(nodeping_ips),
        toggles={**EXCLUSION_TOGGLE_DEFAULTS, **toggles},
    )


def _block(rendered, rule_id):
    """Return the rule with id:<rule_id>, chained links included."""
    start = rendered.rindex("SecRule ", 0, rendered.index(f'"id:{rule_id},'))
    end = rendered.find("\nSecRule ", start + 1)
    return rendered[start:] if end == -1 else rendered[start:end]


class TestDefaults:
    def test_blocking_rules_on_token_audit_off(self):
        assert EXCLUSION_TOGGLE_DEFAULTS == {
            "block_harvest_ua": True,
            "device_read_allowlist_only": False,
            "device_walk": True,
            "token_audit": False,
        }

    def test_slow_walk_limit_fits_in_dbm_record(self):
        """The 24h domain list lives in one ~1KB DBM record (~17 entries max)."""
        assert ABUSE_LIMITS["slow_max_domains"] <= 14


class TestToggleMarkers:
    def test_header_records_every_toggle(self):
        rendered = _render(token_audit=True, device_walk=False)
        assert "# nssec-toggle: token_audit=on" in rendered
        assert "# nssec-toggle: device_walk=off" in rendered
        assert "# nssec-toggle: block_harvest_ua=on" in rendered

    def test_round_trip(self):
        toggles = {
            "block_harvest_ua": False,
            "device_read_allowlist_only": True,
            "device_walk": True,
            "token_audit": True,
        }
        assert parse_exclusion_toggles(_render(**toggles)) == toggles

    def test_missing_markers_get_defaults(self):
        assert parse_exclusion_toggles("# older file\n") == EXCLUSION_TOGGLE_DEFAULTS

    def test_unknown_marker_ignored(self):
        parsed = parse_exclusion_toggles("# nssec-toggle: bogus=on\n")
        assert parsed == EXCLUSION_TOGGLE_DEFAULTS


class TestHarvestUserAgent:
    def test_matches_harvest_substring_case_insensitive(self):
        block = _block(_render(), 1000300)
        assert '"@contains harvest/"' in block
        assert "t:lowercase" in block

    def test_denies_request(self):
        block = _block(_render(), 1000331)
        assert "deny" in block
        assert "status:403" in block

    def test_bans_ip_from_ns_api(self):
        rendered = _render()
        mark = _block(rendered, 1000330)
        assert "initcol:resource=nssec_abuse_%{REMOTE_ADDR}" in mark
        assert f"expirevar:resource.ua_ban={ABUSE_LIMITS['ua_ban_period']}" in mark
        ban = _block(rendered, 1000332)
        assert 'RESOURCE:ua_ban "@eq 1"' in ban
        assert '"@beginsWith /ns-api/"' in ban
        assert "deny" in ban

    def test_ban_is_exempt_for_allowlisted_sources(self):
        rendered = _render()
        assert "tag:'nssec-abuse'" in _block(rendered, 1000330)
        assert "tag:'nssec-abuse'" in _block(rendered, 1000332)

    def test_toggle_off_removes_rules(self):
        rendered = _render(block_harvest_ua=False)
        assert "harvest/" not in rendered
        for rule_id in (1000300, 1000330, 1000331, 1000332):
            assert f'"id:{rule_id},' not in rendered


class TestDeviceWalk:
    def test_scoped_to_v1_device_read(self):
        block = _block(_render(), 1000340)
        assert "^/ns-api/(?:index\\.php)?$" in block
        assert 'ARGS:object "@streq device"' in block
        assert 'ARGS:action "@streq read"' in block

    def test_runs_in_phase_2_for_post_bodies(self):
        rendered = _render()
        for rule_id in DEVICE_WALK_IDS:
            assert "phase:2" in _block(rendered, rule_id)

    def test_uses_collections_crs_does_not(self):
        rendered = _render()
        assert "initcol:resource=nssec_abuse_%{REMOTE_ADDR}" in rendered
        assert "initcol:user=nssec_walk24_%{REMOTE_ADDR}" in rendered
        assert "initcol:ip=" not in rendered

    def test_domains_stored_as_short_hashes(self):
        block = _block(_render(), 1000343)
        assert "t:sha1,t:hexEncode" in block
        assert '"@rx ^([0-9a-f]{8})"' in block

    def test_nothing_recorded_while_blocked(self):
        """Growth cap: tracking rules skip IPs that were already blocked."""
        rendered = _render()
        for rule_id in (1000342, 1000344, 1000347, 1000348, 1000349):
            assert '&TX:nssec_was_blocked "@eq 0"' in _block(rendered, rule_id)

    def test_missing_domain_counts_as_a_domain(self):
        block = _block(_render(), 1000344)
        assert '&TX:nssec_domain_ok "@eq 0"' in block
        assert "setvar:resource.w_none=1" in block
        assert "setvar:user.w_none=1" in block

    def test_thresholds_rendered(self):
        rendered = _render()
        limits = ABUSE_LIMITS
        assert f'&RESOURCE:/^w_/ "@gt {limits["max_domains"]}"' in rendered
        assert f'RESOURCE:device_reads "@gt {limits["max_reads"]}"' in rendered
        assert f'&USER:/^w_/ "@gt {limits["slow_max_domains"]}"' in rendered

    def test_short_block_then_escalation(self):
        rendered = _render()
        limits = ABUSE_LIMITS
        first = _block(rendered, 1000350)
        assert f"expirevar:resource.walk_block={limits['block_period']}" in first
        assert f"expirevar:resource.walk_strikes={limits['repeat_window']}" in first
        repeat = _block(rendered, 1000351)
        assert 'RESOURCE:walk_strikes "@gt 1"' in repeat
        assert f"expirevar:resource.walk_block={limits['long_block_period']}" in repeat

    def test_slow_walk_gets_long_block(self):
        block = _block(_render(), 1000352)
        long_block = ABUSE_LIMITS["long_block_period"]
        assert f"expirevar:resource.walk_block={long_block}" in block

    def test_single_deny_for_blocked_ip(self):
        rendered = _render()
        deny_ids = [rule_id for rule_id in DEVICE_WALK_IDS if "deny" in _block(rendered, rule_id)]
        assert deny_ids == [1000353]
        assert 'RESOURCE:walk_block "@eq 1"' in _block(rendered, 1000353)

    def test_every_rule_tagged(self):
        rendered = _render()
        for rule_id in DEVICE_WALK_IDS:
            assert "tag:'nssec-abuse'" in _block(rendered, rule_id)

    def test_localhost_exempt(self):
        assert "ctl:ruleRemoveByTag=nssec-abuse" in _block(_render(), 1000005)

    def test_admin_and_nodeping_ips_exempt(self):
        rendered = _render(admin_ips=["203.0.113.7"], nodeping_ips=["198.51.100.8"])
        assert "ctl:ruleRemoveByTag=nssec-abuse" in _block(rendered, 1000101)
        assert "ctl:ruleRemoveByTag=nssec-abuse" in _block(rendered, 1000201)

    def test_follows_engine_mode(self):
        """Rules must not force the engine on — DetectionOnly only logs."""
        assert "ctl:ruleEngine" not in _render()

    def test_toggle_off_removes_rules(self):
        rendered = _render(device_walk=False)
        assert "initcol:user=" not in rendered
        for rule_id in DEVICE_WALK_IDS:
            assert f'"id:{rule_id},' not in rendered

    def test_both_off_skips_collection_init(self):
        rendered = _render(device_walk=False, block_harvest_ua=False)
        assert "initcol:" not in rendered


class TestDeviceReadAllowlistOnly:
    def test_off_by_default(self):
        assert '"id:1000360,' not in _render()

    def test_denies_every_v1_device_read(self):
        block = _block(_render(device_read_allowlist_only=True), 1000360)
        assert 'TX:nssec_device_read "@eq 1"' in block
        assert "deny" in block
        assert "status:403" in block

    def test_allowlisted_sources_exempt(self):
        """Tag nssec-abuse is removed by localhost/admin/NodePing/cluster rules."""
        block = _block(_render(device_read_allowlist_only=True), 1000360)
        assert "tag:'nssec-abuse'" in block

    def test_denies_before_walk_limits(self):
        rendered = _render(device_read_allowlist_only=True)
        assert rendered.index('"id:1000360,') < rendered.index('"id:1000341,')

    def test_works_with_walk_limits_off(self):
        rendered = _render(device_read_allowlist_only=True, device_walk=False)
        assert '"id:1000340,' in rendered  # device-read detection
        assert '"id:1000360,' in rendered
        assert '"id:1000341,' not in rendered
        assert "initcol:user=" not in rendered

    def test_follows_engine_mode(self):
        assert "ctl:ruleEngine" not in _render(device_read_allowlist_only=True)

    def test_cli_flag(self, mock_installer):
        with patch("nssec.modules.waf.fetch_nodeping_probe_ips", return_value=([], "")):
            result = CliRunner().invoke(
                waf, ["update-exclusions", "-y", "--device-read-allowlist-only"]
            )
        assert result.exit_code == 0, result.output
        toggles = mock_installer.install_exclusions.call_args.kwargs["toggles"]
        assert toggles == {"device_read_allowlist_only": True}
        assert "403" in result.output


class TestTokenAudit:
    def test_off_by_default(self):
        assert '"id:1000400,' not in _render()

    def test_on_enables_audit_for_token_endpoints(self):
        block = _block(_render(token_audit=True), 1000400)
        assert "ctl:auditEngine=On" in block
        assert "pass" in block

    def test_matches_both_token_endpoints(self):
        rendered = _render(token_audit=True)
        pattern = re.search(r'SecRule REQUEST_URI "@rx ([^"]+)"[^"]*"id:1000400', rendered)
        rx = re.compile(pattern.group(1))
        assert rx.search("/ns-api/oauth2/token")
        assert rx.search("/ns-api/v2/tokens")
        assert not rx.search("/ns-api/v2/domains")


class TestRuleIds:
    def test_ids_unique_with_everything_enabled(self):
        rendered = _render(
            admin_ips=["203.0.113.7", "198.51.100.0/24"],
            nodeping_ips=["198.51.100.8"],
            token_audit=True,
        )
        ids = re.findall(r'"id:(\d+)', rendered)
        assert len(ids) == len(set(ids))


class TestTogglesCarryForward:
    DEPLOYED = "# nssec-toggle: token_audit=on\n# nssec-toggle: device_walk=off\n"

    def test_unnamed_toggles_keep_deployed_setting(self, mock_file_ops):
        from nssec.modules.waf import ModSecurityInstaller

        mock_file_ops["read"].return_value = self.DEPLOYED
        result = ModSecurityInstaller().install_exclusions(
            nodeping_ips=[], toggles={"block_harvest_ua": False}
        )

        assert result.success
        assert mock_file_ops["render"].call_args.kwargs["toggles"] == {
            "block_harvest_ua": False,
            "device_read_allowlist_only": False,
            "device_walk": False,
            "token_audit": True,
        }

    def test_no_toggles_keeps_everything(self, mock_file_ops):
        from nssec.modules.waf import ModSecurityInstaller

        mock_file_ops["read"].return_value = self.DEPLOYED
        ModSecurityInstaller().install_exclusions(nodeping_ips=[])

        toggles = mock_file_ops["render"].call_args.kwargs["toggles"]
        assert toggles["token_audit"] is True
        assert toggles["device_walk"] is False

    def test_allowlist_add_keeps_toggles(self, mock_file_ops):
        from nssec.modules.waf import add_allowlisted_ip

        mock_file_ops["read"].return_value = self.DEPLOYED
        add_allowlisted_ip("198.51.100.4")

        toggles = mock_file_ops["render"].call_args.kwargs["toggles"]
        assert toggles["token_audit"] is True
        assert toggles["device_walk"] is False


@pytest.fixture
def mock_installer():
    with patch("nssec.modules.waf.ModSecurityInstaller") as mock_class:
        installer = MagicMock()
        pf = MagicMock()
        pf.is_root = True
        pf.modsec_installed = True
        installer.preflight.return_value = pf
        step = MagicMock()
        step.success = True
        step.skipped = False
        step.message = "ok"
        for name in (
            "install_exclusions",
            "refresh_evasive_cluster",
            "write_security2_conf",
            "validate_config",
            "reload_apache",
        ):
            getattr(installer, name).return_value = step
        mock_class.return_value = installer
        yield installer


class TestUpdateExclusionsToggleFlags:
    @pytest.mark.parametrize(
        "args, expected",
        [
            ([], {}),
            (["--token-audit"], {"token_audit": True}),
            (["--no-token-audit"], {"token_audit": False}),
            (["--no-device-walk"], {"device_walk": False}),
            (["--no-block-harvest-ua"], {"block_harvest_ua": False}),
            (
                ["--device-walk", "--block-harvest-ua"],
                {"device_walk": True, "block_harvest_ua": True},
            ),
        ],
    )
    def test_only_given_flags_passed_through(self, mock_installer, args, expected):
        with patch("nssec.modules.waf.fetch_nodeping_probe_ips", return_value=([], "")):
            result = CliRunner().invoke(waf, ["update-exclusions", "-y", *args])

        assert result.exit_code == 0, result.output
        assert mock_installer.install_exclusions.call_args.kwargs["toggles"] == expected

    def test_warns_about_credentials(self, mock_installer):
        with patch("nssec.modules.waf.fetch_nodeping_probe_ips", return_value=([], "")):
            result = CliRunner().invoke(waf, ["update-exclusions", "-y", "--token-audit"])

        assert "passwords" in result.output
