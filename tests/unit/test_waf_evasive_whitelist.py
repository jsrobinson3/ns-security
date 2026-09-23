"""Tests for allowlisting the CRS-exempt sources in mod_evasive.

DOSWhitelist matches literal addresses with wildcard octets and cannot express
a prefix, so an allowlist entry only converts exactly on an octet boundary.
Anything else must be reported rather than silently widened to the enclosing
octet (which would excuse addresses the operator never allowlisted) or silently
dropped (which leaves an allowlisted host exposed to a 403).
"""

from unittest.mock import patch

from jinja2 import Template

from nssec.modules.waf.config import (
    EVASIVE_ALLOWLIST_BEGIN,
    EVASIVE_ALLOWLIST_END,
    EVASIVE_CONF_TEMPLATE,
    EVASIVE_EXPAND_LIMIT,
    EVASIVE_PROFILES,
)
from nssec.modules.waf.evasive import (
    deployed_whitelist,
    expand_hosts,
    parse_evasive_expand,
    resolve_whitelist,
    wildcard_for,
)


class TestWildcardFor:
    """Converting an allowlist entry to its DOSWhitelist form."""

    def test_bare_address_is_itself(self):
        assert wildcard_for("203.0.113.5") == "203.0.113.5"

    def test_host_prefix_reduces_to_the_address(self):
        assert wildcard_for("203.0.113.5/32") == "203.0.113.5"

    def test_octet_boundaries_become_wildcards(self):
        assert wildcard_for("192.168.1.0/24") == "192.168.1.*"
        assert wildcard_for("172.16.0.0/16") == "172.16.*.*"
        assert wildcard_for("10.0.0.0/8") == "10.*.*.*"

    def test_non_octet_prefix_has_no_form(self):
        """A /27 covers part of an octet; no wildcard expresses exactly that."""
        assert wildcard_for("198.51.100.64/27") is None
        assert wildcard_for("198.51.100.0/22") is None

    def test_ipv6_has_no_form(self):
        assert wildcard_for("2001:db8::1") is None
        assert wildcard_for("2001:db8::/32") is None

    def test_junk_has_no_form(self):
        assert wildcard_for("not-an-ip") is None
        assert wildcard_for("") is None

    def test_unaligned_network_address_still_uses_its_network(self):
        """10.1.2.3/8 is the 10.0.0.0/8 network, so it is 10.*.*.*."""
        assert wildcard_for("10.1.2.3/8") == "10.*.*.*"


class TestExpandHosts:
    def test_expands_a_small_range(self):
        hosts = expand_hosts("198.51.100.64/30")
        assert hosts == [
            "198.51.100.64",
            "198.51.100.65",
            "198.51.100.66",
            "198.51.100.67",
        ]

    def test_refuses_a_range_over_the_limit(self):
        assert expand_hosts("10.0.0.0/8") is None
        assert expand_hosts("198.51.100.0/22") is None

    def test_limit_is_inclusive(self):
        assert len(expand_hosts("198.51.100.0/24", limit=256)) == 256
        assert expand_hosts("198.51.100.0/24", limit=255) is None

    def test_refuses_ipv6(self):
        assert expand_hosts("2001:db8::/126") is None


class TestResolveWhitelist:
    def test_covers_both_allowlist_sources(self):
        result = resolve_whitelist(["203.0.113.5"], ["198.51.100.9"])
        assert [value for value, _ in result.entries] == ["203.0.113.5", "198.51.100.9"]

    def test_labels_name_the_source(self):
        result = resolve_whitelist(["203.0.113.5"], ["198.51.100.9"])
        labels = dict((value, label) for value, label in result.entries)
        assert "admin allowlist" in labels["203.0.113.5"]
        assert "NodePing probe" in labels["198.51.100.9"]

    def test_label_keeps_the_original_entry_when_converted(self):
        """The operator allowlisted 10.0.0.0/8; the comment should say so."""
        result = resolve_whitelist(["10.0.0.0/8"], [])
        value, label = result.entries[0]
        assert value == "10.*.*.*"
        assert "10.0.0.0/8" in label

    def test_skips_non_octet_range_by_default(self):
        result = resolve_whitelist(["198.51.100.64/27"], [])
        assert result.entries == []
        assert len(result.skipped) == 1
        entry, reason = result.skipped[0]
        assert entry == "198.51.100.64/27"
        assert "--expand-cidr" in reason

    def test_does_not_widen_to_the_enclosing_octet(self):
        """Never silently whitelist more than was allowlisted."""
        result = resolve_whitelist(["198.51.100.64/27"], [])
        assert "198.51.100.*" not in [value for value, _ in result.entries]

    def test_expand_writes_the_range_out(self):
        result = resolve_whitelist(["198.51.100.64/30"], [], expand=True)
        assert [value for value, _ in result.entries] == [
            "198.51.100.64",
            "198.51.100.65",
            "198.51.100.66",
            "198.51.100.67",
        ]
        assert result.skipped == []

    def test_expand_still_refuses_an_oversized_range(self):
        result = resolve_whitelist(["10.0.0.0/8"], [], expand=True)
        # /8 is an octet boundary, so it converts to a wildcard, not an expansion.
        assert [value for value, _ in result.entries] == ["10.*.*.*"]

        result = resolve_whitelist(["198.51.100.0/22"], [], expand=True)
        assert result.entries == []
        entry, reason = result.skipped[0]
        assert str(EVASIVE_EXPAND_LIMIT) in reason
        assert "1024 addresses" in reason

    def test_ipv6_is_reported_not_dropped(self):
        result = resolve_whitelist(["2001:db8::1"], [])
        assert result.entries == []
        assert "IPv4-only" in result.skipped[0][1]

    def test_invalid_entry_is_reported(self):
        result = resolve_whitelist(["not-an-ip"], [])
        assert "not a valid IP address or CIDR range" in result.skipped[0][1]

    def test_deduplicates_across_sources(self):
        """An IP that is both an admin entry and a probe is whitelisted once."""
        result = resolve_whitelist(["198.51.100.9"], ["198.51.100.9"])
        assert [value for value, _ in result.entries] == ["198.51.100.9"]

    def test_deduplicates_after_conversion(self):
        """10.0.0.0/8 and 10.1.0.0/8 both render as 10.*.*.*."""
        result = resolve_whitelist(["10.0.0.0/8", "10.1.2.3/8"], [])
        assert [value for value, _ in result.entries] == ["10.*.*.*"]

    def test_ignores_blank_entries(self):
        assert resolve_whitelist(["", "  "], []).entries == []

    def test_warnings_mention_the_entry(self):
        result = resolve_whitelist(["2001:db8::1"], [])
        assert any("2001:db8::1" in w for w in result.warnings())

    def test_expandable_flags_only_recoverable_skips(self):
        assert resolve_whitelist(["198.51.100.64/27"], []).expandable is True
        # IPv6 can never be written, so --expand-cidr would not help.
        assert resolve_whitelist(["2001:db8::1"], []).expandable is False

    def test_empty_inputs_produce_nothing(self):
        result = resolve_whitelist(None, None)
        assert result.entries == []
        assert result.skipped == []


class TestEvasiveTemplate:
    """Rendering the allowlist block into evasive.conf."""

    def _render(self, **kwargs):
        context = {
            "profile": "standard",
            "log_dir": "/var/log/apache2/mod_evasive",
            "log_file": "/var/log/apache2/mod_evasive.log",
            "cluster_peers": [],
            "cluster_ipv4": [],
            "cluster_ipv6": [],
            "cluster_manifest_url": "",
            "cluster_host_count": 0,
            "cluster_discovered_at": "",
            "cluster_rule_id_base": 1001000,
            "cluster_block_end": "# ---- end cluster peers ----",
            "restrict_cluster_begin": "",
            "restrict_cluster_end": "",
            "evasive_allowlist": [],
            "evasive_skipped": [],
            "evasive_expand": False,
            "evasive_allowlist_begin": EVASIVE_ALLOWLIST_BEGIN,
            "evasive_allowlist_end": EVASIVE_ALLOWLIST_END,
            "timestamp": "test",
            **EVASIVE_PROFILES["standard"],
        }
        context.update(kwargs)
        return Template(EVASIVE_CONF_TEMPLATE).render(**context)

    def test_renders_allowlist_entries(self):
        whitelist = resolve_whitelist(["10.0.0.0/8"], ["198.51.100.9"])
        rendered = self._render(**whitelist.template_context())
        assert "DOSWhitelist            10.*.*.*" in rendered
        assert "DOSWhitelist            198.51.100.9" in rendered
        assert EVASIVE_ALLOWLIST_BEGIN in rendered
        assert EVASIVE_ALLOWLIST_END in rendered

    def test_omits_block_when_nothing_to_say(self):
        rendered = self._render()
        assert EVASIVE_ALLOWLIST_BEGIN not in rendered

    def test_records_skipped_entries_as_comments(self):
        whitelist = resolve_whitelist(["198.51.100.64/27"], [])
        rendered = self._render(**whitelist.template_context())
        assert "198.51.100.64/27" in rendered
        # Only as a comment — never as an active directive.
        assert "DOSWhitelist            198.51.100.64/27" not in rendered
        for line in rendered.splitlines():
            if "198.51.100.64/27" in line:
                assert line.lstrip().startswith("#")

    def test_records_expand_setting_in_header(self):
        assert "# Expand-CIDR: off" in self._render(evasive_expand=False)
        assert "# Expand-CIDR: on" in self._render(evasive_expand=True)

    def test_expand_setting_round_trips(self):
        assert parse_evasive_expand(self._render(evasive_expand=True)) is True
        assert parse_evasive_expand(self._render(evasive_expand=False)) is False

    def test_parse_expand_returns_none_when_absent(self):
        assert parse_evasive_expand("# Profile: standard\n") is None

    def test_rfc1918_defaults_are_untouched(self):
        rendered = self._render()
        for expected in ("127.0.0.1", "10.*.*.*", "192.168.*.*"):
            assert f"DOSWhitelist            {expected}" in rendered

    def test_deployed_whitelist_reads_back_only_the_managed_block(self):
        """The RFC 1918 defaults and cluster peers must not be counted."""
        whitelist = resolve_whitelist(["203.0.113.5"], [])
        rendered = self._render(
            cluster_peers=[("192.0.2.7", "core1-atl")],
            cluster_ipv4=[("192.0.2.7", "core1-atl")],
            **whitelist.template_context(),
        )
        found = deployed_whitelist(rendered)
        assert list(found) == ["203.0.113.5"]

    def test_block_is_valid_apache_structure(self):
        whitelist = resolve_whitelist(["203.0.113.5"], [])
        rendered = self._render(**whitelist.template_context())
        assert rendered.count("<IfModule mod_evasive20.c>") == 1
        assert rendered.count("</IfModule>") == 1
        assert rendered.index(EVASIVE_ALLOWLIST_BEGIN) < rendered.index("</IfModule>")


class TestSetupEvasiveConfigWiring:
    """setup_evasive_config should derive the allowlist from the deployed conf."""

    def _installer(self):
        from nssec.modules.waf import ModSecurityInstaller

        return ModSecurityInstaller()

    def test_derives_allowlist_from_exclusions(self, mock_file_ops):
        installer = self._installer()
        with patch("nssec.modules.waf.get_allowlisted_ips", return_value=["203.0.113.5"]), patch(
            "nssec.modules.waf.get_nodeping_ips", return_value=["198.51.100.9"]
        ), patch("nssec.modules.waf.read_file", return_value=None):
            whitelist = installer.evasive_whitelist()
        assert [value for value, _ in whitelist.entries] == ["203.0.113.5", "198.51.100.9"]

    def test_keeps_recorded_expand_setting(self):
        installer = self._installer()
        deployed = "# Profile: standard\n# Expand-CIDR: on\n"
        admin = ["198.51.100.64/30"]
        with patch("nssec.modules.waf.get_allowlisted_ips", return_value=admin), patch(
            "nssec.modules.waf.get_nodeping_ips", return_value=[]
        ), patch("nssec.modules.waf.read_file", return_value=deployed):
            whitelist = installer.evasive_whitelist()
        assert whitelist.expand is True
        assert len(whitelist.entries) == 4

    def test_explicit_expand_overrides_the_recorded_setting(self):
        installer = self._installer()
        deployed = "# Profile: standard\n# Expand-CIDR: on\n"
        admin = ["198.51.100.64/30"]
        with patch("nssec.modules.waf.get_allowlisted_ips", return_value=admin), patch(
            "nssec.modules.waf.get_nodeping_ips", return_value=[]
        ), patch("nssec.modules.waf.read_file", return_value=deployed):
            whitelist = installer.evasive_whitelist(expand_cidr=False)
        assert whitelist.expand is False
        assert whitelist.entries == []

    def test_defaults_to_no_expansion_when_not_deployed(self):
        installer = self._installer()
        with patch("nssec.modules.waf.get_allowlisted_ips", return_value=[]), patch(
            "nssec.modules.waf.get_nodeping_ips", return_value=[]
        ), patch("nssec.modules.waf.read_file", return_value=None):
            assert installer.evasive_whitelist().expand is False

    def test_result_carries_warnings_for_skipped_entries(self, mock_file_ops):
        installer = self._installer()
        with patch("nssec.modules.waf.get_allowlisted_ips", return_value=["2001:db8::1"]), patch(
            "nssec.modules.waf.get_nodeping_ips", return_value=[]
        ), patch("nssec.modules.waf.Path"):
            result = installer.setup_evasive_config(profile="standard")
        assert result.success
        assert any("2001:db8::1" in w for w in result.warnings)
