"""Tests for exclusions load-order relative to the CRS rules.

The NetSapiens exclusions are runtime ctl directives — they only suppress
CRS rules that execute after them. Within a phase, execution order is load
order, so the exclusions file must be included BEFORE the CRS rules or the
phase-1 exclusions (localhost, admin/NodePing IP allowlists) never apply
and rules like 920350/920180 keep firing on 127.0.0.1.
"""

from unittest.mock import patch

from jinja2 import Template

from nssec.modules.waf.config import (
    NS_EXCLUSIONS_CONF,
    NS_EXCLUSIONS_TEMPLATE,
    SECURITY2_CONF_TEMPLATE,
)
from nssec.modules.waf.status import _exclusions_load_before_crs

SEC2_EXCLUSIONS_BEFORE_RULES = """\
<IfModule security2_module>
    IncludeOptional /etc/modsecurity/modsecurity.conf
    IncludeOptional /etc/modsecurity/crs/crs-setup.conf
    IncludeOptional /etc/modsecurity/netsapiens-exclusions.conf
    IncludeOptional /etc/modsecurity/crs/rules/*.conf
</IfModule>
"""

# Layout written by nssec versions before this fix
SEC2_EXCLUSIONS_AFTER_RULES = """\
<IfModule security2_module>
    IncludeOptional /etc/modsecurity/modsecurity.conf
    IncludeOptional /etc/modsecurity/crs/crs-setup.conf
    IncludeOptional /etc/modsecurity/crs/rules/*.conf
    IncludeOptional /etc/modsecurity/netsapiens-exclusions.conf
</IfModule>
"""

# Debian default wildcard include with the CRS block appended by nssec
SEC2_WILDCARD = """\
<IfModule security2_module>
    IncludeOptional /etc/modsecurity/*.conf
    # OWASP CRS (added by nssec)
    IncludeOptional /etc/modsecurity/crs/crs-setup.conf
    IncludeOptional /etc/modsecurity/crs/rules/*.conf
</IfModule>
"""


class TestSecurity2Template:
    def test_exclusions_included_before_crs_rules(self):
        rendered = Template(SECURITY2_CONF_TEMPLATE).render(
            timestamp="test", crs_path="/etc/modsecurity/crs"
        )
        excl_pos = rendered.index(f"IncludeOptional {NS_EXCLUSIONS_CONF}")
        rules_pos = rendered.index("IncludeOptional /etc/modsecurity/crs/rules/*.conf")
        assert excl_pos < rules_pos

    def test_template_passes_order_detection(self):
        rendered = Template(SECURITY2_CONF_TEMPLATE).render(
            timestamp="test", crs_path="/etc/modsecurity/crs"
        )
        assert _exclusions_load_before_crs(rendered) is True


class TestExclusionsLoadOrderDetection:
    def test_before_rules_is_ordered(self):
        assert _exclusions_load_before_crs(SEC2_EXCLUSIONS_BEFORE_RULES) is True

    def test_after_rules_is_misordered(self):
        assert _exclusions_load_before_crs(SEC2_EXCLUSIONS_AFTER_RULES) is False

    def test_wildcard_include_before_appended_crs_is_ordered(self):
        assert _exclusions_load_before_crs(SEC2_WILDCARD) is True

    def test_comment_lines_are_ignored(self):
        content = (
            "# NetSapiens exclusions: /etc/modsecurity/netsapiens-exclusions.conf\n"
            "IncludeOptional /etc/modsecurity/crs/rules/*.conf\n"
            "IncludeOptional /etc/modsecurity/netsapiens-exclusions.conf\n"
        )
        assert _exclusions_load_before_crs(content) is False

    def test_no_rules_include_is_not_misordered(self):
        content = "IncludeOptional /etc/modsecurity/netsapiens-exclusions.conf\n"
        assert _exclusions_load_before_crs(content) is True

    def test_no_exclusions_include_is_not_misordered(self):
        # Missing include is exclusions_included's job, not ordering's
        content = "IncludeOptional /etc/modsecurity/crs/rules/*.conf\n"
        assert _exclusions_load_before_crs(content) is True


class TestLocalhostExclusion:
    def _render(self, **kwargs):
        return Template(NS_EXCLUSIONS_TEMPLATE).render(
            timestamp="test",
            version="7",
            template_hash="abc",
            admin_ips=kwargs.get("admin_ips", []),
            nodeping_ips=kwargs.get("nodeping_ips", []),
        )

    def test_localhost_rule_covers_ipv4_and_ipv6_loopback(self):
        assert '@ipMatch 127.0.0.1,::1' in self._render()

    def test_loopback_not_counted_as_admin_ip(self):
        from nssec.modules.waf.status import _parse_exclusions_meta

        rendered = self._render(admin_ips=["203.0.113.10"])
        _, _, admin_count, _ = _parse_exclusions_meta(rendered)
        assert admin_count == 1

    def test_loopback_not_returned_by_get_allowlisted_ips(self):
        from nssec.modules.waf import get_allowlisted_ips

        rendered = self._render(admin_ips=["203.0.113.10", "198.51.100.7"])
        with patch("nssec.modules.waf.read_file", return_value=rendered):
            assert get_allowlisted_ips() == ["203.0.113.10", "198.51.100.7"]
