"""Tests for WAF status reporting."""

from jinja2 import Template


class TestParseExclusionsMeta:
    """Tests for _parse_exclusions_meta."""

    def test_parses_version_and_hash(self):
        from nssec.modules.waf.status import _parse_exclusions_meta

        content = """\
# nssec-exclusions-version: 2
# nssec-exclusions-hash: abc123def456
SecRule REMOTE_ADDR "@ipMatch 192.168.1.1" "id:1000101,phase:1"
SecRule REMOTE_ADDR "@ipMatch 52.71.195.82" "id:1000201,phase:1"
"""
        version, template_hash, admin, nodeping = _parse_exclusions_meta(content)
        assert version == "2"
        assert template_hash == "abc123def456"
        assert admin == 1
        assert nodeping == 1

    def test_counts_multiple_ips(self):
        from nssec.modules.waf.status import _parse_exclusions_meta

        content = """\
# nssec-exclusions-version: 2
# nssec-exclusions-hash: abc123
"id:1000101,phase:1"
"id:1000102,phase:1"
"id:1000201,phase:1"
"id:1000202,phase:1"
"id:1000203,phase:1"
"""
        version, _, admin, nodeping = _parse_exclusions_meta(content)
        assert admin == 2
        assert nodeping == 3

    def test_handles_missing_version_and_hash(self):
        from nssec.modules.waf.status import _parse_exclusions_meta

        content = "# Old exclusions file without version\nSecRule something"
        version, template_hash, admin, nodeping = _parse_exclusions_meta(content)
        assert version is None
        assert template_hash is None
        assert admin == 0
        assert nodeping == 0


class TestParseSecurity2CrsPath:
    """Tests for _parse_security2_crs_path."""

    def test_extracts_crs_path(self):
        from nssec.modules.waf.status import _parse_security2_crs_path

        content = """\
<IfModule security2_module>
    IncludeOptional /etc/modsecurity/modsecurity.conf
    IncludeOptional /etc/modsecurity/crs/crs-setup.conf
    IncludeOptional /etc/modsecurity/crs/rules/*.conf
</IfModule>
"""
        assert _parse_security2_crs_path(content) == "/etc/modsecurity/crs"

    def test_extracts_apt_crs_path(self):
        from nssec.modules.waf.status import _parse_security2_crs_path

        content = "IncludeOptional /usr/share/modsecurity-crs/crs-setup.conf"
        assert _parse_security2_crs_path(content) == "/usr/share/modsecurity-crs"

    def test_returns_none_when_no_crs(self):
        from nssec.modules.waf.status import _parse_security2_crs_path

        content = "IncludeOptional /etc/modsecurity/modsecurity.conf"
        assert _parse_security2_crs_path(content) is None


class TestExclusionsHashDrift:
    """Tests for template hash drift detection."""

    def test_matching_hash_means_current(self):
        from nssec.modules.waf.config import (
            NS_EXCLUSIONS_HASH,
            NS_EXCLUSIONS_TEMPLATE,
            NS_EXCLUSIONS_VERSION,
        )
        from nssec.modules.waf.status import _parse_exclusions_meta

        # Render the template with the current hash
        rendered = Template(NS_EXCLUSIONS_TEMPLATE).render(
            timestamp="test",
            admin_ips=[],
            nodeping_ips=[],
            version=NS_EXCLUSIONS_VERSION,
            template_hash=NS_EXCLUSIONS_HASH,
        )
        _, deployed_hash, _, _ = _parse_exclusions_meta(rendered)
        assert deployed_hash == NS_EXCLUSIONS_HASH

    def test_old_hash_means_outdated(self):
        from nssec.modules.waf.config import NS_EXCLUSIONS_HASH
        from nssec.modules.waf.status import _parse_exclusions_meta

        content = "# nssec-exclusions-hash: stale_old_hash\n"
        _, deployed_hash, _, _ = _parse_exclusions_meta(content)
        assert deployed_hash != NS_EXCLUSIONS_HASH

    def test_missing_hash_means_outdated(self):
        from nssec.modules.waf.config import NS_EXCLUSIONS_HASH
        from nssec.modules.waf.status import _parse_exclusions_meta

        content = "# Old file without hash\n"
        _, deployed_hash, _, _ = _parse_exclusions_meta(content)
        assert deployed_hash is None
        assert deployed_hash != NS_EXCLUSIONS_HASH


class TestExclusionsTemplateHash:
    """Tests for the template hash computation."""

    def test_hash_is_deterministic(self):
        from nssec.modules.waf.config import _exclusions_template_hash

        assert _exclusions_template_hash() == _exclusions_template_hash()

    def test_hash_is_12_chars(self):
        from nssec.modules.waf.config import NS_EXCLUSIONS_HASH

        assert len(NS_EXCLUSIONS_HASH) == 12
        assert all(c in "0123456789abcdef" for c in NS_EXCLUSIONS_HASH)
