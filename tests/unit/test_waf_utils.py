"""Tests for WAF utility functions."""

from unittest.mock import patch

import pytest


class TestVersionGte:
    """Tests for version_gte helper."""

    def test_equal_versions(self):
        from nssec.modules.waf.utils import version_gte

        assert version_gte("2.9.6", "2.9.6") is True

    def test_greater_patch(self):
        from nssec.modules.waf.utils import version_gte

        assert version_gte("2.9.7", "2.9.6") is True

    def test_greater_minor(self):
        from nssec.modules.waf.utils import version_gte

        assert version_gte("2.10.0", "2.9.6") is True

    def test_greater_major(self):
        from nssec.modules.waf.utils import version_gte

        assert version_gte("3.0.0", "2.9.6") is True

    def test_less_than(self):
        from nssec.modules.waf.utils import version_gte

        assert version_gte("2.9.5", "2.9.6") is False

    def test_none_returns_false(self):
        from nssec.modules.waf.utils import version_gte

        assert version_gte(None, "2.9.6") is False

    def test_empty_string_returns_false(self):
        from nssec.modules.waf.utils import version_gte

        assert version_gte("", "2.9.6") is False

    def test_invalid_version_returns_false(self):
        from nssec.modules.waf.utils import version_gte

        assert version_gte("not.a.version", "2.9.6") is False

    def test_two_component_versions(self):
        from nssec.modules.waf.utils import version_gte

        assert version_gte("2.10", "2.9") is True
        assert version_gte("2.8", "2.9") is False


class TestDetectModsecVersion:
    """Tests for detect_modsec_version."""

    def test_returns_version_string(self):
        from nssec.modules.waf.utils import detect_modsec_version

        with patch("nssec.modules.waf.utils.run_cmd", return_value=("2.9.5-3", "", 0)):
            ver = detect_modsec_version()
        assert ver == "2.9.5"

    def test_returns_none_when_not_installed(self):
        from nssec.modules.waf.utils import detect_modsec_version

        with patch("nssec.modules.waf.utils.run_cmd", return_value=("", "not installed", 1)):
            ver = detect_modsec_version()
        assert ver is None

    def test_strips_debian_suffix(self):
        from nssec.modules.waf.utils import detect_modsec_version

        with patch("nssec.modules.waf.utils.run_cmd", return_value=("2.9.7-1ubuntu2", "", 0)):
            ver = detect_modsec_version()
        assert ver == "2.9.7"

    def test_returns_none_on_empty_stdout(self):
        from nssec.modules.waf.utils import detect_modsec_version

        with patch("nssec.modules.waf.utils.run_cmd", return_value=("", "", 0)):
            ver = detect_modsec_version()
        assert ver is None


DEBIAN_DEFAULT_SEC2 = """\
<IfModule security2_module>
    SecDataDir /var/cache/modsecurity
    IncludeOptional /etc/modsecurity/*.conf
    IncludeOptional /usr/share/modsecurity-crs/*.load
</IfModule>
"""

NSSEC_MANAGED_SEC2 = """\
<IfModule security2_module>
    IncludeOptional /etc/modsecurity/modsecurity.conf
    IncludeOptional /etc/modsecurity/crs/crs-setup.conf
    IncludeOptional /etc/modsecurity/crs/rules/*.conf
</IfModule>
"""


class TestParseSecurity2Conf:
    """Tests for parse_security2_conf utility."""

    def test_detects_wildcard_include(self):
        from nssec.modules.waf.utils import parse_security2_conf

        with patch("nssec.modules.waf.utils.read_file", return_value=DEBIAN_DEFAULT_SEC2):
            has_wildcard, has_crs_load = parse_security2_conf("/fake")
        assert has_wildcard is True
        assert has_crs_load is True

    def test_detects_no_wildcard(self):
        from nssec.modules.waf.utils import parse_security2_conf

        with patch("nssec.modules.waf.utils.read_file", return_value=NSSEC_MANAGED_SEC2):
            has_wildcard, has_crs_load = parse_security2_conf("/fake")
        assert has_wildcard is False
        assert has_crs_load is False

    def test_ignores_commented_lines(self):
        from nssec.modules.waf.utils import parse_security2_conf

        content = """\
<IfModule security2_module>
    # IncludeOptional /etc/modsecurity/*.conf
    # IncludeOptional /usr/share/modsecurity-crs/*.load
</IfModule>
"""
        with patch("nssec.modules.waf.utils.read_file", return_value=content):
            has_wildcard, has_crs_load = parse_security2_conf("/fake")
        assert has_wildcard is False
        assert has_crs_load is False

    def test_returns_false_when_file_missing(self):
        from nssec.modules.waf.utils import parse_security2_conf

        with patch("nssec.modules.waf.utils.read_file", return_value=None):
            has_wildcard, has_crs_load = parse_security2_conf("/fake")
        assert has_wildcard is False
        assert has_crs_load is False


class TestAppendCrsToSecurity2:
    """Tests for append_crs_to_security2 utility."""

    def test_appends_crs_includes(self):
        from nssec.modules.waf.utils import append_crs_to_security2

        written = {}

        def capture_write(path, content):
            written["content"] = content
            return True

        with patch("nssec.modules.waf.utils.read_file", return_value=DEBIAN_DEFAULT_SEC2), \
             patch("nssec.modules.waf.utils.backup_file"), \
             patch("nssec.modules.waf.utils.write_file", side_effect=capture_write):
            result = append_crs_to_security2("/etc/modsecurity/crs")

        assert result is True
        content = written["content"]
        assert "IncludeOptional /etc/modsecurity/crs/crs-setup.conf" in content
        assert "IncludeOptional /etc/modsecurity/crs/rules/*.conf" in content
        assert "added by nssec" in content

    def test_comments_out_old_v3_load_line(self):
        """Should comment out the apt v3 *.load line to prevent dual-loading."""
        from nssec.modules.waf.utils import append_crs_to_security2

        written = {}

        def capture_write(path, content):
            written["content"] = content
            return True

        with patch("nssec.modules.waf.utils.read_file", return_value=DEBIAN_DEFAULT_SEC2), \
             patch("nssec.modules.waf.utils.backup_file"), \
             patch("nssec.modules.waf.utils.write_file", side_effect=capture_write):
            append_crs_to_security2("/etc/modsecurity/crs")

        content = written["content"]
        # The old v3 line should be commented out
        assert "# IncludeOptional /usr/share/modsecurity-crs/*.load" in content
        assert "Disabled by nssec" in content
        # It should NOT appear as an active (uncommented) directive
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            assert "modsecurity-crs/*.load" not in stripped

    def test_preserves_wildcard_modsecurity_conf(self):
        """Should NOT touch the /etc/modsecurity/*.conf wildcard."""
        from nssec.modules.waf.utils import append_crs_to_security2

        written = {}

        def capture_write(path, content):
            written["content"] = content
            return True

        with patch("nssec.modules.waf.utils.read_file", return_value=DEBIAN_DEFAULT_SEC2), \
             patch("nssec.modules.waf.utils.backup_file"), \
             patch("nssec.modules.waf.utils.write_file", side_effect=capture_write):
            append_crs_to_security2("/etc/modsecurity/crs")

        content = written["content"]
        # The modsecurity/*.conf line should remain active (not commented)
        active_lines = [
            l.strip() for l in content.splitlines()
            if not l.strip().startswith("#") and l.strip()
        ]
        assert any("/etc/modsecurity/*.conf" in l for l in active_lines)

    def test_does_not_comment_out_already_commented_lines(self):
        """Should not double-comment already commented CRS lines."""
        from nssec.modules.waf.utils import append_crs_to_security2

        content_with_comment = """\
<IfModule security2_module>
    SecDataDir /var/cache/modsecurity
    IncludeOptional /etc/modsecurity/*.conf
    # IncludeOptional /usr/share/modsecurity-crs/*.load
</IfModule>
"""
        written = {}

        def capture_write(path, content):
            written["content"] = content
            return True

        with patch("nssec.modules.waf.utils.read_file", return_value=content_with_comment), \
             patch("nssec.modules.waf.utils.backup_file"), \
             patch("nssec.modules.waf.utils.write_file", side_effect=capture_write):
            append_crs_to_security2("/etc/modsecurity/crs")

        content = written["content"]
        # Should not have "Disabled by nssec" since the line was already commented
        assert "Disabled by nssec" not in content

    def test_returns_false_on_write_failure(self):
        from nssec.modules.waf.utils import append_crs_to_security2

        with patch("nssec.modules.waf.utils.read_file", return_value=DEBIAN_DEFAULT_SEC2), \
             patch("nssec.modules.waf.utils.backup_file"), \
             patch("nssec.modules.waf.utils.write_file", return_value=False):
            result = append_crs_to_security2("/etc/modsecurity/crs")

        assert result is False
