"""Tests for mTLS module functions."""

from nssec.modules.mtls.config import NODEPING_BEGIN_MARKER, NODEPING_END_MARKER
from nssec.modules.mtls.utils import (
    build_managed_section,
    find_requireany_block,
    get_managed_section,
    parse_ip_list,
)


class TestParseIpList:
    """Tests for parse_ip_list function."""

    def test_parses_ipv4_addresses(self):
        content = "192.168.1.1\n10.0.0.1\n172.16.0.1"
        result = parse_ip_list(content)
        assert result == ["192.168.1.1", "10.0.0.1", "172.16.0.1"]

    def test_parses_ipv6_addresses(self):
        content = "2001:db8::1\n::1\nfe80::1"
        result = parse_ip_list(content)
        assert len(result) == 3
        assert "2001:db8::1" in result
        assert "::1" in result

    def test_skips_comments_and_empty_lines(self):
        content = "# Comment\n\n192.168.1.1\n\n# Another comment\n10.0.0.1"
        result = parse_ip_list(content)
        assert result == ["192.168.1.1", "10.0.0.1"]

    def test_skips_invalid_ips(self):
        content = "192.168.1.1\nnot-an-ip\n10.0.0.1"
        result = parse_ip_list(content)
        assert result == ["192.168.1.1", "10.0.0.1"]

    def test_handles_whitespace(self):
        content = "  192.168.1.1  \n\t10.0.0.1\t"
        result = parse_ip_list(content)
        assert result == ["192.168.1.1", "10.0.0.1"]

    def test_empty_content(self):
        result = parse_ip_list("")
        assert result == []

    def test_parses_hostname_ip_format(self):
        """NodePing uses 'hostname IP' format."""
        content = "pinghostca.nodeping.com 104.247.192.170\npinghostaz.nodeping.com 38.114.123.177"
        result = parse_ip_list(content)
        assert result == ["104.247.192.170", "38.114.123.177"]

    def test_parses_hostname_ipv6_format(self):
        content = "pinghostca.nodeping.com 2607:3f00:11:21::10"
        result = parse_ip_list(content)
        assert result == ["2607:3f00:11:21::10"]


class TestGetManagedSection:
    """Tests for get_managed_section function."""

    def test_finds_existing_section(self):
        content = f"""
<Location /cfg>
    Require ip 127.0.0.1
    {NODEPING_BEGIN_MARKER}
        Require ip 1.2.3.4
        Require ip 5.6.7.8
    {NODEPING_END_MARKER}
</Location>
"""
        start, end, ips = get_managed_section(content)
        assert start > 0
        assert end > start
        assert ips == ["1.2.3.4", "5.6.7.8"]

    def test_returns_empty_when_no_section(self):
        content = """
<Location /cfg>
    Require ip 127.0.0.1
</Location>
"""
        start, end, ips = get_managed_section(content)
        assert start == -1
        assert end == -1
        assert ips == []

    def test_handles_missing_end_marker(self):
        content = f"""
<Location /cfg>
    {NODEPING_BEGIN_MARKER}
        Require ip 1.2.3.4
</Location>
"""
        start, end, ips = get_managed_section(content)
        assert start == -1
        assert end == -1
        assert ips == []


class TestBuildManagedSection:
    """Tests for build_managed_section function."""

    def test_builds_section_with_markers(self):
        ips = ["1.2.3.4", "5.6.7.8"]
        result = build_managed_section(ips)

        assert NODEPING_BEGIN_MARKER in result
        assert NODEPING_END_MARKER in result
        assert "Require ip 1.2.3.4" in result
        assert "Require ip 5.6.7.8" in result

    def test_includes_metadata(self):
        ips = ["1.2.3.4"]
        result = build_managed_section(ips)

        assert "Updated:" in result
        assert "Source:" in result
        assert "Count: 1 IPs" in result

    def test_sorts_ips(self):
        ips = ["5.6.7.8", "1.2.3.4", "9.10.11.12"]
        result = build_managed_section(ips)

        # Find positions of IPs in output
        pos_1 = result.find("1.2.3.4")
        pos_5 = result.find("5.6.7.8")
        pos_9 = result.find("9.10.11.12")

        assert pos_1 < pos_5 < pos_9


class TestFindRequireanyBlock:
    """Tests for find_requireany_block function."""

    def test_finds_requireany_in_location(self):
        content = """
<Location /cfg>
    SSLVerifyClient require
    <RequireAny>
        Require ip 127.0.0.1
    </RequireAny>
</Location>
"""
        pos = find_requireany_block(content)
        assert pos > 0
        # Position should be right after <RequireAny>\n
        assert content[pos : pos + 8] == "        "  # indentation of next line

    def test_returns_negative_when_no_location(self):
        content = """
<RequireAny>
    Require ip 127.0.0.1
</RequireAny>
"""
        pos = find_requireany_block(content)
        assert pos == -1

    def test_returns_negative_when_no_requireany(self):
        content = """
<Location /cfg>
    Require ip 127.0.0.1
</Location>
"""
        pos = find_requireany_block(content)
        assert pos == -1
