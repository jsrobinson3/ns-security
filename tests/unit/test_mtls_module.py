"""Tests for mTLS module functions."""

from nssec.modules.mtls.config import NODEPING_BEGIN_MARKER, NODEPING_END_MARKER
from nssec.modules.mtls.utils import (
    add_ip_to_requireany,
    build_managed_section,
    find_requireany_block,
    get_all_requireany_ips,
    get_managed_section,
    get_requireany_bounds,
    parse_ip_list,
    remove_ip_from_requireany,
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


SAMPLE_CONF = f"""
<Location /cfg>
    SSLVerifyClient require
    <RequireAny>
        Require ip 10.0.0.1
        Require ip 192.168.1.0/24
        {NODEPING_BEGIN_MARKER}
        Require ip 1.2.3.4
        Require ip 5.6.7.8
        {NODEPING_END_MARKER}
    </RequireAny>
</Location>
"""

SAMPLE_CONF_NO_MANAGED = """
<Location /cfg>
    SSLVerifyClient require
    <RequireAny>
        Require ip 10.0.0.1
        Require ip 192.168.1.0/24
    </RequireAny>
</Location>
"""


class TestGetRequireanyBounds:
    """Tests for get_requireany_bounds function."""

    def test_finds_block_bounds(self):
        start, end = get_requireany_bounds(SAMPLE_CONF)
        assert start > 0
        assert end > start
        block = SAMPLE_CONF[start:end]
        assert "Require ip 10.0.0.1" in block
        assert "</RequireAny>" not in block

    def test_returns_negative_when_no_location(self):
        content = "<RequireAny>\n    Require ip 1.2.3.4\n</RequireAny>"
        start, end = get_requireany_bounds(content)
        assert start == -1
        assert end == -1

    def test_returns_negative_when_no_requireany(self):
        content = "<Location /cfg>\n    Require ip 1.2.3.4\n</Location>"
        start, end = get_requireany_bounds(content)
        assert start == -1
        assert end == -1


class TestGetAllRequireanyIps:
    """Tests for get_all_requireany_ips function."""

    def test_returns_all_ips_with_managed_flag(self):
        results = get_all_requireany_ips(SAMPLE_CONF)
        ips = [r["ip"] for r in results]
        assert "10.0.0.1" in ips
        assert "192.168.1.0/24" in ips
        assert "1.2.3.4" in ips
        assert "5.6.7.8" in ips

    def test_marks_managed_ips_correctly(self):
        results = get_all_requireany_ips(SAMPLE_CONF)
        by_ip = {r["ip"]: r["managed"] for r in results}
        assert by_ip["10.0.0.1"] is False
        assert by_ip["192.168.1.0/24"] is False
        assert by_ip["1.2.3.4"] is True
        assert by_ip["5.6.7.8"] is True

    def test_no_managed_section(self):
        results = get_all_requireany_ips(SAMPLE_CONF_NO_MANAGED)
        assert len(results) == 2
        assert all(not r["managed"] for r in results)

    def test_empty_content(self):
        results = get_all_requireany_ips("")
        assert results == []


class TestAddIpToRequireany:
    """Tests for add_ip_to_requireany function."""

    def test_adds_ip_to_block(self):
        new_content, error = add_ip_to_requireany(SAMPLE_CONF_NO_MANAGED, "203.0.113.1")
        assert error == ""
        assert "Require ip 203.0.113.1" in new_content

    def test_rejects_duplicate_ip(self):
        _, error = add_ip_to_requireany(SAMPLE_CONF_NO_MANAGED, "10.0.0.1")
        assert "already in the allowlist" in error

    def test_adds_outside_managed_section(self):
        new_content, error = add_ip_to_requireany(SAMPLE_CONF, "203.0.113.1")
        assert error == ""
        assert "Require ip 203.0.113.1" in new_content
        # The new IP should be before the managed section
        new_ip_pos = new_content.find("Require ip 203.0.113.1")
        managed_pos = new_content.find(NODEPING_BEGIN_MARKER)
        assert new_ip_pos < managed_pos

    def test_returns_error_when_no_block(self):
        _, error = add_ip_to_requireany("no block here", "1.2.3.4")
        assert "Could not find" in error


class TestRemoveIpFromRequireany:
    """Tests for remove_ip_from_requireany function."""

    def test_removes_manual_ip(self):
        new_content, error = remove_ip_from_requireany(SAMPLE_CONF, "10.0.0.1")
        assert error == ""
        assert "Require ip 10.0.0.1" not in new_content
        # Other IPs should remain
        assert "Require ip 192.168.1.0/24" in new_content

    def test_blocks_removal_of_managed_ip(self):
        _, error = remove_ip_from_requireany(SAMPLE_CONF, "1.2.3.4")
        assert "managed by NodePing" in error

    def test_returns_error_for_missing_ip(self):
        _, error = remove_ip_from_requireany(SAMPLE_CONF, "99.99.99.99")
        assert "not found" in error

    def test_returns_error_when_no_block(self):
        _, error = remove_ip_from_requireany("no block here", "1.2.3.4")
        assert "Could not find" in error
