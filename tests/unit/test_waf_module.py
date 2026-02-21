"""Tests for WAF module functions."""

import pytest
from unittest.mock import patch, MagicMock


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
