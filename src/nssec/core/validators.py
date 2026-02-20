"""Input validation utilities for nssec.

This module provides validation functions for network-related inputs
such as IP addresses and CIDR notation.
"""

import ipaddress
from typing import Union


def validate_ip_address(ip: str) -> bool:
    """Validate an IPv4 or IPv6 address.

    Args:
        ip: IP address string to validate (e.g., "192.168.1.1" or "2001:db8::1").

    Returns:
        True if the IP address is valid.

    Raises:
        ValueError: If the IP address is invalid, with a descriptive message.

    Examples:
        >>> validate_ip_address("192.168.1.1")
        True
        >>> validate_ip_address("2001:db8::1")
        True
        >>> validate_ip_address("invalid")
        Raises ValueError
    """
    if not ip or not isinstance(ip, str):
        raise ValueError("IP address must be a non-empty string")

    ip = ip.strip()
    if not ip:
        raise ValueError("IP address must be a non-empty string")

    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError as e:
        raise ValueError(f"Invalid IP address '{ip}': {e}") from e


def validate_ip_network(cidr: str, strict: bool = False) -> bool:
    """Validate a CIDR notation network address.

    Args:
        cidr: CIDR notation string to validate (e.g., "192.168.1.0/24" or "2001:db8::/32").
        strict: If True, require the host bits to be zero (e.g., "192.168.1.1/24"
            would be invalid). If False (default), host bits are allowed and will
            be masked off.

    Returns:
        True if the CIDR notation is valid.

    Raises:
        ValueError: If the CIDR notation is invalid, with a descriptive message.

    Examples:
        >>> validate_ip_network("192.168.1.0/24")
        True
        >>> validate_ip_network("2001:db8::/32")
        True
        >>> validate_ip_network("192.168.1.1/24", strict=False)
        True
        >>> validate_ip_network("192.168.1.1/24", strict=True)
        Raises ValueError (host bits set)
    """
    if not cidr or not isinstance(cidr, str):
        raise ValueError("CIDR notation must be a non-empty string")

    cidr = cidr.strip()
    if not cidr:
        raise ValueError("CIDR notation must be a non-empty string")

    # Check for presence of prefix length
    if "/" not in cidr:
        raise ValueError(f"Invalid CIDR notation '{cidr}': missing prefix length (e.g., /24)")

    try:
        ipaddress.ip_network(cidr, strict=strict)
        return True
    except ValueError as e:
        raise ValueError(f"Invalid CIDR notation '{cidr}': {e}") from e


def parse_ip_address(ip: str) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address]:
    """Parse and return an IP address object.

    Args:
        ip: IP address string to parse.

    Returns:
        IPv4Address or IPv6Address object.

    Raises:
        ValueError: If the IP address is invalid.
    """
    validate_ip_address(ip)
    return ipaddress.ip_address(ip.strip())


def parse_ip_network(
    cidr: str, strict: bool = False
) -> Union[ipaddress.IPv4Network, ipaddress.IPv6Network]:
    """Parse and return an IP network object.

    Args:
        cidr: CIDR notation string to parse.
        strict: If True, require the host bits to be zero.

    Returns:
        IPv4Network or IPv6Network object.

    Raises:
        ValueError: If the CIDR notation is invalid.
    """
    validate_ip_network(cidr, strict=strict)
    return ipaddress.ip_network(cidr.strip(), strict=strict)
