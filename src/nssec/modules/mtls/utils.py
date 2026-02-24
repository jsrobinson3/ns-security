"""Utility functions for the mTLS module."""

from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

from nssec.core import ssh
from nssec.core.validators import validate_ip_address
from nssec.modules.mtls.config import (
    BACKUP_SUFFIX,
    NODEPING_BEGIN_MARKER,
    NODEPING_END_MARKER,
    NODEPING_URL,
)


def run_cmd(cmd: list[str], timeout: int = 120) -> tuple[str, str, int]:
    """Run a command and return (stdout, stderr, returncode).

    Uses SSH-aware execution - works locally or remotely.
    """
    return ssh.run_command(cmd, timeout)


def file_exists(path: str) -> bool:
    """Check if a file exists. SSH-aware."""
    return ssh.file_exists(path)


def read_file(path: str) -> str | None:
    """Read a file. SSH-aware."""
    return ssh.read_file(path)


def backup_file(path: str) -> str | None:
    """Create a backup of a file. Returns backup path or None."""
    if not file_exists(path):
        return None
    backup = path + BACKUP_SUFFIX
    if file_exists(backup):
        return backup  # Already backed up from a previous run
    shutil.copy2(path, backup)
    return backup


def write_file(path: str, content: str) -> bool:
    """Write content to a file, creating parent dirs as needed."""
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(content)
        return True
    except OSError:
        return False


def fetch_nodeping_ips() -> tuple[list[str], str]:
    """Fetch NodePing IPs from their published list.

    Returns:
        Tuple of (list of IPs, error message or empty string)
    """
    stdout, stderr, rc = run_cmd(["curl", "-sL", "--max-time", "30", NODEPING_URL])
    if rc != 0:
        return [], f"Failed to fetch NodePing IPs: {stderr}"
    return parse_ip_list(stdout), ""


def parse_ip_list(content: str) -> list[str]:
    """Parse plain text IP list.

    Handles formats:
    - One IP per line: "192.168.1.1"
    - Hostname and IP: "hostname.example.com 192.168.1.1"
    """
    ips = []
    for line in content.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Handle "hostname IP" format (NodePing uses this)
        parts = line.split()
        candidates = parts if len(parts) > 1 else [line]

        for candidate in candidates:
            try:
                validate_ip_address(candidate)
                ips.append(candidate)
                break  # Only take one IP per line
            except ValueError:
                continue
    return ips


def get_managed_section(content: str) -> tuple[int, int, list[str]]:
    """Find and parse the nssec-managed NodePing section.

    Returns:
        Tuple of (start_pos, end_pos, list of IPs) or (-1, -1, []) if not found
    """
    begin_idx = content.find(NODEPING_BEGIN_MARKER)
    if begin_idx == -1:
        return -1, -1, []

    end_idx = content.find(NODEPING_END_MARKER, begin_idx)
    if end_idx == -1:
        return -1, -1, []

    # Extract IPs from the section
    section = content[begin_idx:end_idx]
    ips = []
    for line in section.splitlines():
        stripped = line.strip()
        if stripped.startswith("Require ip "):
            ip = stripped.replace("Require ip ", "").strip()
            ips.append(ip)

    return begin_idx, end_idx + len(NODEPING_END_MARKER), ips


def build_managed_section(ips: list[str]) -> str:
    """Build the managed section content with marker comments."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "",
        f"    {NODEPING_BEGIN_MARKER}",
        f"    # Updated: {timestamp}",
        f"    # Source: {NODEPING_URL}",
        f"    # Count: {len(ips)} IPs",
    ]
    for ip in sorted(ips):
        lines.append(f"        Require ip {ip}")
    lines.append(f"    {NODEPING_END_MARKER}")
    lines.append("")
    return "\n".join(lines)


def find_requireany_block(content: str) -> int:
    """Find the position of the first <RequireAny> block to insert NodePing IPs.

    Returns the position after the opening <RequireAny> tag, or -1 if not found.
    """
    # Look for the outermost <RequireAny> in the <Location /cfg> block
    loc_start = content.find("<Location /cfg")
    if loc_start == -1:
        return -1

    loc_end = content.find("</Location>", loc_start)
    if loc_end == -1:
        return -1

    # Find first <RequireAny> within the Location block
    loc_content = content[loc_start:loc_end]
    req_any_pos = loc_content.find("<RequireAny>")
    if req_any_pos == -1:
        return -1

    # Return absolute position after <RequireAny>\n
    abs_pos = loc_start + req_any_pos + len("<RequireAny>")
    # Skip past the newline if present
    if abs_pos < len(content) and content[abs_pos] == "\n":
        abs_pos += 1
    return abs_pos
