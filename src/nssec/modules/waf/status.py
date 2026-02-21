"""WAF status reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from nssec.modules.waf.config import (
    CRS_SEARCH_PATHS,
    MODSEC_AUDIT_LOG,
    MODSEC_CONF,
    MODSEC_PACKAGE,
    NS_EXCLUSIONS_CONF,
    SECURITY2_LOAD,
)


@dataclass
class WafStatus:
    """Current state of ModSecurity / CRS."""

    modsec_installed: bool = False
    modsec_enabled: bool = False
    modsec_mode: Optional[str] = None
    crs_installed: bool = False
    crs_version: Optional[str] = None
    crs_path: Optional[str] = None
    exclusions_present: bool = False
    audit_log_exists: bool = False
    recent_log_lines: list[str] = field(default_factory=list)


def _pkg_installed(package: str) -> bool:
    import subprocess

    try:
        result = subprocess.run(
            ["dpkg", "-s", package],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _read_file(path: str) -> Optional[str]:
    try:
        return Path(path).read_text()
    except (OSError, PermissionError):
        return None


def _tail_file(path: str, lines: int = 10) -> list[str]:
    """Return the last N lines of a file."""
    try:
        # Audit log may contain binary request bodies; use replace to handle them
        content = Path(path).read_text(errors="replace")
        all_lines = content.splitlines()
        return all_lines[-lines:]
    except (OSError, PermissionError):
        return []


def get_waf_status() -> WafStatus:
    """Collect comprehensive WAF status information."""
    status = WafStatus()

    status.modsec_installed = _pkg_installed(MODSEC_PACKAGE)
    status.modsec_enabled = Path(SECURITY2_LOAD).exists()

    # Detect mode
    content = _read_file(MODSEC_CONF)
    if content:
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("SecRuleEngine") and " " in stripped:
                status.modsec_mode = stripped.split(None, 1)[1]
                break

    # Detect CRS
    for search_path in CRS_SEARCH_PATHS:
        if not Path(search_path).is_dir():
            continue
        status.crs_installed = True
        status.crs_path = search_path
        version_file = Path(search_path) / "VERSION"
        if version_file.exists():
            status.crs_version = version_file.read_text().strip()
        break

    status.exclusions_present = Path(NS_EXCLUSIONS_CONF).exists()
    status.audit_log_exists = Path(MODSEC_AUDIT_LOG).exists()
    if status.audit_log_exists:
        status.recent_log_lines = _tail_file(MODSEC_AUDIT_LOG, 10)

    return status
