"""WAF status reporting."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from nssec.modules.waf.config import (
    CRS_RULES_REQUIRE_296,
    CRS_SEARCH_PATHS,
    EVASIVE_LOAD,
    EVASIVE_PACKAGE,
    MODSEC_AUDIT_LOG,
    MODSEC_CONF,
    MODSEC_PACKAGE,
    NS_EXCLUSIONS_CONF,
    NS_EXCLUSIONS_HASH,
    NS_EXCLUSIONS_VERSION,
    SECURITY2_CONF,
    SECURITY2_LOAD,
)


@dataclass
class WafStatus:
    """Current state of ModSecurity / CRS."""

    apache_version: Optional[str] = None
    apache_ppa: bool = False
    modsec_installed: bool = False
    modsec_enabled: bool = False
    modsec_mode: Optional[str] = None
    crs_installed: bool = False
    crs_version: Optional[str] = None
    crs_path: Optional[str] = None
    crs_setup_present: bool = False
    evasive_installed: bool = False
    evasive_enabled: bool = False
    exclusions_present: bool = False
    exclusions_version: Optional[str] = None
    exclusions_current: bool = False
    exclusions_included: bool = False
    crs_path_valid: bool = False
    exclusions_admin_ips: int = 0
    exclusions_nodeping_ips: int = 0
    modsec_version: Optional[str] = None
    disabled_crs_rules: int = 0
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


def _get_pkg_version(package: str) -> Optional[str]:
    """Get the upstream version of an installed deb package."""
    import subprocess

    try:
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${Version}", package],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        # Strip Debian suffix (e.g. "2.9.5-3" → "2.9.5")
        return result.stdout.strip().split("-")[0]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def _is_ondrej_apache_ppa() -> bool:
    """Check whether the ondrej/apache2 PPA is configured."""
    import glob

    patterns = [
        "/etc/apt/sources.list.d/ondrej-ubuntu-apache2-*",
        "/etc/apt/sources.list.d/ondrej-*apache2*",
    ]
    return any(glob.glob(p) for p in patterns)


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


def _parse_security2_crs_path(content: str) -> Optional[str]:
    """Extract the CRS path referenced in security2.conf."""
    match = re.search(r"IncludeOptional\s+(\S+)/crs-setup\.conf", content)
    if match:
        return match.group(1)
    return None


def _parse_exclusions_meta(content: str) -> tuple[Optional[str], Optional[str], int, int]:
    """Parse exclusions file for version, hash, admin IP count, NodePing IP count."""
    version = None
    template_hash = None
    for line in content.splitlines():
        if line.startswith("# nssec-exclusions-version:"):
            version = line.split(":", 1)[1].strip()
        elif line.startswith("# nssec-exclusions-hash:"):
            template_hash = line.split(":", 1)[1].strip()

    admin_ips = len(re.findall(r'"id:10001\d+', content))
    nodeping_ips = len(re.findall(r'"id:10002\d+', content))
    return version, template_hash, admin_ips, nodeping_ips


def get_waf_status() -> WafStatus:
    """Collect comprehensive WAF status information."""
    status = WafStatus()

    status.apache_version = _get_pkg_version("apache2")
    status.apache_ppa = _is_ondrej_apache_ppa()
    status.modsec_installed = _pkg_installed(MODSEC_PACKAGE)
    status.modsec_version = _get_pkg_version(MODSEC_PACKAGE)
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
        # Check crs-setup.conf exists at this path
        status.crs_setup_present = (Path(search_path) / "crs-setup.conf").exists()
        # Count disabled CRS rules (files renamed .conf.disabled for ModSec compat)
        rules_dir = Path(search_path) / "rules"
        if rules_dir.is_dir():
            status.disabled_crs_rules = sum(
                1 for f in CRS_RULES_REQUIRE_296
                if (rules_dir / (f + ".disabled")).exists()
            )
        break

    # Check security2.conf references the correct CRS path and includes exclusions
    sec2_content = _read_file(SECURITY2_CONF)
    if sec2_content:
        sec2_crs_path = _parse_security2_crs_path(sec2_content)

        # Exclusions are included if security2.conf either:
        # 1. Explicitly includes the exclusions file path, OR
        # 2. Uses a wildcard IncludeOptional /etc/modsecurity/*.conf
        #    (the default Debian config) which picks up all .conf in that dir
        has_explicit = NS_EXCLUSIONS_CONF in sec2_content
        has_wildcard = "/etc/modsecurity/*.conf" in sec2_content
        status.exclusions_included = has_explicit or has_wildcard

        status.crs_path_valid = (
            sec2_crs_path is not None
            and Path(sec2_crs_path).is_dir()
            and (Path(sec2_crs_path) / "crs-setup.conf").exists()
        )

    status.evasive_installed = _pkg_installed(EVASIVE_PACKAGE)
    status.evasive_enabled = Path(EVASIVE_LOAD).exists()

    # Parse exclusions file
    status.exclusions_present = Path(NS_EXCLUSIONS_CONF).exists()
    if status.exclusions_present:
        excl_content = _read_file(NS_EXCLUSIONS_CONF)
        if excl_content:
            version, deployed_hash, admin_count, np_count = _parse_exclusions_meta(
                excl_content
            )
            status.exclusions_version = version
            # Use hash for drift detection — automatically catches any template change
            status.exclusions_current = deployed_hash == NS_EXCLUSIONS_HASH
            status.exclusions_admin_ips = admin_count
            status.exclusions_nodeping_ips = np_count

    status.audit_log_exists = Path(MODSEC_AUDIT_LOG).exists()
    if status.audit_log_exists:
        status.recent_log_lines = _tail_file(MODSEC_AUDIT_LOG, 10)

    return status
