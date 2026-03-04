"""Utility functions for the WAF module."""

from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Template

from nssec.core import ssh
from nssec.modules.waf.config import BACKUP_SUFFIX, SECURITY2_CONF


def run_cmd(cmd: list[str], timeout: int = 120) -> tuple[str, str, int]:
    """Run a command and return (stdout, stderr, returncode).

    Uses SSH-aware execution - works locally or remotely.
    """
    return ssh.run_command(cmd, timeout)


def package_installed(package: str) -> bool:
    """Check if a deb package is installed.

    Uses SSH-aware execution - works locally or remotely.
    """
    _, _, rc = run_cmd(["dpkg", "-s", package])
    return rc == 0


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


def render(template_str: str, **kwargs: object) -> str:
    """Render a Jinja2 template string."""
    return Template(template_str).render(
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        **kwargs,
    )


def _parse_version(s: str) -> tuple[int, ...]:
    """Parse a version string into an int tuple, stripping pre-release suffixes.

    Handles versions like "2.9.13~pre", "2.9.5-1", "2.9.6".
    """
    import re

    parts = []
    for component in s.split("."):
        # Extract leading digits, ignore suffixes like ~pre, -rc1, etc.
        m = re.match(r"(\d+)", component)
        if m:
            parts.append(int(m.group(1)))
        else:
            raise ValueError(f"Cannot parse version component: {component}")
    return tuple(parts)


def version_gte(version_str: str | None, target: str) -> bool:
    """Compare version strings using tuple comparison.

    Returns True if version_str >= target. Returns False on parse errors.
    Handles pre-release suffixes like ~pre, -rc1, etc.
    """
    try:
        v = _parse_version(version_str)
        t = _parse_version(target)
        return v >= t
    except (ValueError, AttributeError, TypeError):
        return False


def detect_modsec_version() -> str | None:
    """Detect installed ModSecurity version from dpkg metadata.

    Returns version string (e.g. "2.9.5") or None if not installed.
    """
    stdout, _, rc = run_cmd(["dpkg-query", "-W", "-f=${Version}", "libapache2-mod-security2"])
    if rc != 0 or not stdout.strip():
        return None
    # dpkg version may have suffixes like "2.9.5-3" — keep only the upstream part
    version = stdout.strip().split("-")[0]
    return version


def detect_modsec_mode(config_paths: list[str]) -> str | None:
    """Read SecRuleEngine mode from the first config that has it."""
    for config_path in config_paths:
        content = read_file(config_path)
        if not content:
            continue
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("SecRuleEngine") and " " in stripped:
                return stripped.split(None, 1)[1]
    return None


def parse_security2_conf(path: str) -> tuple[bool, bool]:
    """Parse security2.conf for wildcard include and CRS load patterns.

    Returns (has_wildcard, has_crs_load).
    """
    content = read_file(path)
    if not content:
        return False, False
    has_wildcard = False
    has_crs_load = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "/etc/modsecurity/*.conf" in stripped:
            has_wildcard = True
        if ".load" in stripped and "modsecurity-crs" in stripped:
            has_crs_load = True
    return has_wildcard, has_crs_load


def append_crs_to_security2(crs_path: str) -> bool:
    """Append CRS IncludeOptional directives to an existing security2.conf.

    Comments out any existing CRS load lines (e.g., apt v3
    ``IncludeOptional /usr/share/modsecurity-crs/*.load``) to prevent
    dual-loading when nssec manages CRS v4 separately.

    Returns True on success, False on write failure.
    """
    sec2_content = read_file(SECURITY2_CONF) or ""
    backup_file(SECURITY2_CONF)

    # Comment out old CRS include lines to prevent dual-loading.
    new_lines = []
    for line in sec2_content.splitlines():
        stripped = line.strip()
        if (
            not stripped.startswith("#")
            and "IncludeOptional" in stripped
            and "modsecurity-crs" in stripped
        ):
            new_lines.append("    # Disabled by nssec (CRS v4 managed below)")
            new_lines.append(f"    # {stripped}")
        else:
            new_lines.append(line)
    sec2_content = "\n".join(new_lines)

    crs_block = (
        f"\n    # OWASP CRS (added by nssec)\n"
        f"    IncludeOptional {crs_path}/crs-setup.conf\n"
        f"    IncludeOptional {crs_path}/plugins/*-config.conf\n"
        f"    IncludeOptional {crs_path}/plugins/*-before.conf\n"
        f"    IncludeOptional {crs_path}/rules/*.conf\n"
        f"    IncludeOptional {crs_path}/plugins/*-after.conf\n"
    )
    new_content = sec2_content.replace("</IfModule>", crs_block + "</IfModule>")
    return write_file(SECURITY2_CONF, new_content)


def write_security2_full(crs_path: str, template: str) -> bool:
    """Write a complete security2.conf from template.

    Returns True on success, False on write failure.
    """
    if file_exists(SECURITY2_CONF):
        backup_file(SECURITY2_CONF)
    content = render(template, crs_path=crs_path)
    return write_file(SECURITY2_CONF, content)
