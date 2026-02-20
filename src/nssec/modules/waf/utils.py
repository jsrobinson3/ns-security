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

    Returns True on success, False on write failure.
    """
    sec2_content = read_file(SECURITY2_CONF) or ""
    backup_file(SECURITY2_CONF)
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
