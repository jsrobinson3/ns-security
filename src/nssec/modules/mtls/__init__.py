"""mTLS device provisioning module.

Provides management of NodePing monitoring IPs for the ndp_mtls.conf
Apache configuration file used by mTLSProtect.
"""

from __future__ import annotations

from dataclasses import dataclass

from nssec.modules.mtls.config import BACKUP_SUFFIX, NDP_MTLS_CONF
from nssec.modules.mtls.utils import (
    add_ip_to_requireany,
    backup_file,
    build_managed_section,
    fetch_nodeping_ips,
    file_exists,
    find_requireany_block,
    get_all_requireany_ips,
    get_managed_section,
    read_file,
    remove_ip_from_requireany,
    run_cmd,
    write_file,
)


@dataclass
class StepResult:
    """Result of a single operation step."""

    success: bool = True
    skipped: bool = False
    message: str = ""
    error: str = ""


def get_current_nodeping_ips() -> list[str]:
    """Get currently configured NodePing IPs from ndp_mtls.conf."""
    content = read_file(NDP_MTLS_CONF)
    if not content:
        return []
    _, _, ips = get_managed_section(content)
    return ips


def _build_dry_run_message(ips: list[str], existing_ips: list[str]) -> str:
    """Build a dry-run summary message."""
    added = set(ips) - set(existing_ips)
    removed = set(existing_ips) - set(ips)
    msg = f"Would update {len(ips)} NodePing IPs"
    if existing_ips:
        if added:
            msg += f" (+{len(added)} new)"
        if removed:
            msg += f" (-{len(removed)} removed)"
    return msg


def _insert_nodeping_section(content: str, new_section: str) -> tuple[str, str]:
    """Insert or replace the NodePing section in config content.

    Returns (new_content, error_message). Error is empty on success.
    """
    sec_start, sec_end, _ = get_managed_section(content)

    if sec_start != -1:
        return content[:sec_start] + new_section + content[sec_end:], ""

    insert_pos = find_requireany_block(content)
    if insert_pos == -1:
        return "", "Could not find <RequireAny> block in ndp_mtls.conf"
    return content[:insert_pos] + new_section + content[insert_pos:], ""


def update_nodeping_ips(dry_run: bool = False) -> StepResult:
    """Fetch NodePing IPs and update ndp_mtls.conf."""
    if not file_exists(NDP_MTLS_CONF):
        return StepResult(
            success=False,
            error=f"{NDP_MTLS_CONF} not found. Is mTLSProtect installed?",
        )

    ips, fetch_error = fetch_nodeping_ips()
    if fetch_error:
        return StepResult(success=False, error=fetch_error)
    if not ips:
        return StepResult(success=False, error="No valid IPs found in NodePing list")

    content = read_file(NDP_MTLS_CONF)
    if not content:
        return StepResult(success=False, error=f"Failed to read {NDP_MTLS_CONF}")

    _, _, existing_ips = get_managed_section(content)
    if set(existing_ips) == set(ips):
        return StepResult(skipped=True, message="NodePing IPs already up to date")

    if dry_run:
        return StepResult(message=_build_dry_run_message(ips, existing_ips))

    new_section = build_managed_section(ips)
    new_content, error = _insert_nodeping_section(content, new_section)
    if error:
        return StepResult(success=False, error=error)

    backup_file(NDP_MTLS_CONF)
    if not write_file(NDP_MTLS_CONF, new_content):
        return StepResult(success=False, error=f"Failed to write {NDP_MTLS_CONF}")

    return StepResult(message=f"Updated {len(ips)} NodePing IPs in {NDP_MTLS_CONF}")


def remove_nodeping_ips() -> StepResult:
    """Remove the nssec-managed NodePing section from ndp_mtls.conf."""
    if not file_exists(NDP_MTLS_CONF):
        return StepResult(skipped=True, message=f"{NDP_MTLS_CONF} not found")

    content = read_file(NDP_MTLS_CONF)
    if not content:
        return StepResult(success=False, error=f"Failed to read {NDP_MTLS_CONF}")

    sec_start, sec_end, _ = get_managed_section(content)
    if sec_start == -1:
        return StepResult(skipped=True, message="No NodePing section found to remove")

    # Remove the section
    new_content = content[:sec_start] + content[sec_end:]

    backup_file(NDP_MTLS_CONF)
    if not write_file(NDP_MTLS_CONF, new_content):
        return StepResult(success=False, error=f"Failed to write {NDP_MTLS_CONF}")

    return StepResult(message="Removed NodePing IPs section from ndp_mtls.conf")


def get_allowlist_ips() -> list[dict]:
    """Get all whitelisted IPs from ndp_mtls.conf.

    Returns list of dicts with 'ip' and 'managed' (bool) keys.
    """
    content = read_file(NDP_MTLS_CONF)
    if not content:
        return []
    return get_all_requireany_ips(content)


def add_allowlist_ip(ip: str) -> StepResult:
    """Add an IP to the mTLS allowlist in ndp_mtls.conf."""
    if not file_exists(NDP_MTLS_CONF):
        return StepResult(
            success=False,
            error=f"{NDP_MTLS_CONF} not found. Is mTLSProtect installed?",
        )

    content = read_file(NDP_MTLS_CONF)
    if not content:
        return StepResult(success=False, error=f"Failed to read {NDP_MTLS_CONF}")

    new_content, error = add_ip_to_requireany(content, ip)
    if error:
        return StepResult(success=False, error=error)

    backup_file(NDP_MTLS_CONF)
    if not write_file(NDP_MTLS_CONF, new_content):
        return StepResult(success=False, error=f"Failed to write {NDP_MTLS_CONF}")

    return StepResult(message=f"Added {ip} to mTLS allowlist")


def remove_allowlist_ip(ip: str) -> StepResult:
    """Remove an IP from the mTLS allowlist in ndp_mtls.conf."""
    if not file_exists(NDP_MTLS_CONF):
        return StepResult(
            success=False,
            error=f"{NDP_MTLS_CONF} not found. Is mTLSProtect installed?",
        )

    content = read_file(NDP_MTLS_CONF)
    if not content:
        return StepResult(success=False, error=f"Failed to read {NDP_MTLS_CONF}")

    new_content, error = remove_ip_from_requireany(content, ip)
    if error:
        return StepResult(success=False, error=error)

    backup_file(NDP_MTLS_CONF)
    if not write_file(NDP_MTLS_CONF, new_content):
        return StepResult(success=False, error=f"Failed to write {NDP_MTLS_CONF}")

    return StepResult(message=f"Removed {ip} from mTLS allowlist")


def validate_apache_config() -> StepResult:
    """Run apache2ctl configtest to validate configuration."""
    stdout, stderr, rc = run_cmd(["apache2ctl", "configtest"])
    if rc != 0:
        return StepResult(success=False, error=f"Apache config test failed: {stderr or stdout}")
    return StepResult(message="Apache config test passed")


def reload_apache() -> StepResult:
    """Reload Apache to apply configuration changes."""
    _, stderr, rc = run_cmd(["systemctl", "reload", "apache2"])
    if rc != 0:
        return StepResult(success=False, error=f"Apache reload failed: {stderr}")
    return StepResult(message="Apache reloaded")


def rollback(path: str = NDP_MTLS_CONF) -> bool:
    """Restore a file from its backup."""
    import shutil

    backup = path + BACKUP_SUFFIX
    if file_exists(backup):
        shutil.copy2(backup, path)
        return True
    return False
