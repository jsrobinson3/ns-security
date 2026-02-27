""".htaccess IP restriction management for NetSapiens paths."""

from __future__ import annotations

import json
import re

from nssec.core.ssh import is_directory
from nssec.modules.waf.config import (
    HTACCESS_DIR_TEMPLATE,
    HTACCESS_FILE_TEMPLATE,
    RESTRICT_CACHE_PATH,
    RESTRICT_MANAGED_MARKER,
    RESTRICT_TARGETS,
)
from nssec.modules.waf.types import StepResult
from nssec.modules.waf.utils import (
    backup_file,
    file_exists,
    read_file,
    render,
    write_file,
)


def load_cached_ips() -> list[str]:
    """Load saved IP list from the restrict cache file.

    Returns:
        List of cached IPs, or empty list if cache doesn't exist.
    """
    content = read_file(RESTRICT_CACHE_PATH)
    if not content:
        return []
    try:
        data = json.loads(content)
        return data.get("ips", [])
    except (json.JSONDecodeError, AttributeError):
        return []


def save_cached_ips(ips: list[str]) -> bool:
    """Save IP list to the restrict cache file.

    Args:
        ips: List of IP addresses/CIDRs to save.

    Returns:
        True on success, False on write failure.
    """
    data = {"ips": ips}
    return write_file(RESTRICT_CACHE_PATH, json.dumps(data, indent=2) + "\n")


def get_applicable_targets(server_type: str) -> list[dict]:
    """Filter RESTRICT_TARGETS by server type and directory existence.

    Args:
        server_type: Server type string (e.g. "core", "ndp", "combo").

    Returns:
        List of target dicts whose server_types include server_type
        and whose directory exists on the filesystem.
    """
    targets = []
    for target in RESTRICT_TARGETS:
        if server_type not in target["server_types"]:
            continue
        if not is_directory(target["directory"]):
            continue
        targets.append(target)
    return targets


def parse_htaccess_ips(path: str) -> list[str]:
    """Extract IP addresses from an .htaccess file.

    Supports both Apache 2.4 syntax (Require ip) and legacy 2.2 syntax
    (Allow from) so IPs can be preserved when upgrading from hand-crafted
    files.

    Args:
        path: Path to the .htaccess file.

    Returns:
        List of IP addresses/CIDRs found.
    """
    content = read_file(path)
    if not content:
        return []
    ips: list[str] = []
    # Apache 2.4: Require ip <addr>
    ips.extend(re.findall(r"Require\s+ip\s+(\S+)", content))
    # Legacy Apache 2.2: Allow from <addr>
    for match in re.findall(r"Allow\s+from\s+(.+)", content):
        for token in match.split():
            stripped = token.strip().rstrip(",")
            if stripped and stripped.lower() != "all":
                ips.append(stripped)
    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            unique.append(ip)
    return unique


def is_nssec_managed(path: str) -> bool:
    """Check if an .htaccess file was created by nssec.

    Args:
        path: Path to the .htaccess file.

    Returns:
        True if the file contains the managed marker.
    """
    content = read_file(path)
    if not content:
        return False
    return RESTRICT_MANAGED_MARKER in content


def get_restrict_status(server_type: str) -> list[dict]:
    """Return status of all applicable restriction targets.

    Args:
        server_type: Server type string.

    Returns:
        List of dicts with keys: name, path, exists, managed, ips.
    """
    statuses = []
    for target in RESTRICT_TARGETS:
        if server_type not in target["server_types"]:
            continue

        path = target["htaccess_path"]
        dir_exists = is_directory(target["directory"])

        if not dir_exists:
            continue

        exists = file_exists(path)
        managed = is_nssec_managed(path) if exists else False
        ips = parse_htaccess_ips(path) if exists else []

        statuses.append({
            "name": target["name"],
            "path": path,
            "exists": exists,
            "managed": managed,
            "ips": ips,
        })
    return statuses


def _render_htaccess(target: dict, ips: list[str]) -> str:
    """Render the appropriate .htaccess template for a target."""
    if target["file_target"]:
        content = render(
            HTACCESS_FILE_TEMPLATE,
            managed_marker=RESTRICT_MANAGED_MARKER,
            file_target=target["file_target"],
            ips=ips,
        )
    else:
        content = render(
            HTACCESS_DIR_TEMPLATE,
            managed_marker=RESTRICT_MANAGED_MARKER,
            ips=ips,
        )
    # Jinja2 strips the trailing newline; ensure file ends with one
    if not content.endswith("\n"):
        content += "\n"
    return content


def collect_existing_ips(server_type: str) -> list[str]:
    """Gather all unique IPs from existing .htaccess files for applicable targets.

    Reads both Apache 2.4 (Require ip) and legacy 2.2 (Allow from) syntax.
    Also includes any IPs from the restrict cache.

    Args:
        server_type: Server type string.

    Returns:
        Deduplicated list of IPs found, excluding 127.0.0.1.
    """
    seen: set[str] = set()
    result: list[str] = []

    for target in RESTRICT_TARGETS:
        if server_type not in target["server_types"]:
            continue
        if not is_directory(target["directory"]):
            continue
        if not file_exists(target["htaccess_path"]):
            continue
        for ip in parse_htaccess_ips(target["htaccess_path"]):
            if ip != "127.0.0.1" and ip not in seen:
                seen.add(ip)
                result.append(ip)

    for ip in load_cached_ips():
        if ip != "127.0.0.1" and ip not in seen:
            seen.add(ip)
            result.append(ip)

    return result


def init_restrictions(
    server_type: str,
    ips: list[str],
    dry_run: bool = False,
    merge_existing: bool = True,
) -> list[tuple[str, StepResult]]:
    """Create .htaccess files with provided IPs for all applicable targets.

    127.0.0.1 is always included automatically.

    Args:
        server_type: Server type string.
        ips: List of IP addresses/CIDRs to allow.
        dry_run: Show what would be done without making changes.
        merge_existing: If True, merge IPs from cache and existing .htaccess
            files on disk.  If False, only use the provided *ips* list
            (plus 127.0.0.1).

    Returns:
        List of (target_name, StepResult) tuples.
    """
    all_ips = ["127.0.0.1"] + [ip for ip in ips if ip != "127.0.0.1"]

    # Merge IPs from cache (survives NS package upgrades)
    if merge_existing:
        for cached_ip in load_cached_ips():
            if cached_ip not in all_ips:
                all_ips.append(cached_ip)

    targets = get_applicable_targets(server_type)
    results: list[tuple[str, StepResult]] = []

    if not targets:
        results.append(("", StepResult(
            skipped=True,
            message="No applicable targets found for this server type",
        )))
        return results

    for target in targets:
        path = target["htaccess_path"]
        name = target["name"]

        # Merge: preserve any existing IPs from the current file on disk
        # (managed or unmanaged — handles both Require ip and Allow from)
        merged_ips = list(all_ips)
        if merge_existing and file_exists(path):
            for existing_ip in parse_htaccess_ips(path):
                if existing_ip not in merged_ips:
                    merged_ips.append(existing_ip)

        if dry_run:
            results.append((name, StepResult(
                message=f"Would create {path} with {len(merged_ips)} IP(s)",
            )))
            continue

        if file_exists(path):
            backup_file(path)

        content = _render_htaccess(target, merged_ips)
        if not write_file(path, content):
            results.append((name, StepResult(
                success=False,
                error=f"Failed to write {path}",
            )))
            continue

        results.append((name, StepResult(
            message=f"Created {path} with {len(merged_ips)} IP(s)",
        )))

    # Save the full IP set to cache for reapply after upgrades
    if not dry_run:
        # Collect the union of all IPs written across targets
        all_written_ips = list(all_ips)
        for target in targets:
            path = target["htaccess_path"]
            if file_exists(path) and is_nssec_managed(path):
                for ip in parse_htaccess_ips(path):
                    if ip not in all_written_ips:
                        all_written_ips.append(ip)
        save_cached_ips(all_written_ips)

    return results


def add_restricted_ip(
    server_type: str,
    ip: str,
) -> list[tuple[str, StepResult]]:
    """Add an IP to all managed .htaccess files.

    Args:
        server_type: Server type string.
        ip: IP address or CIDR to add.

    Returns:
        List of (target_name, StepResult) tuples.
    """
    targets = get_applicable_targets(server_type)
    results: list[tuple[str, StepResult]] = []

    for target in targets:
        path = target["htaccess_path"]
        name = target["name"]

        if not file_exists(path):
            results.append((name, StepResult(
                skipped=True,
                message=f"No .htaccess at {path} (run init first)",
            )))
            continue

        if not is_nssec_managed(path):
            results.append((name, StepResult(
                skipped=True,
                message=f"Skipping unmanaged {path}",
            )))
            continue

        current_ips = parse_htaccess_ips(path)
        if ip in current_ips:
            results.append((name, StepResult(
                skipped=True,
                message=f"{ip} already in {path}",
            )))
            continue

        new_ips = current_ips + [ip]
        backup_file(path)
        content = _render_htaccess(target, new_ips)
        if not write_file(path, content):
            results.append((name, StepResult(
                success=False,
                error=f"Failed to write {path}",
            )))
            continue

        results.append((name, StepResult(
            message=f"Added {ip} to {path}",
        )))

    # Update cache with new IP
    cached = load_cached_ips()
    if ip not in cached:
        cached.append(ip)
        save_cached_ips(cached)

    return results


def remove_restricted_ip(
    server_type: str,
    ip: str,
) -> list[tuple[str, StepResult]]:
    """Remove an IP from all managed .htaccess files.

    Refuses to remove 127.0.0.1.

    Args:
        server_type: Server type string.
        ip: IP address or CIDR to remove.

    Returns:
        List of (target_name, StepResult) tuples.
    """
    if ip == "127.0.0.1":
        return [("", StepResult(
            success=False,
            error="Cannot remove 127.0.0.1 (localhost must always be allowed)",
        ))]

    targets = get_applicable_targets(server_type)
    results: list[tuple[str, StepResult]] = []

    for target in targets:
        path = target["htaccess_path"]
        name = target["name"]

        if not file_exists(path):
            results.append((name, StepResult(
                skipped=True,
                message=f"No .htaccess at {path}",
            )))
            continue

        if not is_nssec_managed(path):
            results.append((name, StepResult(
                skipped=True,
                message=f"Skipping unmanaged {path}",
            )))
            continue

        current_ips = parse_htaccess_ips(path)
        if ip not in current_ips:
            results.append((name, StepResult(
                skipped=True,
                message=f"{ip} not found in {path}",
            )))
            continue

        new_ips = [existing for existing in current_ips if existing != ip]
        backup_file(path)
        content = _render_htaccess(target, new_ips)
        if not write_file(path, content):
            results.append((name, StepResult(
                success=False,
                error=f"Failed to write {path}",
            )))
            continue

        results.append((name, StepResult(
            message=f"Removed {ip} from {path}",
        )))

    # Update cache — remove this IP
    cached = load_cached_ips()
    if ip in cached:
        cached = [c for c in cached if c != ip]
        save_cached_ips(cached)

    return results


def reapply_restrictions(
    server_type: str,
    dry_run: bool = False,
) -> list[tuple[str, StepResult]]:
    """Re-deploy .htaccess files from the cached IP list.

    Use after a NetSapiens package upgrade overwrites .htaccess files.

    Args:
        server_type: Server type string.
        dry_run: Show what would be done without making changes.

    Returns:
        List of (target_name, StepResult) tuples.
    """
    cached_ips = load_cached_ips()
    if not cached_ips:
        return [("", StepResult(
            skipped=True,
            message=f"No cached IPs found in {RESTRICT_CACHE_PATH} (run init first)",
        ))]

    # Ensure 127.0.0.1 is first
    ips = ["127.0.0.1"] + [ip for ip in cached_ips if ip != "127.0.0.1"]

    targets = get_applicable_targets(server_type)
    results: list[tuple[str, StepResult]] = []

    if not targets:
        results.append(("", StepResult(
            skipped=True,
            message="No applicable targets found for this server type",
        )))
        return results

    for target in targets:
        path = target["htaccess_path"]
        name = target["name"]

        if dry_run:
            results.append((name, StepResult(
                message=f"Would write {path} with {len(ips)} cached IP(s)",
            )))
            continue

        if file_exists(path):
            backup_file(path)

        content = _render_htaccess(target, ips)
        if not write_file(path, content):
            results.append((name, StepResult(
                success=False,
                error=f"Failed to write {path}",
            )))
            continue

        results.append((name, StepResult(
            message=f"Restored {path} with {len(ips)} cached IP(s)",
        )))

    return results
