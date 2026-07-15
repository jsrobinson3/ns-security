"""Apache-config IP restriction management for the NetSapiens admin UIs.

Writes a single Apache config (``RESTRICT_CONF_PATH``) using mod_authz_core
``<LocationMatch>`` + ``<RequireAny>`` + ``Require ip`` directives. This
replaces the legacy per-directory ``.htaccess`` approach, which used deprecated
Apache 2.2 syntax (``Order``/``Allow``), was wiped by NetSapiens package
upgrades, and is ignored under PHP-FPM.
"""

from __future__ import annotations

import ipaddress
import json
import re

from nssec.core.ssh import is_directory
from nssec.modules.waf.config import (
    LEGACY_HTACCESS_PATHS,
    RESTRICT_CACHE_PATH,
    RESTRICT_COMPONENTS,
    RESTRICT_CONF_PATH,
    RESTRICT_CONF_TEMPLATE,
    RESTRICT_MANAGED_MARKER,
)
from nssec.modules.waf.types import StepResult
from nssec.modules.waf.utils import (
    backup_file,
    file_exists,
    read_file,
    remove_file,
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


def get_applicable_components(server_type: str) -> list[dict]:
    """Filter RESTRICT_COMPONENTS by server type and directory existence.

    Args:
        server_type: Server type string (e.g. "core", "ndp", "combo").

    Returns:
        List of component dicts whose server_types include server_type
        and whose directory exists on the filesystem.
    """
    components = []
    for comp in RESTRICT_COMPONENTS:
        if server_type not in comp["server_types"]:
            continue
        if not is_directory(comp["directory"]):
            continue
        components.append(comp)
    return components


def parse_ips(path: str) -> list[str]:
    """Extract IP addresses from an Apache config or .htaccess file.

    Supports both Apache 2.4 syntax (Require ip) and legacy 2.2 syntax
    (Allow from) so IPs can be carried forward when migrating older,
    hand-crafted files.

    Args:
        path: Path to the file.

    Returns:
        Deduplicated list of IP addresses/CIDRs found, in order.
    """
    content = read_file(path)
    if not content:
        return []
    # Drop comment lines first. Hand-edited files and NetSapiens' default
    # .htaccess often carry commented example directives (e.g.
    # "# Require ip <ADMIN-IP>"); without this the regexes below would scrape
    # the placeholder as a real IP and carry it into the generated config.
    content = "\n".join(
        line for line in content.splitlines() if not line.lstrip().startswith("#")
    )
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


def parse_conf_segments(path: str) -> list[str]:
    """Extract the protected URL segments from an existing restrict config.

    Reads the ``<LocationMatch "^/(SiPbx|ndp|LiCf)/">`` group so IP edits can
    preserve the components the config already protects.

    Args:
        path: Path to the restrict config.

    Returns:
        List of segment names (e.g. ["SiPbx", "ndp"]), or empty if not found.
    """
    content = read_file(path)
    if not content:
        return []
    match = re.search(r'LocationMatch\s+"\^/\(([^)]*)\)/', content)
    if not match:
        return []
    return [seg for seg in match.group(1).split("|") if seg]


def is_nssec_managed(path: str) -> bool:
    """Check if a file was created by nssec.

    Args:
        path: Path to the file.

    Returns:
        True if the file contains the managed marker.
    """
    content = read_file(path)
    if not content:
        return False
    return RESTRICT_MANAGED_MARKER in content


def find_legacy_managed_htaccess() -> list[str]:
    """Return legacy .htaccess paths that exist AND were created by nssec.

    Hand-written .htaccess files (without the managed marker) are never
    reported, so migration cleanup leaves them untouched.
    """
    return [p for p in LEGACY_HTACCESS_PATHS if file_exists(p) and is_nssec_managed(p)]


def is_valid_ip(value: str) -> bool:
    """True if *value* is a valid IP address or CIDR network."""
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _partition_valid_ips(ips: list[str]) -> tuple[list[str], list[str]]:
    """Split *ips* into (valid, invalid), preserving order.

    Non-IP tokens can be carried forward from hand-edited legacy .htaccess
    files or a stale cache. If one reaches the Apache config it fails
    `apache2ctl configtest` (``ip address '...' appears to be invalid``) and
    leaves a broken config on disk, so they are filtered out before writing.
    """
    valid: list[str] = []
    invalid: list[str] = []
    for ip in ips:
        (valid if is_valid_ip(ip) else invalid).append(ip)
    return valid, invalid


def _render_conf(segments: list[str], ips: list[str]) -> str:
    """Render the restrict Apache config for the given segments and IPs.

    Invalid entries are dropped here as a final safety net so no code path can
    emit a config that breaks Apache (and so a previously-poisoned on-disk
    config self-heals on the next add/remove/reapply).
    """
    valid_ips, _ = _partition_valid_ips(ips)
    content = render(
        RESTRICT_CONF_TEMPLATE,
        managed_marker=RESTRICT_MANAGED_MARKER,
        segments="|".join(segments),
        ips=valid_ips,
    )
    # Jinja2 strips the trailing newline; ensure the file ends with one.
    if not content.endswith("\n"):
        content += "\n"
    return content


def collect_existing_ips(server_type: str) -> list[str]:
    """Gather IPs to carry forward when (re)writing the restrict config.

    Pulls from the current restrict config, any legacy .htaccess files, and
    the restrict cache. 127.0.0.1 is excluded (it is always re-added).

    Args:
        server_type: Server type string (accepted for API symmetry).

    Returns:
        Deduplicated list of IPs, excluding 127.0.0.1.
    """
    seen: set[str] = set()
    result: list[str] = []

    for path in [RESTRICT_CONF_PATH, *LEGACY_HTACCESS_PATHS]:
        if not file_exists(path):
            continue
        for ip in parse_ips(path):
            if ip != "127.0.0.1" and ip not in seen:
                seen.add(ip)
                result.append(ip)

    for ip in load_cached_ips():
        if ip != "127.0.0.1" and ip not in seen:
            seen.add(ip)
            result.append(ip)

    return result


def get_restrict_status(server_type: str) -> dict:
    """Return the status of the restrict config for this server type.

    Args:
        server_type: Server type string.

    Returns:
        Dict with keys: path, exists, managed, ips, components (names),
        segments (URL segments that would be protected), and legacy
        (leftover nssec-managed .htaccess files still on disk).
    """
    components = get_applicable_components(server_type)
    exists = file_exists(RESTRICT_CONF_PATH)
    return {
        "path": RESTRICT_CONF_PATH,
        "exists": exists,
        "managed": is_nssec_managed(RESTRICT_CONF_PATH) if exists else False,
        "ips": parse_ips(RESTRICT_CONF_PATH) if exists else [],
        "components": [c["name"] for c in components],
        "segments": [c["segment"] for c in components],
        "legacy": find_legacy_managed_htaccess(),
    }


def init_restrictions(
    server_type: str,
    ips: list[str],
    dry_run: bool = False,
    merge_existing: bool = True,
) -> list[tuple[str, StepResult]]:
    """Write the restrict Apache config with the provided IPs.

    127.0.0.1 is always included automatically.

    Args:
        server_type: Server type string.
        ips: List of IP addresses/CIDRs to allow.
        dry_run: Show what would be done without making changes.
        merge_existing: If True, merge IPs from the current config, legacy
            .htaccess files, and the cache. If False, use only *ips*
            (plus 127.0.0.1).

    Returns:
        List of (label, StepResult) tuples.
    """
    all_ips = ["127.0.0.1"] + [ip for ip in ips if ip != "127.0.0.1"]
    if merge_existing:
        for existing_ip in collect_existing_ips(server_type):
            if existing_ip not in all_ips:
                all_ips.append(existing_ip)

    # Drop non-IP tokens (e.g. carried forward from a hand-edited legacy
    # .htaccess or stale cache) before they reach the config or the cache.
    all_ips, invalid_ips = _partition_valid_ips(all_ips)

    components = get_applicable_components(server_type)
    if not components:
        return [
            ("", StepResult(skipped=True, message="No applicable admin UIs for this server type"))
        ]

    segments = [c["segment"] for c in components]
    label = f"Admin UI restrictions ({'|'.join(segments)})"

    def _with_invalid(msg: str) -> str:
        if invalid_ips:
            noun = "entry" if len(invalid_ips) == 1 else "entries"
            return f"{msg}; skipped {len(invalid_ips)} invalid {noun}: {', '.join(invalid_ips)}"
        return msg

    if dry_run:
        return [
            (
                label,
                StepResult(
                    message=_with_invalid(f"Would write {RESTRICT_CONF_PATH} with {len(all_ips)} IP(s)")
                ),
            )
        ]

    if file_exists(RESTRICT_CONF_PATH):
        backup_file(RESTRICT_CONF_PATH)

    if not write_file(RESTRICT_CONF_PATH, _render_conf(segments, all_ips)):
        return [(label, StepResult(success=False, error=f"Failed to write {RESTRICT_CONF_PATH}"))]

    save_cached_ips(all_ips)
    return [
        (label, StepResult(message=_with_invalid(f"Wrote {RESTRICT_CONF_PATH} with {len(all_ips)} IP(s)")))
    ]


def _segments_for_edit(server_type: str) -> list[str]:
    """Segments to use when rewriting an existing config on add/remove.

    Prefers the segments already in the config (so IP edits don't silently
    change scope), falling back to recomputing from the server type.
    """
    existing = parse_conf_segments(RESTRICT_CONF_PATH)
    if existing:
        return existing
    return [c["segment"] for c in get_applicable_components(server_type)]


def add_restricted_ip(server_type: str, ip: str) -> list[tuple[str, StepResult]]:
    """Add an IP to the managed restrict config.

    Args:
        server_type: Server type string.
        ip: IP address or CIDR to add.

    Returns:
        List of (label, StepResult) tuples.
    """
    if not file_exists(RESTRICT_CONF_PATH):
        return [
            (
                "",
                StepResult(
                    skipped=True,
                    message=f"No restrict config at {RESTRICT_CONF_PATH} (run init first)",
                ),
            )
        ]
    if not is_nssec_managed(RESTRICT_CONF_PATH):
        return [("", StepResult(skipped=True, message=f"Skipping unmanaged {RESTRICT_CONF_PATH}"))]

    current_ips = parse_ips(RESTRICT_CONF_PATH)
    if ip in current_ips:
        return [("", StepResult(skipped=True, message=f"{ip} already allowed"))]

    segments = _segments_for_edit(server_type)
    if not segments:
        return [
            ("", StepResult(success=False, error="No applicable admin UIs for this server type"))
        ]

    backup_file(RESTRICT_CONF_PATH)
    if not write_file(RESTRICT_CONF_PATH, _render_conf(segments, current_ips + [ip])):
        return [("", StepResult(success=False, error=f"Failed to write {RESTRICT_CONF_PATH}"))]

    cached = load_cached_ips()
    if ip not in cached:
        cached.append(ip)
        save_cached_ips(cached)

    return [("", StepResult(message=f"Added {ip} to {RESTRICT_CONF_PATH}"))]


def remove_restricted_ip(server_type: str, ip: str) -> list[tuple[str, StepResult]]:
    """Remove an IP from the managed restrict config.

    Refuses to remove 127.0.0.1.

    Args:
        server_type: Server type string.
        ip: IP address or CIDR to remove.

    Returns:
        List of (label, StepResult) tuples.
    """
    if ip == "127.0.0.1":
        return [
            (
                "",
                StepResult(
                    success=False,
                    error="Cannot remove 127.0.0.1 (localhost must always be allowed)",
                ),
            )
        ]

    if not file_exists(RESTRICT_CONF_PATH):
        return [
            ("", StepResult(skipped=True, message=f"No restrict config at {RESTRICT_CONF_PATH}"))
        ]
    if not is_nssec_managed(RESTRICT_CONF_PATH):
        return [("", StepResult(skipped=True, message=f"Skipping unmanaged {RESTRICT_CONF_PATH}"))]

    current_ips = parse_ips(RESTRICT_CONF_PATH)
    if ip not in current_ips:
        return [("", StepResult(skipped=True, message=f"{ip} not found in {RESTRICT_CONF_PATH}"))]

    segments = _segments_for_edit(server_type)
    new_ips = [existing for existing in current_ips if existing != ip]

    backup_file(RESTRICT_CONF_PATH)
    if not write_file(RESTRICT_CONF_PATH, _render_conf(segments, new_ips)):
        return [("", StepResult(success=False, error=f"Failed to write {RESTRICT_CONF_PATH}"))]

    cached = load_cached_ips()
    if ip in cached:
        save_cached_ips([c for c in cached if c != ip])

    return [("", StepResult(message=f"Removed {ip} from {RESTRICT_CONF_PATH}"))]


def reapply_restrictions(
    server_type: str,
    dry_run: bool = False,
) -> list[tuple[str, StepResult]]:
    """Re-deploy the restrict config from the cached IP list.

    Use after a NetSapiens package upgrade or if the config is removed.

    Args:
        server_type: Server type string.
        dry_run: Show what would be done without making changes.

    Returns:
        List of (label, StepResult) tuples.
    """
    cached_ips = load_cached_ips()
    if not cached_ips:
        return [
            (
                "",
                StepResult(
                    skipped=True,
                    message=f"No cached IPs found in {RESTRICT_CACHE_PATH} (run init first)",
                ),
            )
        ]

    ips = ["127.0.0.1"] + [ip for ip in cached_ips if ip != "127.0.0.1"]
    # A cache written by an older nssec may contain invalid tokens; drop them so
    # reapply can't produce a config that fails apache2ctl configtest.
    ips, _invalid = _partition_valid_ips(ips)

    components = get_applicable_components(server_type)
    if not components:
        return [
            ("", StepResult(skipped=True, message="No applicable admin UIs for this server type"))
        ]

    segments = [c["segment"] for c in components]
    label = f"Admin UI restrictions ({'|'.join(segments)})"

    if dry_run:
        return [
            (
                label,
                StepResult(
                    message=f"Would write {RESTRICT_CONF_PATH} with {len(ips)} cached IP(s)"
                ),
            )
        ]

    if file_exists(RESTRICT_CONF_PATH):
        backup_file(RESTRICT_CONF_PATH)

    if not write_file(RESTRICT_CONF_PATH, _render_conf(segments, ips)):
        return [(label, StepResult(success=False, error=f"Failed to write {RESTRICT_CONF_PATH}"))]

    return [
        (label, StepResult(message=f"Restored {RESTRICT_CONF_PATH} with {len(ips)} cached IP(s)"))
    ]


def remove_legacy_htaccess(dry_run: bool = False) -> list[tuple[str, StepResult]]:
    """Delete legacy nssec-managed .htaccess files after migration.

    Only files bearing the managed marker are removed; hand-written .htaccess
    files are left untouched.

    Args:
        dry_run: Show what would be removed without deleting.

    Returns:
        List of (path, StepResult) tuples (empty if nothing to clean up).
    """
    results: list[tuple[str, StepResult]] = []
    for path in find_legacy_managed_htaccess():
        if dry_run:
            results.append((path, StepResult(message=f"Would remove legacy {path}")))
            continue
        if remove_file(path):
            results.append((path, StepResult(message=f"Removed legacy {path}")))
        else:
            results.append((path, StepResult(success=False, error=f"Failed to remove {path}")))
    return results
