"""mod_evasive allowlisting for the sources that already bypass the CRS rules.

The exclusions file allowlists three sources — admin IPs (``1000100+``),
NodePing probes (``1000200+``) and SBUS cluster peers (``CLUSTER_RULE_ID_BASE``).
mod_evasive has to be told about the same ones: it runs independently of
ModSecurity, so a host excused from the CRS rules can still be answered with a
403 by the flood protection. Cluster peers are handled in :mod:`.cluster`;
this module covers the admin and NodePing lists.

``DOSWhitelist`` cannot express a prefix. It matches literal addresses with
wildcard octets, which is why the template hardcodes ``10.*.*.*`` rather than
``10.0.0.0/8``. An allowlist entry therefore only converts cleanly when its
prefix falls on an octet boundary; anything else is reported rather than
quietly widened to the enclosing octet, and can be written out as individual
addresses with ``expand=True``.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from nssec.modules.waf.config import (
    EVASIVE_ALLOWLIST_BEGIN,
    EVASIVE_ALLOWLIST_END,
    EVASIVE_CONF,
    EVASIVE_EXPAND_LIMIT,
)
from nssec.modules.waf.utils import read_file

# A prefix length maps to a wildcard only on an octet boundary.
_OCTET_PREFIXES = {8: 1, 16: 2, 24: 3, 32: 4}

SOURCE_ADMIN = "admin allowlist"
SOURCE_NODEPING = "NodePing probe"


@dataclass
class EvasiveWhitelist:
    """The DOSWhitelist entries to render, and the ones that could not be."""

    entries: list[tuple[str, str]] = field(default_factory=list)  # (value, label)
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (entry, reason)
    expand: bool = False

    @property
    def expandable(self) -> bool:
        """True when --expand-cidr would turn something skipped into entries."""
        return any("--expand-cidr" in reason for _, reason in self.skipped)

    def warnings(self) -> list[str]:
        """One line per skipped entry, for status output."""
        return [
            f"{entry} not whitelisted in mod_evasive: {reason}" for entry, reason in self.skipped
        ]

    def template_context(self) -> dict:
        return {
            "evasive_allowlist": self.entries,
            "evasive_skipped": self.skipped,
            "evasive_expand": self.expand,
            "evasive_allowlist_begin": EVASIVE_ALLOWLIST_BEGIN,
            "evasive_allowlist_end": EVASIVE_ALLOWLIST_END,
        }


def wildcard_for(entry: str) -> str | None:
    """The DOSWhitelist form of *entry*, or None if it has no exact one.

    A bare IPv4 address and a /32 both become the address itself; /24, /16 and
    /8 become wildcards. Everything else (a /27, an IPv6 address, junk) has no
    faithful representation and returns None.
    """
    entry = entry.strip()
    if not entry:
        return None
    if "/" not in entry:
        try:
            if ipaddress.ip_address(entry).version != 4:
                return None
        except ValueError:
            return None
        return entry
    try:
        network = ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None
    if network.version != 4:
        return None
    octets = _OCTET_PREFIXES.get(network.prefixlen)
    if octets is None:
        return None
    kept = str(network.network_address).split(".")[:octets]
    return ".".join(kept + ["*"] * (4 - octets))


def expand_hosts(entry: str, limit: int = EVASIVE_EXPAND_LIMIT) -> list[str] | None:
    """Every address in *entry*, or None if IPv6 or larger than *limit*."""
    try:
        network = ipaddress.ip_network(entry.strip(), strict=False)
    except ValueError:
        return None
    if network.version != 4 or network.num_addresses > limit:
        return None
    return [str(ip) for ip in network]


def _reason(entry: str, expand: bool, limit: int) -> str:
    """Why *entry* cannot be written, phrased for a config comment."""
    try:
        network = ipaddress.ip_network(entry.strip(), strict=False)
    except ValueError:
        try:
            ipaddress.ip_address(entry.strip())
        except ValueError:
            return "not a valid IP address or CIDR range"
        return "DOSWhitelist is IPv4-only"
    if network.version != 4:
        return "DOSWhitelist is IPv4-only"
    if expand:
        return (
            f"/{network.prefixlen} expands to {network.num_addresses} addresses, "
            f"over the {limit} limit"
        )
    return (
        f"/{network.prefixlen} is not a whole octet, so it has no DOSWhitelist "
        "wildcard; use --expand-cidr to write it out address by address"
    )


def resolve_whitelist(
    admin_ips: list[str] | None = None,
    nodeping_ips: list[str] | None = None,
    expand: bool = False,
    limit: int = EVASIVE_EXPAND_LIMIT,
) -> EvasiveWhitelist:
    """Turn the CRS allowlist entries into DOSWhitelist entries.

    Each entry becomes its wildcard form where one exists.  Otherwise it is
    recorded in ``skipped`` with the reason, unless *expand* is set and the
    range is no larger than *limit*, in which case every address in it is
    written out individually.  Duplicates are dropped, keeping the first
    source that contributed a value, so an admin IP that is also a NodePing
    probe is whitelisted once.
    """
    result = EvasiveWhitelist(expand=expand)
    seen: set[str] = set()

    for source, entries in ((SOURCE_ADMIN, admin_ips or []), (SOURCE_NODEPING, nodeping_ips or [])):
        for entry in entries:
            entry = entry.strip()
            if not entry:
                continue
            value = wildcard_for(entry)
            if value is not None:
                if value not in seen:
                    seen.add(value)
                    label = f"{source} {entry}" if value != entry else f"{source} {value}"
                    result.entries.append((value, label))
                continue
            hosts = expand_hosts(entry, limit) if expand else None
            if hosts is None:
                result.skipped.append((entry, _reason(entry, expand, limit)))
                continue
            for host in hosts:
                if host not in seen:
                    seen.add(host)
                    result.entries.append((host, f"{source} {entry}"))

    return result


def parse_evasive_expand(content: str) -> bool | None:
    """The '# Expand-CIDR: on|off' recorded in a deployed evasive.conf."""
    match = re.search(r"^# Expand-CIDR: (on|off)", content, re.MULTILINE)
    if match is None:
        return None
    return match.group(1) == "on"


def deployed_whitelist(content: str | None = None) -> dict[str, str]:
    """value -> label for the allowlist block in a deployed evasive.conf.

    Scoped to the managed block so the RFC 1918 defaults and the cluster-peer
    entries are not counted as allowlisted sources.
    """
    if content is None:
        content = read_file(EVASIVE_CONF) or ""
    start = content.find(EVASIVE_ALLOWLIST_BEGIN)
    if start == -1:
        return {}
    end = content.find(EVASIVE_ALLOWLIST_END, start)
    block = content[start : end if end != -1 else len(content)]
    found: dict[str, str] = {}
    for match in re.finditer(r"^\s*# (\S[^\n]*)\n\s*DOSWhitelist\s+(\S+)", block, re.MULTILINE):
        found[match.group(2)] = match.group(1).strip()
    return found
