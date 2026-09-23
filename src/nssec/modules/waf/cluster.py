"""Cluster-peer allowlisting for the WAF configs.

Chooses which cluster peers to write (fresh discovery, else the cached last
good discovery, never a silent drop), and knows how the peers appear in each
deployed config so status can report drift and refresh can show a diff.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterable

from nssec.core.cluster import (
    ClusterDiscovery,
    discover_cluster,
    is_ipv4,
    load_cached_cluster,
    save_cached_cluster,
    sort_ips,
)
from nssec.modules.waf.config import (
    CLUSTER_BLOCK_END,
    CLUSTER_RULE_ID_BASE,
    EVASIVE_CONF,
    NS_EXCLUSIONS_CONF,
    RESTRICT_CLUSTER_BEGIN,
    RESTRICT_CLUSTER_END,
)
from nssec.modules.waf.utils import read_file

SOURCE_DISCOVERED = "discovered"
SOURCE_CACHE = "cache"
SOURCE_NONE = "none"


@dataclass
class ClusterPeers:
    """The cluster peers to render into the configs, and where they came from."""

    peers: dict[str, str] = field(default_factory=dict)  # ip -> hostname(s), sorted
    manifest_url: str = ""
    hosts: list[str] = field(default_factory=list)
    discovered_at: str = ""
    source: str = SOURCE_NONE
    warnings: list[str] = field(default_factory=list)

    @property
    def ipv4(self) -> list[tuple[str, str]]:
        return [(ip, host) for ip, host in self.peers.items() if is_ipv4(ip)]

    @property
    def ipv6(self) -> list[tuple[str, str]]:
        return [(ip, host) for ip, host in self.peers.items() if not is_ipv4(ip)]

    def template_context(self) -> dict:
        """Jinja context shared by the evasive, exclusions and restrict templates."""
        return {
            "cluster_peers": list(self.peers.items()),
            "cluster_ipv4": self.ipv4,
            "cluster_ipv6": self.ipv6,
            "cluster_manifest_url": self.manifest_url or "unknown",
            "cluster_host_count": len(self.hosts),
            "cluster_discovered_at": self.discovered_at or "unknown",
            "cluster_rule_id_base": CLUSTER_RULE_ID_BASE,
            "cluster_block_end": CLUSTER_BLOCK_END,
            "restrict_cluster_begin": RESTRICT_CLUSTER_BEGIN,
            "restrict_cluster_end": RESTRICT_CLUSTER_END,
        }


def _from_discovery(result: ClusterDiscovery, source: str) -> ClusterPeers:
    return ClusterPeers(
        peers={ip: result.peers[ip] for ip in sort_ips(result.peers)},
        manifest_url=result.manifest_url,
        hosts=list(result.hosts),
        discovered_at=result.discovered_at,
        source=source,
    )


def cached_cluster_peers(read: Callable[[str], str | None] = read_file) -> ClusterPeers:
    """The cached peers (no discovery), or an empty set if there is no cache."""
    cached = load_cached_cluster(read=read)
    if cached is None:
        return ClusterPeers()
    return _from_discovery(cached, SOURCE_CACHE)


def resolve_cluster_peers(
    discover: bool = True,
    lookup_public: bool = True,
    exclude: Iterable[str] = (),
    save: bool = True,
    discoverer: Callable[..., ClusterDiscovery] = discover_cluster,
    read: Callable[[str], str | None] = read_file,
) -> ClusterPeers:
    """Discover the cluster peers, falling back to the cache on failure.

    Never raises and never silently drops peers: when discovery fails or is
    skipped, the cached last good result is used and a warning says so.
    """
    if discover:
        result = discoverer(lookup_public=lookup_public, exclude=tuple(exclude))
        if not result.error:
            peers = _from_discovery(result, SOURCE_DISCOVERED)
            if result.unresolved:
                peers.warnings.append(
                    "manifest host(s) did not resolve and are not allowlisted: "
                    + ", ".join(result.unresolved)
                )
            if result.invalid:
                peers.warnings.append(
                    "manifest host(s) with invalid names ignored: " + ", ".join(result.invalid)
                )
            if result.excluded:
                peers.warnings.append("excluded by --exclude-host: " + ", ".join(result.excluded))
            if save and not save_cached_cluster(result):
                peers.warnings.append("could not write the cluster peer cache")
            return peers
        reason = f"Cluster discovery failed ({result.error})"
    else:
        reason = "Cluster discovery skipped (--no-cluster)"

    cached = cached_cluster_peers(read=read)
    if cached.peers:
        cached.warnings.append(
            f"{reason}; reusing {len(cached.peers)} cached cluster peer address(es) "
            f"from {cached.discovered_at or 'an earlier run'}"
        )
    else:
        cached.warnings.append(f"{reason}; no cached peers, so no cluster peers are allowlisted")
    return cached


# ---------------------------------------------------------------------------
# Reading the peers back out of deployed configs
# ---------------------------------------------------------------------------


def _hosted_entries(content: str, entry_re: str) -> dict[str, str]:
    """ip -> host for "# host" comment lines followed by an entry line."""
    found: dict[str, str] = {}
    for match in re.finditer(r"^\s*# (\S[^\n]*)\n\s*" + entry_re, content, re.MULTILINE):
        found[match.group(2)] = match.group(1).strip()
    return found


def deployed_exclusions_peers(content: str | None = None) -> dict[str, str]:
    """Cluster peers in the deployed ModSecurity exclusions (IPv4 and IPv6)."""
    if content is None:
        content = read_file(NS_EXCLUSIONS_CONF) or ""
    prefix = str(CLUSTER_RULE_ID_BASE)[:4]
    return _hosted_entries(
        content,
        r'SecRule REMOTE_ADDR "@ipMatch ([^"\s]+)"[^"]*"id:' + prefix + r"\d{3},",
    )


def deployed_evasive_peers(content: str | None = None) -> dict[str, str]:
    """Cluster peers in the deployed mod_evasive config (IPv4 only)."""
    if content is None:
        content = read_file(EVASIVE_CONF) or ""
    start = content.find("# ---- Cluster peers")
    if start == -1:
        return {}
    end = content.find(CLUSTER_BLOCK_END, start)
    block = content[start : end if end != -1 else len(content)]
    return _hosted_entries(block, r"DOSWhitelist\s+(\S+)")


def deployed_peers() -> dict[str, str]:
    """What is allowlisted now: exclusions if deployed, else evasive.conf."""
    return deployed_exclusions_peers() or deployed_evasive_peers()


def diff_peers(old: dict[str, str], new: dict[str, str]) -> tuple[list[str], list[str]]:
    """(added, removed) IPs between two ip -> host maps, sorted."""
    added = sort_ips(ip for ip in new if ip not in old)
    removed = sort_ips(ip for ip in old if ip not in new)
    return added, removed


def evasive_drift(cluster: ClusterPeers, evasive_content: str) -> list[str]:
    """Manifest hosts with an IPv4 address that evasive.conf does not allowlist."""
    listed = deployed_evasive_peers(evasive_content)
    missing: list[str] = []
    for host in cluster.hosts:
        wanted = [ip for ip, names in cluster.ipv4 if host in names.split(", ")]
        if wanted and not any(ip in listed for ip in wanted):
            missing.append(host)
    return missing


def parse_evasive_profile(content: str) -> str | None:
    """The '# Profile: <name>' recorded in a deployed evasive.conf."""
    match = re.search(r"^# Profile: (\S+)", content, re.MULTILINE)
    return match.group(1) if match else None


def as_discovery(cluster: ClusterPeers) -> ClusterDiscovery:
    """Convert back to the cache format (for saving after a successful write)."""
    return ClusterDiscovery(
        peers=dict(cluster.peers),
        manifest_url=cluster.manifest_url,
        hosts=list(cluster.hosts),
        discovered_at=cluster.discovered_at,
    )


def format_age(timestamp: str) -> str:
    """Human age of an ISO-8601 UTC timestamp such as 2026-09-08T12:00:00Z."""
    try:
        then = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return "unknown time"
    seconds = max(0, int((datetime.now(timezone.utc) - then).total_seconds()))
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"
