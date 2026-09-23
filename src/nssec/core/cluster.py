"""SBUS cluster peer discovery.

A NetSapiens cluster lists its members in an SBUS manifest, whose URL is set
in sbus.ini.  Every member delivers SBUS events to every other member over
HTTP, often from public addresses, so the HTTP protections on this server
(mod_evasive, ModSecurity, the admin-UI restrictions) must allowlist them;
otherwise a burst of events looks like a flood, deliveries are denied, SBUS
retries them, and the block keeps itself going.

Discovery runs over the core/ssh.py remote mode: sbus.ini is read on the
target, and the manifest fetch, DNS resolution and public-IP lookup all run
on the target box, which is the one whose peers matter.

Unlike tools that pick scan/block targets from the manifest, nothing is
filtered out here: nsapi and recording hosts publish SBUS events too, and the
local host calls itself.  Hosts are only dropped when the operator names them
with ``exclude``.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Tuple

from nssec.core import ssh

SBUS_INI_PATH = "/usr/local/NetSapiens/Sbus/bin/sbus.ini"
SBUS_MANIFEST_KEY = "SBusClusterManifest"
PUBLIC_IP_URL = "https://api.ipify.org"
FETCH_TIMEOUT = 5
CLUSTER_CACHE_PATH = "/etc/nssec/cluster-peers.json"

PUBLIC_IP_LABEL = "public IP of this server"
LOCAL_HOST_SUFFIX = " (this server)"

# (url, verify_tls) -> (http_status, body).  Status 0 means the request itself
# failed; body then carries the error text.
Fetch = Callable[[str, bool], Tuple[int, str]]
# host -> every A and AAAA address of that host (empty if it does not resolve)
Resolver = Callable[[str], List[str]]
# path -> file contents, or None if missing/unreadable
Reader = Callable[[str], Optional[str]]

# Hostnames end up in comments in Apache config files, and the manifest is
# fetched without TLS verification, so anything that is not a plain DNS name
# is refused rather than written out.
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
_HOSTNAME_RE = re.compile(rf"\A(?=.{{1,253}}\Z){_LABEL}(?:\.{_LABEL})*\Z")


@dataclass
class ClusterDiscovery:
    """Result of one discovery run (also the on-disk cache format)."""

    peers: dict[str, str] = field(default_factory=dict)  # ip -> hostname(s)
    manifest_url: str = ""
    hosts: list[str] = field(default_factory=list)  # manifest hosts, in order
    unresolved: list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)
    invalid: list[str] = field(default_factory=list)
    discovered_at: str = ""
    error: str = ""


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def parse_manifest_url(ini: str) -> str | None:
    """Return the SBusClusterManifest URL from sbus.ini content, or None.

    The line is ``SBusClusterManifest <url>`` (whitespace, no ``=``).
    """
    for line in ini.splitlines():
        stripped = line.strip()
        if not stripped.startswith(SBUS_MANIFEST_KEY):
            continue
        parts = stripped.split(None, 1)
        if parts[0] != SBUS_MANIFEST_KEY or len(parts) < 2:
            continue
        url = parts[1].strip()
        if url:
            return url
    return None


def host_from_uri(uri: str) -> str | None:
    """Extract the host from an SBUS uri such as ``https://core1.example.com/SBusMgr``.

    A uri without a scheme (``core1.example.com/SBusMgr``) is accepted too:
    dropping a real peer would bring back the flood blocking this exists to
    prevent.  Any port is stripped.
    """
    uri = uri.strip()
    match = re.match(r"https?://([^/]+)", uri, re.IGNORECASE)
    authority = match.group(1) if match else uri.split("/", 1)[0]
    authority = authority.rsplit("@", 1)[-1]  # drop any userinfo
    if authority.startswith("["):  # [IPv6]:port
        host = authority[1:].split("]", 1)[0]
    else:
        host = authority.split(":", 1)[0]
    host = host.strip().rstrip(".").lower()
    return host or None


def is_valid_host(host: str) -> bool:
    """True for a DNS name or IP literal that is safe to write into a config."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_HOSTNAME_RE.match(host))


def parse_manifest_hosts(xml_text: str) -> list[str]:
    """Hosts of every ``<sbus uri=...>`` in the manifest, deduped, in order.

    Raises ValueError if the XML cannot be parsed.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"manifest is not valid XML: {exc}") from exc
    hosts: list[str] = []
    for element in root.iter("sbus"):
        uri = element.get("uri")
        if not uri:
            continue
        host = host_from_uri(uri)
        if host and host not in hosts:
            hosts.append(host)
    return hosts


def sort_ips(ips: Iterable[str]) -> list[str]:
    """Sort IPs numerically, IPv4 first, so renders do not churn on reorder."""
    parsed = sorted({ipaddress.ip_address(ip) for ip in ips}, key=lambda a: (a.version, a))
    return [str(a) for a in parsed]


def is_ipv4(ip: str) -> bool:
    return ipaddress.ip_address(ip).version == 4


def _valid_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Default I/O (runs on the target box via core/ssh.py)
# ---------------------------------------------------------------------------


def default_fetch(url: str, verify: bool) -> tuple[int, str]:
    """GET url with curl on the target box; returns (status, body)."""
    marker = "\n__nssec_http_status__:"
    cmd = ["curl", "-s", "--max-time", str(FETCH_TIMEOUT), "-w", marker + "%{http_code}"]
    if not verify:
        cmd.append("-k")
    cmd.append(url)
    stdout, stderr, rc = ssh.run_command(cmd, timeout=FETCH_TIMEOUT + 5)
    if rc != 0 or marker not in stdout:
        return 0, (stderr or stdout or f"curl exited {rc}").strip()
    body, _, status = stdout.rpartition(marker)
    try:
        return int(status.strip()), body
    except ValueError:
        return 0, f"unexpected curl output: {status!r}"


def default_resolver(host: str) -> list[str]:
    """All A and AAAA addresses of host, resolved on the target box."""
    stdout, _, rc = ssh.run_command(["getent", "ahosts", host], timeout=15)
    if rc != 0:
        return []
    ips: list[str] = []
    for line in stdout.splitlines():
        fields = line.split()
        ip = _valid_ip(fields[0]) if fields else None
        if ip and ip not in ips:
            ips.append(ip)
    return ips


def local_fqdn() -> str | None:
    """The target box's own FQDN, or None."""
    stdout, _, rc = ssh.run_command(["hostname", "-f"], timeout=10)
    name = stdout.strip().lower()
    return name if rc == 0 and name and is_valid_host(name) else None


def lookup_public_ip(fetch: Fetch) -> str | None:
    """The target box's public IP as seen from outside (NATed cores)."""
    status, body = fetch(PUBLIC_IP_URL, True)
    if status != 200:
        return None
    return _valid_ip(body)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _add_peer(peers: dict[str, str], ip: str, label: str) -> None:
    existing = peers.get(ip)
    if existing is None:
        peers[ip] = label
    elif label not in existing.split(", "):
        peers[ip] = f"{existing}, {label}"


def discover_cluster(
    fetch: Fetch | None = None,
    resolver: Resolver | None = None,
    read: Reader | None = None,
    lookup_public: bool = True,
    exclude: Iterable[str] = (),
    fqdn: Callable[[], str | None] | None = None,
) -> ClusterDiscovery:
    """Discover every SBUS cluster member's addresses.

    Never raises: any failure is returned in ``error`` with no peers, and the
    caller carries on without cluster entries.
    """
    fetch = fetch or default_fetch
    resolver = resolver or default_resolver
    read = read or ssh.read_file
    fqdn = fqdn or local_fqdn
    result = ClusterDiscovery(discovered_at=_now())
    try:
        ini = read(SBUS_INI_PATH)
        if ini is None:
            result.error = f"{SBUS_INI_PATH} not found (is this an SBUS host?)"
            return result
        url = parse_manifest_url(ini)
        if not url:
            result.error = f"no {SBUS_MANIFEST_KEY} line in {SBUS_INI_PATH}"
            return result
        result.manifest_url = url

        # The manifest is served with the cluster's internal certificate.
        status, body = fetch(url, False)
        if status != 200:
            detail = f"HTTP {status}" if status else body
            result.error = f"could not fetch manifest {url}: {detail}"
            return result

        hosts = parse_manifest_hosts(body)
        patterns = [p.lower() for p in exclude]
        for host in hosts:
            if not is_valid_host(host):
                result.invalid.append(host)
            elif any(fnmatch.fnmatch(host, p) for p in patterns):
                result.excluded.append(host)
            else:
                result.hosts.append(host)
        if not result.hosts:
            result.error = f"manifest {url} lists no usable sbus hosts"
            return result

        peers: dict[str, str] = {}
        for host in result.hosts:
            ips = [ip for ip in (_valid_ip(a) for a in resolver(host)) if ip]
            if not ips:
                result.unresolved.append(host)
            for ip in ips:
                _add_peer(peers, ip, host)
        if not peers:
            result.error = f"none of the {len(result.hosts)} manifest hosts resolved"
            return result

        # The local host is normally in the manifest already; make sure its
        # own names count even if it is not.
        own = fqdn()
        if own and own not in result.hosts:
            for own_ip in (_valid_ip(a) for a in resolver(own)):
                if own_ip and own_ip not in peers:
                    _add_peer(peers, own_ip, own + LOCAL_HOST_SUFFIX)

        # A NATed core reaches its peers from an address it does not see on
        # its own interfaces.
        if lookup_public:
            public_ip = lookup_public_ip(fetch)
            if public_ip and public_ip not in peers:
                _add_peer(peers, public_ip, PUBLIC_IP_LABEL)

        result.peers = {ip: peers[ip] for ip in sort_ips(peers)}
        return result
    except Exception as exc:  # discovery must never break an install/reload
        result.peers = {}
        result.error = f"cluster discovery failed: {exc}"
        return result


def discover_cluster_peers(
    fetch: Fetch | None = None,
    resolver: Resolver | None = None,
    read: Reader | None = None,
    lookup_public: bool = True,
    exclude: Iterable[str] = (),
) -> tuple[dict[str, str], str]:
    """Return (ip -> hostname, error).  Empty dict plus error on any failure."""
    result = discover_cluster(
        fetch=fetch, resolver=resolver, read=read, lookup_public=lookup_public, exclude=exclude
    )
    return result.peers, result.error


# ---------------------------------------------------------------------------
# Cache of the last good discovery
# ---------------------------------------------------------------------------


def load_cached_cluster(read: Reader | None = None) -> ClusterDiscovery | None:
    """Last successful discovery, or None if there is no usable cache."""
    content = (read or ssh.read_file)(CLUSTER_CACHE_PATH)
    if not content:
        return None
    try:
        data = json.loads(content)
        peers = {str(ip): str(host) for ip, host in data.get("peers", {}).items()}
        if not peers or any(_valid_ip(ip) != ip for ip in peers):
            return None
        return ClusterDiscovery(
            peers={ip: peers[ip] for ip in sort_ips(peers)},
            manifest_url=str(data.get("manifest_url", "")),
            hosts=[str(h) for h in data.get("hosts", [])],
            unresolved=[str(h) for h in data.get("unresolved", [])],
            excluded=[str(h) for h in data.get("excluded", [])],
            discovered_at=str(data.get("discovered_at", "")),
        )
    except (ValueError, AttributeError, TypeError):
        return None


def save_cached_cluster(result: ClusterDiscovery, path: str | None = None) -> bool:
    """Persist a successful discovery.  Failed discoveries are never cached."""
    path = path or CLUSTER_CACHE_PATH
    if result.error or not result.peers:
        return False
    data = asdict(result)
    data.pop("error", None)
    data.pop("invalid", None)
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(data, indent=2) + "\n")
        return True
    except OSError:
        return False
