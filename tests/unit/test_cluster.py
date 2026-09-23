"""Tests for SBUS cluster peer discovery and allowlisting.

No network: fetch, resolver and file reads are injected or patched.  All
addresses are documentation ranges (192.0.2.0/24, 2001:db8::/32).
"""

import json
import re
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from nssec.core import cluster as core
from nssec.core.cluster import (
    PUBLIC_IP_LABEL,
    ClusterDiscovery,
    discover_cluster,
    discover_cluster_peers,
    host_from_uri,
    is_valid_host,
    load_cached_cluster,
    parse_manifest_hosts,
    parse_manifest_url,
    save_cached_cluster,
    sort_ips,
)
from nssec.modules.waf.cluster import (
    SOURCE_CACHE,
    SOURCE_DISCOVERED,
    SOURCE_NONE,
    ClusterPeers,
    deployed_evasive_peers,
    deployed_exclusions_peers,
    diff_peers,
    evasive_drift,
    parse_evasive_profile,
    resolve_cluster_peers,
)
from nssec.modules.waf.config import (
    EVASIVE_CONF_TEMPLATE,
    EVASIVE_PROFILES,
    EXCLUSION_TOGGLE_DEFAULTS,
)
from nssec.modules.waf.utils import render

MANIFEST_URL = "https://core1.example.com/SBus-Global.xml"
SBUS_INI = f"""\
# SBus config
SBusPort 8080
SBusClusterManifest {MANIFEST_URL}
SBusOther value
"""
MANIFEST = """\
<xml>
    <sbus uri="https://core1.example.com/SBusMgr"/>
    <sbus uri="https://core2.example.com/SBusMgr"/>
    <sbus uri="https://nsapi1.example.com/SBusMgr"/>
    <sbus uri="https://recording1.example.com/SBusMgr"/>
    <sbus uri="https://core1.example.com/SBusMgr"/>
</xml>
"""
DNS = {
    "core1.example.com": ["192.0.2.11", "2001:db8::11"],
    "core2.example.com": ["192.0.2.12"],
    "nsapi1.example.com": ["192.0.2.21"],
    "recording1.example.com": ["192.0.2.31"],
}


def _fetch(manifest=MANIFEST, status=200, public_ip="192.0.2.99"):
    def fetch(url, verify):
        if url == core.PUBLIC_IP_URL:
            assert verify is True
            return (200, public_ip) if public_ip else (0, "timeout")
        assert url == MANIFEST_URL
        assert verify is False  # cluster's internal certificate
        return status, manifest

    return fetch


def _discover(**kwargs):
    kwargs.setdefault("fetch", _fetch())
    kwargs.setdefault("resolver", lambda host: DNS.get(host, []))
    kwargs.setdefault("read", lambda path: SBUS_INI)
    kwargs.setdefault("fqdn", lambda: None)
    return discover_cluster(**kwargs)


def _peers(peers, hosts=None):
    return ClusterPeers(
        peers={ip: peers[ip] for ip in sort_ips(peers)},
        manifest_url=MANIFEST_URL,
        hosts=hosts or sorted(set(", ".join(peers.values()).split(", "))),
        discovered_at="2026-09-23T12:00:00Z",
        source=SOURCE_DISCOVERED,
    )


def _render_evasive(cluster):
    return render(
        EVASIVE_CONF_TEMPLATE,
        **cluster.template_context(),
        profile="standard",
        log_dir="/tmp/x",
        log_file="/tmp/x.log",
        **EVASIVE_PROFILES["standard"],
    )


def _render_exclusions(cluster):
    from nssec.modules.waf import render_exclusions

    return render_exclusions([], [], EXCLUSION_TOGGLE_DEFAULTS, cluster)


# ---------------------------------------------------------------------------
# sbus.ini
# ---------------------------------------------------------------------------


class TestParseManifestUrl:
    def test_key_present(self):
        assert parse_manifest_url(SBUS_INI) == MANIFEST_URL

    def test_key_absent(self):
        assert parse_manifest_url("SBusPort 8080\n") is None

    def test_extra_whitespace(self):
        ini = f"   SBusClusterManifest \t   {MANIFEST_URL}   \n"
        assert parse_manifest_url(ini) == MANIFEST_URL

    def test_key_without_value(self):
        assert parse_manifest_url("SBusClusterManifest\n") is None

    def test_longer_key_is_not_a_match(self):
        assert parse_manifest_url("SBusClusterManifestBackup https://x.example.com/\n") is None

    def test_file_missing_is_a_discovery_error(self):
        result = _discover(read=lambda path: None)
        assert result.peers == {}
        assert "not found" in result.error

    def test_missing_key_is_a_discovery_error(self):
        result = _discover(read=lambda path: "SBusPort 8080\n")
        assert result.peers == {}
        assert "SBusClusterManifest" in result.error


# ---------------------------------------------------------------------------
# Manifest XML
# ---------------------------------------------------------------------------


class TestParseManifestHosts:
    def test_dedupes_keeping_order(self):
        assert parse_manifest_hosts(MANIFEST) == [
            "core1.example.com",
            "core2.example.com",
            "nsapi1.example.com",
            "recording1.example.com",
        ]

    def test_nsapi_and_recording_hosts_are_kept(self):
        hosts = _discover().hosts
        assert "nsapi1.example.com" in hosts
        assert "recording1.example.com" in hosts

    def test_uri_without_scheme_is_kept(self):
        xml = '<xml><sbus uri="core3.example.com/SBusMgr"/></xml>'
        assert parse_manifest_hosts(xml) == ["core3.example.com"]

    def test_port_and_case_normalised(self):
        assert host_from_uri("HTTPS://Core1.Example.com:8443/SBusMgr") == "core1.example.com"
        assert host_from_uri("https://[2001:db8::5]:443/SBusMgr") == "2001:db8::5"

    def test_elements_without_uri_ignored(self):
        xml = '<xml><sbus/><sbus uri="https://core1.example.com/"/></xml>'
        assert parse_manifest_hosts(xml) == ["core1.example.com"]

    def test_invalid_xml_is_a_discovery_error(self):
        result = _discover(fetch=_fetch(manifest="<xml><sbus"))
        assert result.peers == {}
        assert "not valid XML" in result.error

    def test_hostname_that_could_inject_config_is_refused(self):
        assert not is_valid_host("core9.example.com\nSecRuleEngine Off")
        assert not is_valid_host("core9.example.com\n")
        assert not is_valid_host("bad host")
        assert is_valid_host("recording1-atl.example.com")
        assert is_valid_host("192.0.2.1")

    def test_invalid_hosts_reported_not_resolved(self):
        xml = (
            '<xml><sbus uri="https://core1.example.com/"/>'
            '<sbus uri="https://bad&#10;SecRuleEngine Off/"/></xml>'
        )
        resolved = []
        result = _discover(
            fetch=_fetch(manifest=xml),
            resolver=lambda host: resolved.append(host) or DNS.get(host, []),
        )
        assert result.hosts == ["core1.example.com"]
        assert len(result.invalid) == 1
        assert all("\n" not in host for host in resolved)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


class TestDiscover:
    def test_every_manifest_host_resolved_v4_and_v6(self):
        result = _discover(lookup_public=False)
        assert not result.error
        assert result.peers == {
            "192.0.2.11": "core1.example.com",
            "192.0.2.12": "core2.example.com",
            "192.0.2.21": "nsapi1.example.com",
            "192.0.2.31": "recording1.example.com",
            "2001:db8::11": "core1.example.com",
        }

    def test_public_ip_added(self):
        assert _discover().peers["192.0.2.99"] == PUBLIC_IP_LABEL

    def test_public_ip_lookup_optional(self):
        calls = []

        def fetch(url, verify):
            calls.append(url)
            return 200, MANIFEST

        _discover(fetch=fetch, lookup_public=False)
        assert calls == [MANIFEST_URL]

    def test_public_ip_lookup_failure_is_not_fatal(self):
        result = _discover(fetch=_fetch(public_ip=None))
        assert not result.error
        assert PUBLIC_IP_LABEL not in result.peers.values()

    def test_local_host_is_included_not_filtered(self):
        result = _discover(fqdn=lambda: "core1.example.com", lookup_public=False)
        assert "192.0.2.11" in result.peers

    def test_local_host_missing_from_manifest_is_added(self):
        dns = {**DNS, "core9.example.com": ["192.0.2.19"]}
        result = _discover(
            fqdn=lambda: "core9.example.com",
            resolver=lambda host: dns.get(host, []),
            lookup_public=False,
        )
        assert result.peers["192.0.2.19"] == "core9.example.com (this server)"

    def test_nothing_excluded_by_default(self):
        assert _discover().excluded == []

    def test_exclude_host_is_opt_in_glob(self):
        result = _discover(exclude=["nsapi*"], lookup_public=False)
        assert result.excluded == ["nsapi1.example.com"]
        assert "192.0.2.21" not in result.peers
        assert "192.0.2.31" in result.peers  # recording still included

    def test_shared_ip_lists_every_host(self):
        dns = {**DNS, "nsapi1.example.com": ["192.0.2.12"]}
        result = _discover(resolver=lambda host: dns.get(host, []), lookup_public=False)
        assert result.peers["192.0.2.12"] == "core2.example.com, nsapi1.example.com"

    def test_unresolved_hosts_reported_others_kept(self):
        dns = {k: v for k, v in DNS.items() if k != "core2.example.com"}
        result = _discover(resolver=lambda host: dns.get(host, []), lookup_public=False)
        assert not result.error
        assert result.unresolved == ["core2.example.com"]
        assert "192.0.2.11" in result.peers

    def test_non_200_is_failure(self):
        result = _discover(fetch=_fetch(status=503))
        assert result.peers == {}
        assert "HTTP 503" in result.error

    def test_transport_failure_is_failure(self):
        result = _discover(fetch=lambda url, verify: (0, "Connection timed out"))
        assert result.peers == {}
        assert "timed out" in result.error

    def test_nothing_resolves_is_failure(self):
        result = _discover(resolver=lambda host: [])
        assert result.peers == {}
        assert "resolved" in result.error

    def test_resolver_exception_never_raises(self):
        def boom(host):
            raise RuntimeError("resolver exploded")

        result = _discover(resolver=boom)
        assert result.peers == {}
        assert "resolver exploded" in result.error

    def test_garbage_resolver_output_dropped(self):
        result = _discover(resolver=lambda host: ["not-an-ip", "192.0.2.50"], lookup_public=False)
        assert set(result.peers) == {"192.0.2.50"}

    def test_public_wrapper_returns_tuple(self):
        peers, error = discover_cluster_peers(
            fetch=_fetch(), resolver=lambda h: DNS.get(h, []), read=lambda p: SBUS_INI
        )
        assert error == ""
        assert "192.0.2.11" in peers
        peers, error = discover_cluster_peers(read=lambda p: None)
        assert peers == {}
        assert error


class TestDefaultIO:
    def test_default_fetch_parses_status(self):
        with patch("nssec.core.cluster.ssh.run_command") as run:
            run.return_value = ("<xml/>\n__nssec_http_status__:200", "", 0)
            assert core.default_fetch(MANIFEST_URL, False) == (200, "<xml/>")
            cmd = run.call_args.args[0]
            assert "-k" in cmd
            assert "--max-time" in cmd

    def test_default_fetch_verifies_when_asked(self):
        with patch("nssec.core.cluster.ssh.run_command") as run:
            run.return_value = ("192.0.2.99\n__nssec_http_status__:200", "", 0)
            core.default_fetch(core.PUBLIC_IP_URL, True)
            assert "-k" not in run.call_args.args[0]

    def test_default_fetch_transport_error(self):
        with patch("nssec.core.cluster.ssh.run_command", return_value=("", "timed out", 28)):
            assert core.default_fetch(MANIFEST_URL, False) == (0, "timed out")

    def test_default_resolver_parses_getent(self):
        out = (
            "192.0.2.11      STREAM core1.example.com\n"
            "192.0.2.11      DGRAM\n"
            "2001:db8::11    STREAM\n"
        )
        with patch("nssec.core.cluster.ssh.run_command", return_value=(out, "", 0)):
            assert core.default_resolver("core1.example.com") == ["192.0.2.11", "2001:db8::11"]

    def test_default_resolver_unknown_host(self):
        with patch("nssec.core.cluster.ssh.run_command", return_value=("", "", 2)):
            assert core.default_resolver("nope.example.com") == []


# ---------------------------------------------------------------------------
# Cache and fallback
# ---------------------------------------------------------------------------


class TestCache:
    def test_round_trip(self, isolate_cluster_paths):
        result = _discover()
        assert save_cached_cluster(result)
        path = isolate_cluster_paths / "cluster-peers.json"
        loaded = load_cached_cluster(read=lambda p: path.read_text())
        assert loaded.peers == result.peers
        assert loaded.manifest_url == MANIFEST_URL
        assert loaded.hosts == result.hosts

    def test_failed_discovery_never_cached(self, isolate_cluster_paths):
        assert not save_cached_cluster(ClusterDiscovery(error="boom"))
        assert not (isolate_cluster_paths / "cluster-peers.json").exists()

    def test_corrupt_cache_ignored(self):
        assert load_cached_cluster(read=lambda p: "{not json") is None
        assert load_cached_cluster(read=lambda p: json.dumps({"peers": {"x": "y"}})) is None


def _cache_reader(tmp_path):
    def read(path):
        p = tmp_path / "cluster-peers.json"
        return p.read_text() if path.endswith("cluster-peers.json") and p.exists() else None

    return read


class TestResolveClusterPeers:
    def test_success_saves_cache(self, isolate_cluster_paths):
        cluster = resolve_cluster_peers(
            discoverer=lambda **kw: _discover(**kw), read=_cache_reader(isolate_cluster_paths)
        )
        assert cluster.source == SOURCE_DISCOVERED
        assert (isolate_cluster_paths / "cluster-peers.json").exists()

    def test_failure_with_cache_reuses_it_and_says_so(self, isolate_cluster_paths):
        save_cached_cluster(_discover())
        cluster = resolve_cluster_peers(
            discoverer=lambda **kw: ClusterDiscovery(error="manifest HTTP 503"),
            read=_cache_reader(isolate_cluster_paths),
        )
        assert cluster.source == SOURCE_CACHE
        assert "192.0.2.11" in cluster.peers
        assert any("reusing" in w and "HTTP 503" in w for w in cluster.warnings)

    def test_failure_without_cache_is_empty_with_warning(self, isolate_cluster_paths):
        cluster = resolve_cluster_peers(
            discoverer=lambda **kw: ClusterDiscovery(error="boom"),
            read=_cache_reader(isolate_cluster_paths),
        )
        assert cluster.source == SOURCE_NONE
        assert cluster.peers == {}
        assert any("no cached peers" in w for w in cluster.warnings)

    def test_no_cluster_skips_discovery_uses_cache(self, isolate_cluster_paths):
        save_cached_cluster(_discover())
        discoverer = MagicMock()
        cluster = resolve_cluster_peers(
            discover=False, discoverer=discoverer, read=_cache_reader(isolate_cluster_paths)
        )
        discoverer.assert_not_called()
        assert cluster.source == SOURCE_CACHE
        assert any("--no-cluster" in w for w in cluster.warnings)

    def test_dry_run_does_not_save(self, isolate_cluster_paths):
        resolve_cluster_peers(
            discoverer=lambda **kw: _discover(**kw),
            save=False,
            read=_cache_reader(isolate_cluster_paths),
        )
        assert not (isolate_cluster_paths / "cluster-peers.json").exists()

    def test_discovery_failure_still_installs(self, mock_file_ops):
        """No cache + failed discovery: exclusions and evasive still write fine."""
        from nssec.modules.waf import ModSecurityInstaller

        cluster = resolve_cluster_peers(
            discoverer=lambda **kw: ClusterDiscovery(error="boom"), read=lambda p: None
        )
        installer = ModSecurityInstaller()
        assert installer.install_exclusions(nodeping_ips=[], cluster=cluster).success
        with patch("nssec.modules.waf.Path"):
            assert installer.setup_evasive_config(cluster=cluster).success


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

V4_V6 = {
    "192.0.2.31": "recording1.example.com",
    "192.0.2.11": "core1.example.com",
    "2001:db8::11": "core1.example.com",
    "192.0.2.2": "core2.example.com",
}


class TestEvasiveRender:
    def test_every_ipv4_peer_one_per_line_sorted_with_host_comment(self):
        rendered = _render_evasive(_peers(V4_V6))
        block = rendered[rendered.index("# ---- Cluster peers") :]
        lines = [line.strip() for line in block.splitlines()]
        whitelist = [line.split()[1] for line in lines if line.startswith("DOSWhitelist")]
        assert whitelist == ["192.0.2.2", "192.0.2.11", "192.0.2.31"]
        for ip, host in [("192.0.2.2", "core2.example.com"), ("192.0.2.11", "core1.example.com")]:
            i = lines.index(f"DOSWhitelist            {ip}".strip())
            assert lines[i - 1] == f"# {host}"

    def test_ipv6_left_out_and_noted(self):
        rendered = _render_evasive(_peers(V4_V6))
        assert "2001:db8::11" not in rendered
        assert "1 IPv6 peer address(es) - DOSWhitelist is IPv4-only" in rendered

    def test_no_inline_comments_on_directives(self):
        """Apache has no trailing comments: '# x' would be parsed as arguments."""
        rendered = _render_evasive(_peers(V4_V6))
        for line in rendered.splitlines():
            if line.strip().startswith("DOSWhitelist"):
                assert "#" not in line

    def test_header_names_manifest_host_count_and_time(self):
        rendered = _render_evasive(_peers(V4_V6))
        assert (
            f"# ---- Cluster peers (SBUS manifest: {MANIFEST_URL}, 3 hosts, "
            "2026-09-23T12:00:00Z) ----" in rendered
        )

    def test_rfc1918_lines_kept(self):
        assert "DOSWhitelist            192.168.*.*" in _render_evasive(_peers(V4_V6))

    def test_no_peers_no_block(self):
        assert "Cluster peers" not in _render_evasive(ClusterPeers())

    def test_round_trips_through_deployed_parser(self):
        parsed = deployed_evasive_peers(_render_evasive(_peers(V4_V6)))
        assert parsed == {ip: h for ip, h in V4_V6.items() if ":" not in ip}


class TestExclusionsRender:
    def test_ipv6_included_in_ipmatch(self):
        rendered = _render_exclusions(_peers(V4_V6))
        assert 'SecRule REMOTE_ADDR "@ipMatch 2001:db8::11"' in rendered

    def test_rules_bypass_crs_and_abuse_limits(self):
        rendered = _render_exclusions(_peers(V4_V6))
        start = rendered.index('"id:1001001,')
        rule = rendered[start : rendered.index("\n\n", start)]
        assert "ctl:ruleRemoveByTag=OWASP_CRS" in rule
        assert "ctl:ruleRemoveByTag=nssec-abuse" in rule

    def test_ids_stable_when_manifest_order_changes(self):
        forward = _render_exclusions(_peers(V4_V6))
        backward = _render_exclusions(_peers(dict(reversed(list(V4_V6.items())))))

        def ids(text):
            return re.findall(r'@ipMatch (\S+)"[^"]*"id:(1001\d{3})', text)

        assert ids(forward) == ids(backward)
        assert ids(forward)[0] == ("192.0.2.2", "1001001")

    def test_ids_unique_alongside_other_allowlists(self):
        from nssec.modules.waf import render_exclusions

        rendered = render_exclusions(
            ["198.51.100.7"], ["203.0.113.8"], EXCLUSION_TOGGLE_DEFAULTS, _peers(V4_V6)
        )
        ids = re.findall(r'"id:(\d+)', rendered)
        assert len(ids) == len(set(ids))

    def test_cluster_ids_not_counted_as_admin_or_nodeping(self):
        from nssec.modules.waf.status import _parse_exclusions_meta

        _, _, admin, nodeping = _parse_exclusions_meta(_render_exclusions(_peers(V4_V6)))
        assert (admin, nodeping) == (0, 0)

    def test_round_trips_through_deployed_parser(self):
        assert deployed_exclusions_peers(_render_exclusions(_peers(V4_V6))) == V4_V6

    def test_none_means_cached_peers(self, mock_file_ops):
        """Callers that are not about peers (allowlist edits) must not drop them."""
        from nssec.modules.waf import add_allowlisted_ip

        cached = json.dumps({"peers": {"192.0.2.11": "core1.example.com"}})
        mock_file_ops["read"].side_effect = lambda p: cached if p.endswith(".json") else ""
        add_allowlisted_ip("198.51.100.4")
        kwargs = mock_file_ops["render"].call_args.kwargs
        assert kwargs["cluster_peers"] == [("192.0.2.11", "core1.example.com")]


class TestRestrictRender:
    def test_peers_in_own_block_ipv6_included(self):
        from nssec.modules.waf.restrict import _render_conf

        rendered = _render_conf(["SiPbx"], ["127.0.0.1"], _peers(V4_V6))
        assert "Require ip 2001:db8::11" in rendered
        assert rendered.index("BEGIN nssec cluster peers") < rendered.index("192.0.2.2")
        for line in rendered.splitlines():
            if "Require ip" in line:
                assert "#" not in line

    def test_parse_ips_skips_cluster_block(self, tmp_path):
        """Peers must not leak into the operator's saved restrict IP list."""
        from nssec.modules.waf.restrict import _render_conf, parse_ips

        path = tmp_path / "restrict.conf"
        path.write_text(_render_conf(["SiPbx"], ["127.0.0.1", "198.51.100.7"], _peers(V4_V6)))
        with patch("nssec.modules.waf.restrict.read_file", side_effect=lambda p: path.read_text()):
            assert parse_ips(str(path)) == ["127.0.0.1", "198.51.100.7"]

    def test_rerender_keeps_operator_ips_and_segments(self, isolate_cluster_paths):
        from nssec.modules.waf import restrict

        path = isolate_cluster_paths / "nssec-restrict.conf"
        path.write_text(restrict._render_conf(["SiPbx", "ndp"], ["127.0.0.1"], ClusterPeers()))
        with patch("nssec.modules.waf.restrict.read_file", side_effect=lambda p: path.read_text()):
            result = restrict.rerender_with_cluster(_peers(V4_V6))
        assert result.success
        text = path.read_text()
        assert '"^/(SiPbx|ndp)/"' in text
        assert "Require ip 127.0.0.1" in text
        assert "Require ip 192.0.2.31" in text

    def test_rerender_skipped_when_not_deployed(self):
        from nssec.modules.waf.restrict import rerender_with_cluster

        assert rerender_with_cluster(_peers(V4_V6)).skipped


# ---------------------------------------------------------------------------
# Drift, diff, profile
# ---------------------------------------------------------------------------


class TestDriftAndDiff:
    def test_drift_when_host_missing_from_evasive(self):
        cluster = _peers(V4_V6, hosts=["core1.example.com", "core2.example.com"])
        deployed = _render_evasive(_peers({"192.0.2.11": "core1.example.com"}))
        assert evasive_drift(cluster, deployed) == ["core2.example.com"]

    def test_no_drift_when_all_listed(self):
        cluster = _peers(V4_V6)
        assert evasive_drift(cluster, _render_evasive(cluster)) == []

    def test_ipv6_only_host_is_not_drift(self):
        cluster = _peers({"2001:db8::7": "core7.example.com"}, hosts=["core7.example.com"])
        assert evasive_drift(cluster, _render_evasive(cluster)) == []

    def test_diff(self):
        old = {"192.0.2.1": "a", "192.0.2.2": "b"}
        new = {"192.0.2.2": "b", "192.0.2.3": "c"}
        assert diff_peers(old, new) == (["192.0.2.3"], ["192.0.2.1"])

    def test_profile_parsed(self):
        assert parse_evasive_profile(_render_evasive(ClusterPeers())) == "standard"


class TestRefreshEvasiveKeepsProfile:
    def test_strict_profile_preserved(self, mock_file_ops):
        from nssec.modules.waf import ModSecurityInstaller

        mock_file_ops["read"].return_value = "# Profile: strict\n"
        with patch("nssec.modules.waf.Path"):
            result = ModSecurityInstaller().refresh_evasive_cluster(_peers(V4_V6))
        assert result.success
        assert mock_file_ops["render"].call_args.kwargs["profile"] == "strict"
        assert mock_file_ops["render"].call_args.kwargs["cluster_ipv4"]

    def test_skipped_when_not_deployed(self, mock_file_ops):
        from nssec.modules.waf import ModSecurityInstaller

        mock_file_ops["read"].return_value = None
        assert ModSecurityInstaller().refresh_evasive_cluster(_peers(V4_V6)).skipped


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@pytest.fixture
def installer():
    with patch("nssec.modules.waf.ModSecurityInstaller") as cls:
        inst = MagicMock()
        pf = MagicMock()
        pf.is_root = True
        pf.modsec_installed = True
        inst.preflight.return_value = pf
        ok = MagicMock(success=True, skipped=False, message="ok")
        for name in (
            "install_exclusions",
            "refresh_evasive_cluster",
            "write_security2_conf",
            "validate_config",
            "reload_apache",
        ):
            getattr(inst, name).return_value = ok
        cls.return_value = inst
        yield inst


def _invoke(*args):
    from nssec.cli.waf_commands import waf

    with patch("nssec.modules.waf.fetch_nodeping_probe_ips", return_value=([], "")):
        return CliRunner().invoke(waf, list(args))


class TestUpdateExclusionsCluster:
    def test_discovery_failure_does_not_break_install(self, installer):
        # sbus.ini is isolated to a missing tmp path, so discovery fails.
        result = _invoke("update-exclusions", "-y")
        assert result.exit_code == 0, result.output
        assert "no cached peers" in result.output
        cluster = installer.install_exclusions.call_args.kwargs["cluster"]
        assert cluster.peers == {}

    def test_no_cluster_skips_discovery(self, installer):
        with patch("nssec.modules.waf.cluster.discover_cluster") as disc:
            result = _invoke("update-exclusions", "-y", "--no-cluster")
        assert result.exit_code == 0, result.output
        disc.assert_not_called()

    def test_peers_passed_to_every_config(self, installer):
        cluster = _peers(V4_V6)
        with patch("nssec.modules.waf.cluster.resolve_cluster_peers", return_value=cluster), patch(
            "nssec.modules.waf.restrict.rerender_with_cluster"
        ) as restrict:
            restrict.return_value = MagicMock(success=True, skipped=True, message="n/a")
            result = _invoke("update-exclusions", "-y")
        assert result.exit_code == 0, result.output
        assert installer.install_exclusions.call_args.kwargs["cluster"] is cluster
        installer.refresh_evasive_cluster.assert_called_once_with(cluster)
        restrict.assert_called_once_with(cluster)
        assert "snapshot" in installer.validate_config.call_args.kwargs


class TestClusterRefresh:
    def _run(self, *args, discovered=None, deployed=None, configtest_ok=True):
        from nssec.modules.waf.types import StepResult

        discovered = discovered if discovered is not None else _peers(V4_V6)
        inst = MagicMock()
        ok = StepResult(message="ok")
        inst.install_exclusions.return_value = ok
        inst.refresh_evasive_cluster.return_value = ok
        inst.validate_config.return_value = (
            ok if configtest_ok else StepResult(success=False, error="configtest failed")
        )
        inst.reload_apache.return_value = ok
        patches = {
            "nssec.core.ssh.is_root": True,
            "nssec.modules.waf.ModSecurityInstaller": inst,
            "nssec.modules.waf.cluster.resolve_cluster_peers": discovered,
            "nssec.modules.waf.cluster.deployed_peers": deployed or {},
            "nssec.modules.waf.cluster.deployed_evasive_peers": {},
            "nssec.modules.waf.utils.file_exists": True,
            "nssec.modules.waf.utils.snapshot_files": {"/x": "old"},
            "nssec.modules.waf.restrict.rerender_with_cluster": ok,
            "nssec.core.cluster.save_cached_cluster": True,
        }
        with ExitStack() as stack:
            mocks = {
                target: stack.enter_context(patch(target, return_value=value))
                for target, value in patches.items()
            }
            save = mocks["nssec.core.cluster.save_cached_cluster"]
            result = _invoke("cluster", "refresh", "-y", *args)
        return result, inst, save

    def test_dry_run_shows_diff_and_writes_nothing(self):
        result, inst, save = self._run(
            "--dry-run", deployed={"192.0.2.200": "old.example.com", "192.0.2.11": "core1"}
        )
        assert result.exit_code == 0, result.output
        assert "+ 192.0.2.2" in result.output
        assert "- 192.0.2.200" in result.output
        inst.install_exclusions.assert_not_called()
        inst.refresh_evasive_cluster.assert_not_called()
        save.assert_not_called()

    def test_writes_all_configs_then_configtest_then_reload(self):
        result, inst, save = self._run()
        assert result.exit_code == 0, result.output
        inst.install_exclusions.assert_called_once()
        inst.refresh_evasive_cluster.assert_called_once()
        assert inst.validate_config.call_args.kwargs["snapshot"] == {"/x": "old"}
        inst.reload_apache.assert_called_once()
        save.assert_called_once()

    def test_configtest_failure_rolls_back_no_reload(self):
        result, inst, save = self._run(configtest_ok=False)
        assert result.exit_code == 1
        inst.reload_apache.assert_not_called()
        save.assert_not_called()

    def test_discovery_failure_changes_nothing(self):
        failed = ClusterPeers(source=SOURCE_CACHE, warnings=["Cluster discovery failed (x)"])
        result, inst, save = self._run(discovered=failed)
        assert result.exit_code == 1
        assert "Nothing changed" in result.output
        inst.install_exclusions.assert_not_called()


class TestStatusRow:
    def test_status_counts_and_drift(self, isolate_cluster_paths):
        from nssec.modules.waf import status as status_mod

        save_cached_cluster(_discover())
        cache = (isolate_cluster_paths / "cluster-peers.json").read_text()
        evasive = _render_evasive(_peers({"192.0.2.11": "core1.example.com"}))

        def read(path):
            if path.endswith("cluster-peers.json"):
                return cache
            if path.endswith("evasive.conf"):
                return evasive
            return None

        with patch.object(status_mod, "_read_file", side_effect=read), patch.object(
            status_mod, "_pkg_installed", return_value=False
        ), patch.object(status_mod, "_get_pkg_version", return_value=None), patch.object(
            status_mod, "_is_ondrej_apache_ppa", return_value=False
        ):
            status = status_mod.get_waf_status()
        assert status.cluster_peer_count == 6
        assert status.cluster_ipv6_count == 1
        assert status.cluster_manifest_url == MANIFEST_URL
        assert status.cluster_evasive_count == 1
        assert set(status.cluster_drift) == {
            "core2.example.com",
            "nsapi1.example.com",
            "recording1.example.com",
        }
