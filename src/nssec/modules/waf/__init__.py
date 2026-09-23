"""WAF/ModSecurity management module.

Provides idempotent installation and configuration of ModSecurity v2
with OWASP CRS v4 on Apache2 for NetSapiens servers.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
from pathlib import Path

from nssec.core.ssh import is_directory, is_root
from nssec.modules.waf.cluster import ClusterPeers, cached_cluster_peers, parse_evasive_profile
from nssec.modules.waf.config import (
    ABUSE_LIMITS,
    BACKUP_SUFFIX,
    BLOCKED_USER_AGENTS,
    CRS_APT_PACKAGE,
    CRS_GITHUB_DOWNLOAD,
    CRS_INSTALL_DIR,
    CRS_RULES_REQUIRE_296,
    CRS_SEARCH_PATHS,
    CRS_SETUP_OVERRIDES_TEMPLATE,
    EVASIVE_CONF,
    EVASIVE_CONF_TEMPLATE,
    EVASIVE_DEFAULT_PROFILE,
    EVASIVE_LOAD,
    EVASIVE_LOG_DIR,
    EVASIVE_LOG_FILE,
    EVASIVE_PACKAGE,
    EVASIVE_PROFILES,
    MODSEC_AUDIT_LOG,
    MODSEC_CONF,
    MODSEC_CONF_RECOMMENDED,
    MODSEC_CONF_TEMPLATE,
    MODSEC_DATA_DIR,
    MODSEC_DIR,
    MODSEC_PACKAGE,
    MODSEC_TMP_DIR,
    NS_EXCLUSIONS_CONF,
    NS_EXCLUSIONS_HASH,
    NS_EXCLUSIONS_TEMPLATE,
    NS_EXCLUSIONS_VERSION,
    PINNED_CRS_VERSION,
    SECURITY2_CONF,
    SECURITY2_CONF_TEMPLATE,
    SECURITY2_LOAD,
)
from nssec.modules.waf.types import InstallResult, PreflightResult, StepResult
from nssec.modules.waf.utils import (
    append_crs_to_security2,
    backup_file,
    detect_modsec_mode,
    detect_modsec_version,
    file_exists,
    package_installed,
    parse_exclusion_toggles,
    parse_security2_conf,
    read_file,
    render,
    restore_snapshot,
    run_cmd,
    version_gte,
    write_file,
    write_security2_full,
)


def fetch_nodeping_probe_ips() -> tuple[list[str], str]:
    """Fetch NodePing monitoring probe IPs for WAF allowlisting."""
    from nssec.modules.mtls.utils import fetch_nodeping_ips

    return fetch_nodeping_ips()


def normalize_ipmatch_entry(ip: str) -> str:
    """Strip a redundant full-host CIDR suffix ("/32" or "/128").

    ModSecurity's @ipMatch operator fails to parse full-host CIDR notation —
    "SecRule REMOTE_ADDR \"@ipMatch 1.2.3.4/32\"" raises "Error creating rule:
    Could not add entry" at Apache startup, even though the equivalent bare
    address works fine (SpiderLabs/ModSecurity#849). A bare address is exactly
    equivalent to a /32 (or /128) network, so dropping the suffix is lossless.
    """
    if "/" not in ip:
        return ip
    try:
        network = ipaddress.ip_network(ip, strict=False)
    except ValueError:
        return ip
    if network.num_addresses == 1:
        return str(network.network_address)
    return ip


def _parse_allowlist_ips(id_pattern: str) -> list[str]:
    """Extract @ipMatch IPs from deployed allowlist rules matching id_pattern.

    The deployed conf is the only store for these IPs — there is no separate
    state file — so every render has to read back what is already there.
    """
    content = read_file(NS_EXCLUSIONS_CONF)
    if not content:
        return []
    return re.findall(
        rf'SecRule REMOTE_ADDR "@ipMatch\s+([^\s"]+)"[^"]*"id:{id_pattern}',
        content,
        re.DOTALL,
    )


def get_allowlisted_ips() -> list[str]:
    """Parse allowlisted admin IPs from the deployed exclusions conf."""
    # Admin IP rules are numbered from 1000100 (id:10001xx)
    return _parse_allowlist_ips(r"10001\d+")


def get_nodeping_ips() -> list[str]:
    """Parse allowlisted NodePing probe IPs from the deployed exclusions conf."""
    # NodePing probe rules are numbered from 1000200 (id:10002xx)
    return _parse_allowlist_ips(r"10002\d+")


def get_exclusion_toggles() -> dict[str, bool]:
    """Optional-feature toggles of the deployed exclusions conf (defaults if absent)."""
    return parse_exclusion_toggles(read_file(NS_EXCLUSIONS_CONF) or "")


def render_exclusions(
    admin_ips: list[str],
    nodeping_ips: list[str],
    toggles: dict[str, bool],
    cluster: ClusterPeers | None = None,
) -> str:
    """Render NS_EXCLUSIONS_TEMPLATE with every section's inputs supplied.

    ``cluster`` None means the cached cluster peers, so a caller that is not
    about cluster peers (e.g. an allowlist edit) never drops them.
    """
    if cluster is None:
        cluster = cached_cluster_peers(read=read_file)
    return render(
        NS_EXCLUSIONS_TEMPLATE,
        **cluster.template_context(),
        admin_ips=admin_ips,
        nodeping_ips=nodeping_ips,
        toggles=toggles,
        limits=ABUSE_LIMITS,
        blocked_user_agents=BLOCKED_USER_AGENTS,
        version=NS_EXCLUSIONS_VERSION,
        template_hash=NS_EXCLUSIONS_HASH,
    )


def add_allowlisted_ip(ip: str) -> StepResult:
    """Add an IP address to the allowlist and regenerate exclusions config."""
    ip = normalize_ipmatch_entry(ip)
    current_ips = get_allowlisted_ips()
    if ip in current_ips:
        return StepResult(skipped=True, message=f"{ip} already allowlisted")

    new_ips = current_ips + [ip]

    if file_exists(NS_EXCLUSIONS_CONF):
        backup_file(NS_EXCLUSIONS_CONF)

    content = render_exclusions(
        admin_ips=new_ips,
        nodeping_ips=get_nodeping_ips(),
        toggles=get_exclusion_toggles(),
    )
    if not write_file(NS_EXCLUSIONS_CONF, content):
        return StepResult(success=False, error=f"Failed to write {NS_EXCLUSIONS_CONF}")

    return StepResult(message=f"Added {ip} to allowlist")


def remove_allowlisted_ip(ip: str) -> StepResult:
    """Remove an IP address from the allowlist and regenerate exclusions config."""
    ip = normalize_ipmatch_entry(ip)
    current_ips = get_allowlisted_ips()
    if ip not in current_ips:
        return StepResult(skipped=True, message=f"{ip} not in allowlist")

    new_ips = [existing for existing in current_ips if existing != ip]

    if file_exists(NS_EXCLUSIONS_CONF):
        backup_file(NS_EXCLUSIONS_CONF)

    content = render_exclusions(
        admin_ips=new_ips,
        nodeping_ips=get_nodeping_ips(),
        toggles=get_exclusion_toggles(),
    )
    if not write_file(NS_EXCLUSIONS_CONF, content):
        return StepResult(success=False, error=f"Failed to write {NS_EXCLUSIONS_CONF}")

    return StepResult(message=f"Removed {ip} from allowlist")


class ModSecurityInstaller:
    """Idempotent ModSecurity v2 + OWASP CRS v4 installer for Apache2."""

    def __init__(
        self,
        mode: str = "DetectionOnly",
        install_evasive: bool = True,
        dry_run: bool = False,
    ) -> None:
        self.mode = mode
        self.install_evasive = install_evasive
        self.dry_run = dry_run
        self._preflight: PreflightResult | None = None

    # ------------------------------------------------------------------
    # Preflight
    # ------------------------------------------------------------------

    def preflight(self) -> PreflightResult:
        """Run all preflight checks and return results."""
        pf = PreflightResult()

        pf.is_root = is_root()
        if not pf.is_root:
            pf.errors.append("Must run as root (use --sudo flag or run with sudo)")

        pf.apache_installed = package_installed("apache2")
        if not pf.apache_installed:
            pf.errors.append("Apache2 is not installed")

        _, _, rc = run_cmd(["systemctl", "is-active", "--quiet", "apache2"])
        pf.apache_running = rc == 0
        pf.modsec_installed = package_installed(MODSEC_PACKAGE)
        pf.modsec_enabled = file_exists(SECURITY2_LOAD)
        pf.modsec_mode = detect_modsec_mode([MODSEC_CONF, MODSEC_CONF_RECOMMENDED])
        pf.crs_installed, pf.crs_version, pf.crs_path = self._detect_crs()
        pf.security2_has_wildcard, pf.security2_has_crs_load = parse_security2_conf(SECURITY2_CONF)
        if pf.security2_has_wildcard:
            pf.warnings.append(
                "Existing security2.conf uses wildcard "
                "IncludeOptional /etc/modsecurity/*.conf \u2014 "
                "will not overwrite (new configs will be picked "
                "up automatically)"
            )

        self._preflight = pf
        return pf

    def _detect_crs(self) -> tuple[bool, str | None, str | None]:
        """Detect CRS installation and version. SSH-aware."""
        for search_path in CRS_SEARCH_PATHS:
            if not is_directory(search_path):
                continue
            version_file = f"{search_path}/VERSION"
            version_content = read_file(version_file)
            if version_content:
                return True, version_content.strip(), search_path
            if is_directory(f"{search_path}/rules"):
                return True, None, search_path

        if package_installed(CRS_APT_PACKAGE):
            stdout, _, rc = run_cmd(["dpkg-query", "-W", "-f=${Version}", CRS_APT_PACKAGE])
            ver = stdout.strip() if rc == 0 else None
            return True, ver, "/usr/share/modsecurity-crs"

        return False, None, None

    # ------------------------------------------------------------------
    # Installation steps
    # ------------------------------------------------------------------

    def install_packages(self) -> StepResult:
        """Install ModSecurity and optionally mod_evasive."""
        packages = []
        if not package_installed(MODSEC_PACKAGE):
            packages.append(MODSEC_PACKAGE)
        if self.install_evasive and not package_installed(EVASIVE_PACKAGE):
            packages.append(EVASIVE_PACKAGE)

        if not packages:
            return StepResult(skipped=True, message="All packages already installed")
        if self.dry_run:
            return StepResult(message=f"Would install: {', '.join(packages)}")

        _, stderr, rc = run_cmd(["apt-get", "update", "-qq"], timeout=60)
        if rc != 0:
            return StepResult(success=False, error=f"apt-get update failed: {stderr}")
        _, stderr, rc = run_cmd(["apt-get", "install", "-y", "-qq"] + packages, timeout=120)
        if rc != 0:
            return StepResult(
                success=False,
                error=f"apt-get install failed: {stderr}",
            )
        return StepResult(message=f"Installed: {', '.join(packages)}")

    def enable_modules(self) -> StepResult:
        """Enable Apache security2 module and conditionally enable evasive."""
        if file_exists(SECURITY2_LOAD):
            return StepResult(skipped=True, message="security2 module already enabled")
        if self.dry_run:
            return StepResult(message="Would run: a2enmod security2")

        _, stderr, rc = run_cmd(["a2enmod", "security2"])
        if rc != 0:
            return StepResult(
                success=False,
                error=f"a2enmod security2 failed: {stderr}",
            )
        if self.install_evasive:
            run_cmd(["a2enmod", "evasive"])
        return StepResult(message="Enabled security2 module")

    def setup_config(self) -> StepResult:
        """Create or update the main ModSecurity configuration."""
        if self.dry_run:
            msg = f"Would configure {MODSEC_CONF} with SecRuleEngine {self.mode}"
            return StepResult(message=msg)

        Path(MODSEC_DIR).mkdir(parents=True, exist_ok=True)
        if file_exists(MODSEC_CONF):
            backup_file(MODSEC_CONF)
        elif file_exists(MODSEC_CONF_RECOMMENDED):
            shutil.copy2(MODSEC_CONF_RECOMMENDED, MODSEC_CONF)

        content = render(
            MODSEC_CONF_TEMPLATE,
            mode=self.mode,
            tmp_dir=MODSEC_TMP_DIR,
            data_dir=MODSEC_DATA_DIR,
            audit_log=MODSEC_AUDIT_LOG,
        )
        if not write_file(MODSEC_CONF, content):
            return StepResult(success=False, error=f"Failed to write {MODSEC_CONF}")
        Path(MODSEC_TMP_DIR).mkdir(parents=True, exist_ok=True)
        Path(MODSEC_DATA_DIR).mkdir(parents=True, exist_ok=True)
        msg = f"Configured ModSecurity (SecRuleEngine {self.mode})"
        return StepResult(message=msg)

    def setup_evasive_config(
        self,
        profile: str = EVASIVE_DEFAULT_PROFILE,
        cluster: ClusterPeers | None = None,
    ) -> StepResult:
        """Write the mod_evasive configuration with the given threshold profile.

        Profiles:
          - "standard" (default): high thresholds, only catches extreme floods.
          - "strict": tighter thresholds tuned for NetSapiens traffic patterns.

        ``cluster`` None uses the cached cluster peers.  DOSWhitelist is
        IPv4-only, so IPv6 peers are left out (and counted in a comment).
        """
        if not self.install_evasive:
            return StepResult(skipped=True, message="Evasive installation skipped")
        if profile not in EVASIVE_PROFILES:
            return StepResult(success=False, error=f"Unknown evasive profile: {profile}")
        if self.dry_run:
            return StepResult(message=f"Would write {EVASIVE_CONF} (profile: {profile})")

        if file_exists(EVASIVE_CONF):
            backup_file(EVASIVE_CONF)

        if cluster is None:
            cluster = cached_cluster_peers(read=read_file)
        thresholds = EVASIVE_PROFILES[profile]
        content = render(
            EVASIVE_CONF_TEMPLATE,
            **cluster.template_context(),
            profile=profile,
            log_dir=EVASIVE_LOG_DIR,
            log_file=EVASIVE_LOG_FILE,
            **thresholds,
        )
        if not write_file(EVASIVE_CONF, content):
            return StepResult(success=False, error=f"Failed to write {EVASIVE_CONF}")

        Path(EVASIVE_LOG_DIR).mkdir(parents=True, exist_ok=True)
        msg = f"Configured mod_evasive ({EVASIVE_CONF}, profile: {profile})"
        if cluster.peers:
            msg += f", {len(cluster.ipv4)} cluster peer IP(s) whitelisted"
            if cluster.ipv6:
                msg += f" ({len(cluster.ipv6)} IPv6 left out: DOSWhitelist is IPv4-only)"
        return StepResult(message=msg)

    def refresh_evasive_cluster(self, cluster: ClusterPeers) -> StepResult:
        """Re-render a deployed evasive.conf with new cluster peers, same profile."""
        content = read_file(EVASIVE_CONF)
        if content is None:
            return StepResult(skipped=True, message=f"{EVASIVE_CONF} not deployed")
        profile = parse_evasive_profile(content) or EVASIVE_DEFAULT_PROFILE
        if profile not in EVASIVE_PROFILES:
            profile = EVASIVE_DEFAULT_PROFILE
        return self.setup_evasive_config(profile=profile, cluster=cluster)

    def set_evasive_state(self, enable: bool) -> StepResult:
        """Enable or disable the mod_evasive Apache module.

        mod_evasive has no detection-only mode, so we toggle the module
        itself: enabled when WAF is in blocking mode, disabled when in
        DetectionOnly mode.
        """
        if not package_installed(EVASIVE_PACKAGE):
            return StepResult(
                skipped=True,
                message="mod_evasive not installed, skipping",
            )

        currently_enabled = file_exists(EVASIVE_LOAD)
        if enable and currently_enabled:
            return StepResult(skipped=True, message="mod_evasive already enabled")
        if not enable and not currently_enabled:
            return StepResult(skipped=True, message="mod_evasive already disabled")

        if self.dry_run:
            action = "enable" if enable else "disable"
            return StepResult(message=f"Would {action} mod_evasive")

        cmd = ["a2enmod", "evasive"] if enable else ["a2dismod", "evasive"]
        _, stderr, rc = run_cmd(cmd)
        if rc != 0:
            action = "enable" if enable else "disable"
            return StepResult(
                success=False,
                error=f"Failed to {action} mod_evasive: {stderr}",
            )

        action = "Enabled" if enable else "Disabled"
        return StepResult(message=f"{action} mod_evasive")

    def install_crs_v4(self) -> StepResult:
        """Install OWASP CRS v4, downloading from GitHub if apt has v3."""
        pf = self._preflight or self.preflight()

        has_v4 = pf.crs_installed and pf.crs_version and pf.crs_version.startswith("4")
        if has_v4:
            # Still update crs-setup.conf with latest template values
            self._update_crs_setup(pf.crs_path)
            disabled = self._disable_incompatible_crs_rules(pf.crs_path)
            msg = f"CRS v{pf.crs_version} at {pf.crs_path} (crs-setup.conf updated)"
            if disabled:
                msg += f"; disabled {len(disabled)} rule(s) incompatible with ModSec < 2.9.6"
            return StepResult(skipped=True, message=msg)

        if self.dry_run:
            return self._crs_dry_run_message(pf)

        if not pf.crs_installed:
            result = self._try_crs_from_apt()
            if result:
                return result

        return self._download_crs_from_github()

    def _crs_dry_run_message(self, pf):
        if pf.crs_installed:
            msg = f"Would upgrade CRS from v{pf.crs_version} to v{PINNED_CRS_VERSION}"
            return StepResult(message=msg)
        msg = f"Would download CRS v{PINNED_CRS_VERSION} from GitHub"
        return StepResult(message=msg)

    def _try_crs_from_apt(self) -> StepResult | None:
        """Try installing CRS from apt. Returns result if v4, else None."""
        _, _, rc = run_cmd(
            ["apt-get", "install", "-y", "-qq", CRS_APT_PACKAGE],
            timeout=60,
        )
        if rc != 0:
            return None
        installed, version, path = self._detect_crs()
        if installed and version and version.startswith("4"):
            msg = f"Installed CRS v{version} from apt at {path}"
            return StepResult(message=msg)
        return None

    def _update_crs_setup(self, crs_path: str) -> bool:
        """Write crs-setup.conf from template. Returns True on success."""
        setup_content = render(
            CRS_SETUP_OVERRIDES_TEMPLATE,
            paranoia_level=1,
            inbound_threshold=5,
            outbound_threshold=4,
        )
        setup_path = f"{crs_path}/crs-setup.conf"
        return write_file(setup_path, setup_content)

    def _disable_incompatible_crs_rules(self, crs_path: str) -> list[str]:
        """Disable CRS rules incompatible with the installed ModSecurity version.

        On ModSecurity < 2.9.6, renames rule files in CRS_RULES_REQUIRE_296
        from .conf to .conf.disabled to prevent Apache startup failures.

        Returns list of disabled filenames (empty if >= 2.9.6 or nothing to do).
        """
        ver = detect_modsec_version()
        if version_gte(ver, "2.9.6"):
            return []

        disabled: list[str] = []
        rules_dir = Path(f"{crs_path}/rules")
        for rule_file in CRS_RULES_REQUIRE_296:
            src = rules_dir / rule_file
            dst = rules_dir / (rule_file + ".disabled")
            if src.exists() and not dst.exists():
                src.rename(dst)
                disabled.append(rule_file)
        return disabled

    def _download_crs_from_github(self) -> StepResult:
        """Download and extract CRS v4 from GitHub releases."""
        tarball = f"/tmp/crs-v{PINNED_CRS_VERSION}.tar.gz"

        _, stderr, rc = run_cmd(
            ["curl", "-sL", "-o", tarball, CRS_GITHUB_DOWNLOAD],
            timeout=60,
        )
        if rc != 0:
            return StepResult(success=False, error=f"Failed to download CRS: {stderr}")

        Path(CRS_INSTALL_DIR).mkdir(parents=True, exist_ok=True)
        _, stderr, rc = run_cmd(
            [
                "tar",
                "xzf",
                tarball,
                "--strip-components=1",
                "-C",
                CRS_INSTALL_DIR,
            ]
        )
        if rc != 0:
            return StepResult(success=False, error=f"Failed to extract CRS: {stderr}")
        Path(tarball).unlink(missing_ok=True)

        if not self._update_crs_setup(CRS_INSTALL_DIR):
            return StepResult(
                success=False, error=f"Failed to write {CRS_INSTALL_DIR}/crs-setup.conf"
            )

        # Refresh preflight cache so write_security2_conf() uses the new CRS path
        self._preflight = None

        disabled = self._disable_incompatible_crs_rules(CRS_INSTALL_DIR)
        msg = f"Installed CRS v{PINNED_CRS_VERSION} to {CRS_INSTALL_DIR}"
        if disabled:
            msg += f"; disabled {len(disabled)} rule(s) incompatible with ModSec < 2.9.6"
        return StepResult(message=msg)

    def install_exclusions(
        self,
        admin_ips: list[str] | None = None,
        nodeping_ips: list[str] | None = None,
        toggles: dict[str, bool] | None = None,
        cluster: ClusterPeers | None = None,
    ) -> StepResult:
        """Write NetSapiens-specific ModSecurity exclusions.

        The template is re-rendered in full on every write, and the deployed
        conf is the only store for allowlisted IPs.  ``None`` therefore means
        "keep whatever is already deployed" — otherwise a caller that knows
        about one list (e.g. update-exclusions, which fetches NodePing IPs but
        has no notion of the admin allowlist) would silently drop the other.
        Pass an empty list to clear a section deliberately.  ``toggles`` holds
        only the optional features to change (e.g. ``{"token_audit": True}``);
        every toggle not named keeps its deployed setting.  ``cluster`` None
        uses the cached cluster peers.
        """
        if self.dry_run:
            return StepResult(message=f"Would write {NS_EXCLUSIONS_CONF}")

        carried_admin = admin_ips is None
        if admin_ips is None:
            admin_ips = get_allowlisted_ips()
        if nodeping_ips is None:
            nodeping_ips = get_nodeping_ips()
        toggles = {**get_exclusion_toggles(), **(toggles or {})}

        # Guard against a silent wipe: if we are carrying the admin allowlist
        # forward (caller did not pass one explicitly) but the deployed file
        # clearly holds more admin rules than we could parse back, the file is
        # malformed or from an older format. Abort rather than regenerate over
        # a populated allowlist with zero — an empty admin list must be an
        # explicit choice, never the result of a parse failure.
        deployed = read_file(NS_EXCLUSIONS_CONF) or ""
        deployed_admin_rules = len(re.findall(r'"id:10001\d+', deployed))
        if carried_admin and deployed_admin_rules > len(admin_ips):
            return StepResult(
                success=False,
                error=(
                    f"Refusing to regenerate {NS_EXCLUSIONS_CONF}: the deployed file has "
                    f"{deployed_admin_rules} admin allowlist rule(s) but only "
                    f"{len(admin_ips)} could be read back. The file may be malformed or "
                    "in an older format — restore it or re-add the IPs before retrying "
                    "so the allowlist is not lost."
                ),
            )

        if file_exists(NS_EXCLUSIONS_CONF):
            backup_file(NS_EXCLUSIONS_CONF)

        content = render_exclusions(admin_ips, nodeping_ips, toggles, cluster)
        if not write_file(NS_EXCLUSIONS_CONF, content):
            return StepResult(
                success=False,
                error=f"Failed to write {NS_EXCLUSIONS_CONF}",
            )
        msg = f"Wrote NS exclusions to {NS_EXCLUSIONS_CONF}"
        return StepResult(message=msg)

    def write_security2_conf(self) -> StepResult:
        """Write Apache Include directives for ModSecurity + CRS."""
        pf = self._preflight or self.preflight()
        crs_path = pf.crs_path or CRS_INSTALL_DIR

        if pf.security2_has_wildcard:
            return self._handle_wildcard_security2(crs_path)
        return self._write_new_security2(crs_path)

    def _handle_wildcard_security2(self, crs_path: str) -> StepResult:
        sec2_content = read_file(SECURITY2_CONF) or ""
        if crs_path in sec2_content:
            msg = f"security2.conf already includes CRS from {crs_path}"
            return StepResult(skipped=True, message=msg)
        if self.dry_run:
            msg = f"Would append CRS includes for {crs_path} to {SECURITY2_CONF}"
            return StepResult(message=msg)
        if not append_crs_to_security2(crs_path):
            return StepResult(success=False, error=f"Failed to update {SECURITY2_CONF}")
        msg = f"Appended CRS includes to existing {SECURITY2_CONF}"
        return StepResult(message=msg)

    def _write_new_security2(self, crs_path: str) -> StepResult:
        if self.dry_run:
            return StepResult(message=f"Would write {SECURITY2_CONF}")
        if not write_security2_full(crs_path, SECURITY2_CONF_TEMPLATE):
            return StepResult(success=False, error=f"Failed to write {SECURITY2_CONF}")
        return StepResult(message=f"Wrote {SECURITY2_CONF}")

    def validate_config(self, snapshot: dict[str, str | None] | None = None) -> StepResult:
        """Run apache2ctl configtest. Rolls back on failure.

        With ``snapshot`` (from ``snapshot_files``), rolls back to exactly
        those pre-write contents, including files outside the default rollback
        list (the restrict config) and files that did not exist before.
        Without it, restores the .bak.nssec files.
        """
        if self.dry_run:
            return StepResult(message="Would run: apache2ctl configtest")
        stdout, stderr, rc = run_cmd(["apache2ctl", "configtest"])
        if rc != 0:
            if snapshot is not None:
                restore_snapshot(snapshot)
            else:
                self._rollback()
            err = f"Apache config test failed (rolled back): {stderr or stdout}"
            return StepResult(success=False, error=err)
        return StepResult(message="Apache config test passed")

    def reload_apache(self) -> StepResult:
        """Reload Apache to apply changes."""
        if self.dry_run:
            return StepResult(message="Would run: systemctl reload apache2")
        _, stderr, rc = run_cmd(["systemctl", "reload", "apache2"])
        if rc != 0:
            return StepResult(success=False, error=f"Apache reload failed: {stderr}")
        return StepResult(message="Apache reloaded")

    def _rollback(self) -> None:
        """Restore .bak.nssec backups for all managed config files."""
        for path in [MODSEC_CONF, SECURITY2_CONF, NS_EXCLUSIONS_CONF, EVASIVE_CONF]:
            bak = path + BACKUP_SUFFIX
            if file_exists(bak):
                shutil.copy2(bak, path)

    def verify(self) -> list[StepResult]:
        """Verify the installation matches what audit checks expect."""
        results: list[StepResult] = []

        if package_installed(MODSEC_PACKAGE):
            results.append(StepResult(message="ModSecurity package installed"))
        else:
            results.append(StepResult(success=False, error="ModSecurity package NOT installed"))

        if file_exists(SECURITY2_LOAD):
            results.append(StepResult(message="security2 module enabled"))
        else:
            results.append(StepResult(success=False, error="security2 module NOT enabled"))

        content = read_file(MODSEC_CONF)
        if content and "SecRuleEngine" in content:
            results.append(StepResult(message=f"ModSecurity configured ({MODSEC_CONF})"))
        else:
            results.append(
                StepResult(success=False, error="ModSecurity config missing or incomplete")
            )

        installed, version, path = self._detect_crs()
        if installed:
            v = f" v{version}" if version else ""
            results.append(StepResult(message=f"CRS{v} installed at {path}"))
        else:
            results.append(StepResult(success=False, error="CRS not found"))

        return results

    # ------------------------------------------------------------------
    # Full install orchestration
    # ------------------------------------------------------------------

    def run(
        self,
        admin_ips: list[str] | None = None,
        nodeping_ips: list[str] | None = None,
        toggles: dict[str, bool] | None = None,
        cluster: ClusterPeers | None = None,
    ) -> InstallResult:
        """Run the full installation sequence."""
        result = InstallResult(mode=self.mode)
        pf = self.preflight()

        if not pf.can_proceed:
            result.errors = pf.errors
            return result

        if pf.apache_installed and not pf.apache_running:
            result.warnings.append("Apache2 is installed but not running")

        steps = [
            ("Install packages", self.install_packages),
            ("Enable Apache modules", self.enable_modules),
            ("Configure ModSecurity", self.setup_config),
            (
                "Configure mod_evasive",
                lambda: self.setup_evasive_config(cluster=cluster),
            ),
            ("Enable mod_evasive", lambda: self.set_evasive_state(True)),
            ("Install OWASP CRS v4", self.install_crs_v4),
            (
                "Install NS exclusions",
                lambda: self.install_exclusions(admin_ips, nodeping_ips, toggles, cluster),
            ),
            ("Update security2.conf", self.write_security2_conf),
            ("Validate Apache config", self.validate_config),
        ]

        for name, step_fn in steps:
            step = step_fn()
            if step.skipped:
                result.steps_skipped.append(f"{name}: {step.message}")
            elif step.success:
                result.steps_completed.append(f"{name}: {step.message}")
            else:
                result.errors.append(f"{name}: {step.error}")
                return result

        result.success = True
        return result

    # ------------------------------------------------------------------
    # Mode switching
    # ------------------------------------------------------------------

    def set_mode(self, mode: str) -> StepResult:
        """Change SecRuleEngine mode.

        Only changes the ModSecurity engine mode. mod_evasive is managed
        independently via 'nssec waf evasive enable/disable'.
        """
        content = read_file(MODSEC_CONF)
        if not content:
            return StepResult(success=False, error=f"{MODSEC_CONF} not found")

        backup_file(MODSEC_CONF)
        new_lines = []
        found = False
        for line in content.splitlines():
            if line.strip().startswith("SecRuleEngine"):
                new_lines.append(f"SecRuleEngine {mode}")
                found = True
            else:
                new_lines.append(line)

        if not found:
            return StepResult(
                success=False,
                error="SecRuleEngine directive not found in config",
            )

        if not write_file(MODSEC_CONF, "\n".join(new_lines) + "\n"):
            return StepResult(success=False, error=f"Failed to write {MODSEC_CONF}")

        stdout, stderr, rc = run_cmd(["apache2ctl", "configtest"])
        if rc != 0:
            self._rollback()
            err = f"Config test failed after mode change (rolled back): {stderr or stdout}"
            return StepResult(success=False, error=err)

        _, stderr, rc = run_cmd(["systemctl", "reload", "apache2"])
        if rc != 0:
            return StepResult(success=False, error=f"Apache reload failed: {stderr}")

        msg = f"SecRuleEngine set to {mode} and Apache reloaded"
        return StepResult(message=msg)

    def _reenable_crs_rules(self, crs_path: str) -> list[str]:
        """Re-enable CRS rules previously disabled for ModSec < 2.9.6.

        Renames .conf.disabled files back to .conf for rules in
        CRS_RULES_REQUIRE_296.

        Returns list of re-enabled filenames.
        """
        reenabled: list[str] = []
        rules_dir = Path(f"{crs_path}/rules")
        for rule_file in CRS_RULES_REQUIRE_296:
            disabled = rules_dir / (rule_file + ".disabled")
            target = rules_dir / rule_file
            if disabled.exists() and not target.exists():
                disabled.rename(target)
                reenabled.append(rule_file)
        return reenabled
