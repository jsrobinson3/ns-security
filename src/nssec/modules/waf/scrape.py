"""API scrape protection for the NetSapiens API (/ns-api/).

Renders a standalone ModSecurity rules file (``SCRAPE_CONF``) that tracks each
client IP across requests and flags:

- known scraper user agents,
- a per-IP request budget over a fixed window, and
- cross-domain enumeration: one IP reading many distinct tenant domains.

The deployed file is the only store for the operator's settings. They are
embedded as a JSON header comment and read back on the next ``enable``, so a
single flag change (e.g. ``--mode block``) keeps everything else.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

from nssec.modules.waf.config import (
    BACKUP_SUFFIX,
    NS_EXCLUSIONS_CONF,
    SCRAPE_BAD_USER_AGENTS,
    SCRAPE_CONF,
    SCRAPE_CONF_TEMPLATE,
    SCRAPE_DEFAULT_MODE,
    SCRAPE_DEFAULT_PROFILE,
    SCRAPE_MODES,
    SCRAPE_PROFILES,
    SCRAPE_TEMPLATE_HASH,
    SECURITY2_CONF,
)
from nssec.modules.waf.types import StepResult
from nssec.modules.waf.utils import (
    backup_file,
    file_exists,
    read_file,
    remove_file,
    render,
    run_cmd,
    write_file,
)

LOOPBACK_IPS = ["127.0.0.1", "::1"]

_SETTINGS_PREFIX = "# nssec-scrape-settings:"
_HASH_PREFIX = "# nssec-scrape-hash:"
_WILDCARD_INCLUDE = "/etc/modsecurity/*.conf"

# @pm takes a space-separated phrase list inside a double-quoted operator
# argument, so tokens must not contain whitespace, quotes or backslashes.
_USER_AGENT_TOKEN = re.compile(r"^[A-Za-z0-9._/;:()+-]{2,64}$")


@dataclass
class ScrapeSettings:
    """Operator settings, persisted in the deployed conf's header."""

    mode: str = SCRAPE_DEFAULT_MODE
    profile: str = SCRAPE_DEFAULT_PROFILE
    max_requests: int | None = None
    max_domains: int | None = None
    exempt_admin_ips: bool = True
    exempt_ips: list[str] = field(default_factory=list)
    bad_user_agents: list[str] = field(default_factory=lambda: list(SCRAPE_BAD_USER_AGENTS))

    def thresholds(self) -> dict[str, int]:
        """Profile thresholds with any per-node overrides applied."""
        values = dict(SCRAPE_PROFILES[self.profile])
        if self.max_requests is not None:
            values["max_requests"] = self.max_requests
        if self.max_domains is not None:
            values["max_domains"] = self.max_domains
        return values


@dataclass
class ScrapeStatus:
    """Deployment state of the scrape protection rules."""

    deployed: bool = False
    included: bool = False
    current: bool = False
    settings: ScrapeSettings | None = None


def _is_valid_network(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return "%" not in value


def validate_settings(settings: ScrapeSettings) -> list[str]:
    """Return a list of problems with *settings* (empty when valid)."""
    errors = []
    if settings.mode not in SCRAPE_MODES:
        errors.append(f"Unknown mode '{settings.mode}' (expected: {', '.join(SCRAPE_MODES)})")
    if settings.profile not in SCRAPE_PROFILES:
        errors.append(
            f"Unknown profile '{settings.profile}' (expected: {', '.join(SCRAPE_PROFILES)})"
        )
    for name in ("max_requests", "max_domains"):
        value = getattr(settings, name)
        if value is not None and (not isinstance(value, int) or value < 1):
            errors.append(f"{name} must be a positive integer, got {value!r}")
    for ip in settings.exempt_ips:
        if not _is_valid_network(ip):
            errors.append(f"Invalid exempt IP/CIDR: {ip}")
    for ua in settings.bad_user_agents:
        if not _USER_AGENT_TOKEN.match(ua):
            errors.append(
                f"Invalid user-agent token '{ua}' (2-64 chars, no spaces, quotes or backslashes)"
            )
    return errors


def get_local_ips() -> list[str]:
    """This node's own addresses from ``hostname -I``. SSH-aware.

    Link-local and zone-scoped addresses are dropped: they never originate
    API traffic and ``fe80::1%eth0`` is not valid ``@ipMatch`` syntax.
    """
    stdout, _, rc = run_cmd(["hostname", "-I"])
    if rc != 0:
        return []
    ips = []
    for token in stdout.split():
        try:
            addr = ipaddress.ip_address(token)
        except ValueError:
            continue
        if addr.is_link_local or "%" in token:
            continue
        ips.append(token)
    return ips


def resolve_exempt_ips(
    settings: ScrapeSettings,
    admin_ips: list[str],
    local_ips: list[str],
) -> list[str]:
    """Decide which source addresses bypass scrape protection entirely.

    Args:
        settings: Operator settings — ``exempt_ips`` (explicit extras) and the
            ``exempt_admin_ips`` flag.
        admin_ips: The WAF admin allowlist (``nssec waf allowlist``).
        local_ips: This node's own addresses (:func:`get_local_ips`).

    Returns:
        Deduplicated ``@ipMatch`` entries. Must always contain LOOPBACK_IPS,
        and every entry must be a valid IP or CIDR: the list is rendered into a
        single operator, and one bad token fails ``apache2ctl configtest``.
        (``write_scrape_conf`` re-validates as a safety net.)
    """
    # TODO: exemption policy — see the conversation notes on the trade-offs.
    raise NotImplementedError("resolve_exempt_ips: exemption policy not implemented yet")


def render_scrape_conf(settings: ScrapeSettings, exempt_ips: list[str]) -> str:
    """Render the scrape protection rules file."""
    return render(
        SCRAPE_CONF_TEMPLATE,
        mode=settings.mode,
        profile=settings.profile,
        exempt_ips=exempt_ips,
        bad_user_agents=settings.bad_user_agents,
        template_hash=SCRAPE_TEMPLATE_HASH,
        settings_json=json.dumps(asdict(settings), sort_keys=True),
        **settings.thresholds(),
    )


def parse_scrape_settings(content: str) -> ScrapeSettings | None:
    """Read settings back from a deployed conf. None if absent or unreadable."""
    for line in content.splitlines():
        if not line.startswith(_SETTINGS_PREFIX):
            continue
        try:
            raw = json.loads(line[len(_SETTINGS_PREFIX) :])
        except ValueError:
            return None
        if not isinstance(raw, dict):
            return None
        known = {f.name for f in fields(ScrapeSettings)}
        values = {k: v for k, v in raw.items() if k in known}
        for name in ("exempt_ips", "bad_user_agents"):
            items = values.get(name, [])
            if not isinstance(items, list) or not all(isinstance(v, str) for v in items):
                return None
        return ScrapeSettings(**values)
    return None


def parse_scrape_hash(content: str) -> str | None:
    """Template hash embedded in a deployed conf."""
    for line in content.splitlines():
        if line.startswith(_HASH_PREFIX):
            return line[len(_HASH_PREFIX) :].strip()
    return None


def is_deployed() -> bool:
    return file_exists(SCRAPE_CONF)


def load_deployed_settings() -> ScrapeSettings | None:
    content = read_file(SCRAPE_CONF)
    return parse_scrape_settings(content) if content else None


def security2_includes_scrape(content: str) -> bool:
    """True if security2.conf loads the scrape conf (explicitly or via wildcard)."""
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if SCRAPE_CONF in stripped or _WILDCARD_INCLUDE in stripped:
            return True
    return False


def ensure_security2_include(dry_run: bool = False) -> StepResult:
    """Add an IncludeOptional for the scrape conf right after the exclusions include.

    The exemption rule is a runtime ctl directive, so it only needs to precede
    the scrape rules (same file). Placing the include after the exclusions keeps
    all nssec rules together and matches the wildcard layout's alphabetical
    order (netsapiens-exclusions < netsapiens-scrape-protection).
    """
    content = read_file(SECURITY2_CONF)
    if not content:
        return StepResult(
            success=False, error=f"{SECURITY2_CONF} not found; run 'nssec waf init' first"
        )
    if security2_includes_scrape(content):
        return StepResult(skipped=True, message=f"{SECURITY2_CONF} already loads {SCRAPE_CONF}")

    lines = content.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith("#") and NS_EXCLUSIONS_CONF in stripped:
            indent = line[: len(line) - len(line.lstrip())]
            lines.insert(i + 1, f"{indent}IncludeOptional {SCRAPE_CONF}")
            break
    else:
        return StepResult(
            success=False,
            error=(
                f"{SECURITY2_CONF} does not include {NS_EXCLUSIONS_CONF}; "
                "run 'nssec waf update-exclusions' first"
            ),
        )

    if dry_run:
        return StepResult(message=f"Would add {SCRAPE_CONF} include to {SECURITY2_CONF}")
    backup_file(SECURITY2_CONF)
    if not write_file(SECURITY2_CONF, "\n".join(lines) + "\n"):
        return StepResult(success=False, error=f"Failed to write {SECURITY2_CONF}")
    return StepResult(message=f"Added {SCRAPE_CONF} include to {SECURITY2_CONF}")


def write_scrape_conf(
    settings: ScrapeSettings,
    exempt_ips: list[str],
    dry_run: bool = False,
) -> StepResult:
    """Validate and write the scrape protection rules file."""
    errors = validate_settings(settings)
    errors += [f"Invalid exempt IP/CIDR: {ip}" for ip in exempt_ips if not _is_valid_network(ip)]
    if errors:
        return StepResult(success=False, error="; ".join(errors))

    summary = f"mode {settings.mode}, profile {settings.profile}, {len(exempt_ips)} exempt IP(s)"
    if dry_run:
        return StepResult(message=f"Would write {SCRAPE_CONF} ({summary})")

    if file_exists(SCRAPE_CONF):
        backup_file(SCRAPE_CONF)
    if not write_file(SCRAPE_CONF, render_scrape_conf(settings, exempt_ips)):
        return StepResult(success=False, error=f"Failed to write {SCRAPE_CONF}")
    return StepResult(message=f"Wrote {SCRAPE_CONF} ({summary})")


def remove_scrape_conf(dry_run: bool = False) -> StepResult:
    """Remove the rules file. The security2.conf IncludeOptional may stay."""
    if not file_exists(SCRAPE_CONF):
        return StepResult(skipped=True, message="Scrape protection is not deployed")
    if dry_run:
        return StepResult(message=f"Would remove {SCRAPE_CONF}")
    backup_file(SCRAPE_CONF)
    if not remove_file(SCRAPE_CONF):
        return StepResult(success=False, error=f"Failed to remove {SCRAPE_CONF}")
    return StepResult(message=f"Removed {SCRAPE_CONF} (backup: {SCRAPE_CONF}{BACKUP_SUFFIX})")


def rollback_scrape(conf_existed: bool, security2_changed: bool) -> None:
    """Undo a failed scrape-protection change.

    If the conf existed before this run, restore the snapshot taken just before
    it was rewritten or removed. If it did not, delete it: any backup on disk
    is from an earlier run and must not be resurrected.
    """
    if conf_existed:
        backup = Path(SCRAPE_CONF + BACKUP_SUFFIX)
        if backup.exists():
            shutil.copy2(backup, SCRAPE_CONF)
    else:
        remove_file(SCRAPE_CONF)

    if security2_changed:
        sec2_backup = Path(SECURITY2_CONF + BACKUP_SUFFIX)
        if sec2_backup.exists():
            shutil.copy2(sec2_backup, SECURITY2_CONF)


def validate_apache_config(conf_existed: bool, security2_changed: bool) -> StepResult:
    """Run apache2ctl configtest, rolling back this run's changes on failure."""
    stdout, stderr, rc = run_cmd(["apache2ctl", "configtest"])
    if rc != 0:
        rollback_scrape(conf_existed=conf_existed, security2_changed=security2_changed)
        return StepResult(
            success=False, error=f"Apache config test failed (rolled back): {stderr or stdout}"
        )
    return StepResult(message="Apache config test passed")


def get_scrape_status() -> ScrapeStatus:
    """Collect deployment state for 'waf status' and 'scrape-protection status'."""
    status = ScrapeStatus()
    status.included = security2_includes_scrape(read_file(SECURITY2_CONF) or "")
    content = read_file(SCRAPE_CONF)
    if content:
        status.deployed = True
        status.current = parse_scrape_hash(content) == SCRAPE_TEMPLATE_HASH
        status.settings = parse_scrape_settings(content)
    return status
