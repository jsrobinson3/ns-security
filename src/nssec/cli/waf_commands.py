"""WAF/ModSecurity CLI commands for nssec."""

import click
from rich.table import Table

from nssec.cli import console, sudo_hint


@click.group()
def waf():
    """WAF/ModSecurity management commands."""
    pass


def _display_install_plan(pf, mode, skip_evasive):
    """Display the WAF installation plan table."""
    table = Table(title="Installation Plan", show_header=True)
    table.add_column("Component", style="cyan")
    table.add_column("Current State", style="yellow")
    table.add_column("Action")

    modsec_state = "installed" if pf.modsec_installed else "not installed"
    modsec_action = "skip" if pf.modsec_installed else "install"
    table.add_row("ModSecurity v2", modsec_state, modsec_action)

    module_state = "enabled" if pf.modsec_enabled else "not enabled"
    module_action = "skip" if pf.modsec_enabled else "enable"
    table.add_row("Apache security2 module", module_state, module_action)

    crs_state = (
        f"v{pf.crs_version}"
        if pf.crs_version
        else ("installed" if pf.crs_installed else "not installed")
    )
    if pf.crs_installed and pf.crs_version and pf.crs_version.startswith("4"):
        crs_action = "skip (v4 present)"
    elif pf.crs_installed:
        crs_action = "upgrade to v4"
    else:
        crs_action = "install v4"
    table.add_row("OWASP CRS", crs_state, crs_action)

    mode_state = pf.modsec_mode or "not configured"
    table.add_row("SecRuleEngine mode", mode_state, f"set to {mode}")
    table.add_row("NS exclusions", "", "install")

    sec2_state = "wildcard include" if pf.security2_has_wildcard else "standard"
    sec2_action = "keep (wildcard picks up new configs)" if pf.security2_has_wildcard else "write"
    table.add_row("security2.conf", sec2_state, sec2_action)

    if not skip_evasive:
        table.add_row("mod_evasive", "", "install + enable")

    console.print(table)


def _print_install_results(result):
    """Print installation step results."""
    for step in result.steps_completed:
        console.print(f"  [green]Done:[/green] {step}")
    for step in result.steps_skipped:
        console.print(f"  [dim]Skipped:[/dim] {step}")
    for warn in result.warnings:
        console.print(f"  [yellow]Warning:[/yellow] {warn}")
    for err in result.errors:
        console.print(f"  [red]Error:[/red] {err}")


def _require_root_and_modsec(pf, command_hint):
    """Validate root access and ModSecurity installation. Exits on failure."""
    if not pf.is_root:
        console.print(f"[red]Error: Must run as root ({sudo_hint(command_hint)})[/red]")
        raise SystemExit(1)
    if not pf.modsec_installed or not pf.modsec_enabled:
        console.print(
            "[red]Error: ModSecurity is not installed/enabled. Run 'nssec waf init' first.[/red]"
        )
        raise SystemExit(1)


def _prompt_and_reload_apache(installer, yes):
    """Prompt user and reload Apache if confirmed."""
    console.print()
    if yes or click.confirm("Reload Apache to apply changes?"):
        reload_result = installer.reload_apache()
        if reload_result.success:
            console.print(f"  [green]Done:[/green] {reload_result.message}")
        else:
            console.print(f"  [red]Error:[/red] {reload_result.error}")
            raise SystemExit(1)
    else:
        console.print("[yellow]Skipped Apache reload. Run manually:[/yellow]")
        console.print("  [cyan]sudo systemctl reload apache2[/cyan]")


def _print_init_next_steps(mode):
    """Print post-installation next steps."""
    console.print("[bold green]ModSecurity installation complete.[/bold green]")
    console.print()
    console.print("[bold]Next steps:[/bold]")
    console.print("  1. Monitor audit log:  [cyan]tail -f /var/log/apache2/modsec_audit.log[/cyan]")
    console.print("  2. Check WAF status:   [cyan]nssec waf status[/cyan]")
    console.print("  3. Run security audit:  [cyan]nssec audit run[/cyan]")
    if mode == "DetectionOnly":
        console.print("  4. When ready to block: [cyan]nssec waf enable[/cyan]")


def _exclusion_toggle_options(fn):
    """Add the --[no-]<toggle> options for the optional exclusion rules."""
    options = [
        click.option(
            "--device-walk/--no-device-walk",
            default=None,
            help="Per-IP limits on v1/v2 API device reads across domains (default on).",
        ),
        click.option(
            "--device-read-allowlist-only/--no-device-read-allowlist-only",
            default=None,
            help=(
                "Deny domain-wide device list reads (v1/v2 API) that are not from "
                "localhost, an allowlisted admin IP, NodePing or a cluster peer; "
                "single-device reads are allowed (default off)."
            ),
        ),
        click.option(
            "--block-harvest-ua/--no-block-harvest-ua",
            default=None,
            help="Deny harvesting user agents and ban their IP from ns-api (default on).",
        ),
        click.option(
            "--token-audit/--no-token-audit",
            default=None,
            help=(
                "Verbose mode: write every /ns-api/oauth2/token and /ns-api/v2/tokens "
                "request to the audit log, credential values masked "
                "(default off)."
            ),
        ),
    ]
    for option in reversed(options):
        fn = option(fn)
    return fn


def _cluster_options(fn):
    """Add the cluster-peer discovery options (SBUS manifest)."""
    options = [
        click.option(
            "--no-cluster",
            is_flag=True,
            help="Skip SBUS cluster discovery; reuse the cached peers, if any.",
        ),
        click.option(
            "--no-public-ip-lookup",
            is_flag=True,
            help="Do not add this server's public IP (from api.ipify.org) to the peers.",
        ),
        click.option(
            "--exclude-host",
            "exclude_hosts",
            multiple=True,
            metavar="PATTERN",
            help="Leave manifest hosts matching this glob out of the peers (repeatable).",
        ),
    ]
    for option in reversed(options):
        fn = option(fn)
    return fn


def _resolve_cluster(no_cluster=False, no_public_ip_lookup=False, exclude_hosts=(), save=True):
    """Discover cluster peers (cache fallback) and report what will be used."""
    from nssec.modules.waf.cluster import SOURCE_DISCOVERED, resolve_cluster_peers

    cluster = resolve_cluster_peers(
        discover=not no_cluster,
        lookup_public=not no_public_ip_lookup,
        exclude=exclude_hosts,
        save=save,
    )
    if cluster.source == SOURCE_DISCOVERED:
        console.print(
            f"  Discovered {len(cluster.peers)} cluster peer IP(s) from "
            f"{len(cluster.hosts)} SBUS manifest host(s)"
        )
    for warning in cluster.warnings:
        console.print(f"  [yellow]Warning:[/yellow] {warning}")
    if cluster.ipv6:
        console.print(
            f"  [dim]Note:[/dim] {len(cluster.ipv6)} IPv6 peer address(es) left out of "
            "mod_evasive (DOSWhitelist is IPv4-only); ModSecurity and the admin-UI "
            "restrictions include them"
        )
    return cluster


def _print_step(result):
    if not result.success:
        console.print(f"  [red]Error:[/red] {result.error}")
    elif result.skipped:
        console.print(f"  [dim]Skipped:[/dim] {result.message}")
    else:
        console.print(f"  [green]Done:[/green] {result.message}")


def _toggle_overrides(toggle_flags):
    """Keep only the toggles given on the command line; warn about risky ones."""
    toggles = {name: value for name, value in toggle_flags.items() if value is not None}
    if toggles.get("device_read_allowlist_only"):
        console.print(
            "  [yellow]Warning:[/yellow] device-read allowlist-only denies domain-wide "
            "device list reads from every source not allowlisted — integrations that "
            "list a domain's devices from their own IPs will get 403"
        )
    if toggles.get("token_audit"):
        console.print(
            "  [yellow]Note:[/yellow] token audit writes every token request to the "
            "audit log; credential values are masked, usernames and other fields are not"
        )
    return toggles


def _on_off(val):
    return "[green]on[/green]" if val else "[yellow]off[/yellow]"


def _yn(val, false_color="red"):
    """Format a boolean as a colored yes/no string."""
    return "[green]yes[/green]" if val else f"[{false_color}]no[/{false_color}]"


def _build_status_table(status):
    """Build and return the WAF status Rich table."""
    table = Table(show_header=False, padding=(0, 2))
    table.add_column("Property", style="cyan")
    table.add_column("Value")

    if status.apache_version:
        apache_val = f"v{status.apache_version}"
        if status.apache_ppa:
            apache_val += " [cyan](ondrej PPA)[/cyan]"
        table.add_row("Apache", apache_val)

    if status.modsec_installed and status.modsec_version:
        from nssec.modules.waf.utils import version_gte

        ver_str = f"v{status.modsec_version}"
        if not version_gte(status.modsec_version, "2.9.6") and status.disabled_crs_rules > 0:
            table.add_row(
                "ModSecurity installed",
                f"[yellow]yes ({ver_str} — {status.disabled_crs_rules} CRS rule(s) disabled, "
                f"run [cyan]nssec waf update[/cyan] to upgrade)[/yellow]",
            )
        else:
            table.add_row(
                "ModSecurity installed",
                f"[green]yes ({ver_str})[/green]",
            )
    else:
        table.add_row("ModSecurity installed", _yn(status.modsec_installed))
    table.add_row("Module enabled", _yn(status.modsec_enabled))

    if status.modsec_mode:
        c = "green" if status.modsec_mode.lower() == "on" else "yellow"
        table.add_row("SecRuleEngine", f"[{c}]{status.modsec_mode}[/{c}]")
    else:
        table.add_row("SecRuleEngine", "[dim]not configured[/dim]")

    if status.crs_installed:
        crs = f"v{status.crs_version}" if status.crs_version else "installed"
        table.add_row("OWASP CRS", f"[green]{crs}[/green]")
        if status.crs_path:
            table.add_row("CRS path", status.crs_path)
        setup_val = _yn(status.crs_setup_present)
        if not status.crs_setup_present:
            setup_val += (
                " [red](rule 901001 will flag all traffic! run [cyan]nssec waf init[/cyan])[/red]"
            )
        table.add_row("crs-setup.conf", setup_val)
    else:
        table.add_row("OWASP CRS", "[red]not installed[/red]")

    if status.evasive_installed:
        evasive_state = (
            "[green]enabled[/green]" if status.evasive_enabled else "[yellow]disabled[/yellow]"
        )
        table.add_row("mod_evasive", evasive_state)
    else:
        table.add_row("mod_evasive", "[dim]not installed[/dim]")

    # NS exclusions detail
    if status.exclusions_present:
        if not status.exclusions_included:
            excl_val = (
                "[red]not loaded[/red] — security2.conf does not include exclusions file, "
                "run [cyan]nssec waf init[/cyan] to fix"
            )
        elif not status.exclusions_ordered:
            excl_val = (
                "[yellow]loaded after CRS rules[/yellow] — localhost/IP allowlist "
                "exclusions cannot suppress phase-1 rules (e.g. 920350), "
                "run [cyan]nssec waf update-exclusions[/cyan] to fix"
            )
        elif not status.crs_path_valid:
            excl_val = (
                "[yellow]loaded but ineffective[/yellow] — "
                "CRS misconfigured (missing crs-setup.conf), "
                "run [cyan]nssec waf init[/cyan] to fix"
            )
        elif not status.exclusions_current:
            v = status.exclusions_version or "unknown"
            excl_val = (
                f"[yellow]outdated (v{v})[/yellow] — run [cyan]nssec waf update-exclusions[/cyan]"
            )
        else:
            excl_val = f"[green]active (v{status.exclusions_version})[/green]"
        table.add_row("NS exclusions", excl_val)
        if status.exclusions_admin_ips:
            table.add_row("  Admin IPs", str(status.exclusions_admin_ips))
        if status.exclusions_nodeping_ips:
            table.add_row("  NodePing IPs", str(status.exclusions_nodeping_ips))
        toggles = status.exclusions_toggles
        table.add_row("  Device-walk limits", _on_off(toggles.get("device_walk")))
        table.add_row(
            "  Device reads allowlist-only",
            "[yellow]on[/yellow]" if toggles.get("device_read_allowlist_only") else "off",
        )
        table.add_row("  Harvest UA block", _on_off(toggles.get("block_harvest_ua")))
        token_audit = "[yellow]on (every token request logged)[/yellow]"
        table.add_row("  Token audit", token_audit if toggles.get("token_audit") else "off")
    else:
        table.add_row("NS exclusions", "[yellow]not deployed[/yellow]")

    if status.cluster_peer_count:
        from nssec.modules.waf.cluster import format_age

        v6 = f", {status.cluster_ipv6_count} IPv6" if status.cluster_ipv6_count else ""
        table.add_row(
            "Cluster peers",
            f"{status.cluster_peer_count} IPs{v6} from {status.cluster_manifest_url} "
            f"(discovered {format_age(status.cluster_discovered_at)} ago)",
        )
        table.add_row("  In mod_evasive", str(status.cluster_evasive_count))
        if status.cluster_drift:
            table.add_row(
                "  [yellow]Drift[/yellow]",
                "[yellow]no mod_evasive entry for "
                + ", ".join(status.cluster_drift)
                + "[/yellow] — run [cyan]nssec waf cluster refresh[/cyan]",
            )
    else:
        table.add_row(
            "Cluster peers",
            "[yellow]none cached[/yellow] — run [cyan]nssec waf cluster refresh[/cyan]",
        )
    table.add_row("Audit log", _yn(status.audit_log_exists, "dim"))
    return table


@waf.command("init")
@click.option(
    "--mode",
    type=click.Choice(["DetectionOnly", "On"]),
    default="DetectionOnly",
    help="Initial SecRuleEngine mode (default: DetectionOnly)",
)
@click.option(
    "--skip-evasive",
    is_flag=True,
    help="Skip mod_evasive installation",
)
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompts")
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be done without making changes",
)
@_exclusion_toggle_options
@_cluster_options
def waf_init(
    mode,
    skip_evasive,
    yes,
    dry_run,
    no_cluster,
    no_public_ip_lookup,
    exclude_hosts,
    **toggle_flags,
):
    """Install and configure ModSecurity v2 with OWASP CRS v4."""
    from nssec.modules.waf import ModSecurityInstaller

    installer = ModSecurityInstaller(
        mode=mode,
        install_evasive=not skip_evasive,
        dry_run=dry_run,
    )

    console.print("[bold]Running preflight checks...[/bold]")
    pf = installer.preflight()

    if not pf.can_proceed:
        for err in pf.errors:
            console.print(f"  [red]Error:[/red] {err}")
        raise SystemExit(1)

    console.print()
    _display_install_plan(pf, mode, skip_evasive)
    for warn in pf.warnings:
        console.print(f"  [yellow]Note:[/yellow] {warn}")
    console.print()

    if dry_run:
        console.print("[yellow]Dry run \u2014 no changes made.[/yellow]")
        return

    if not yes and not click.confirm("Proceed with installation?"):
        console.print("[yellow]Aborted.[/yellow]")
        return

    # Fetch NodePing monitoring probe IPs for WAF allowlisting
    from nssec.modules.waf import fetch_nodeping_probe_ips

    nodeping_ips, np_err = fetch_nodeping_probe_ips()
    if np_err:
        console.print(f"  [yellow]Warning:[/yellow] {np_err}")
    elif nodeping_ips:
        console.print(f"  Fetched {len(nodeping_ips)} NodePing probe IPs for WAF allowlisting")

    cluster = _resolve_cluster(no_cluster, no_public_ip_lookup, exclude_hosts)

    from nssec.modules.waf.restrict import rerender_with_cluster

    if cluster.peers:
        restrict = rerender_with_cluster(cluster)
        if not restrict.skipped:
            _print_step(restrict)

    console.print()
    toggles = _toggle_overrides(toggle_flags)
    result = installer.run(nodeping_ips=nodeping_ips, toggles=toggles, cluster=cluster)
    _print_install_results(result)

    if not result.success:
        raise SystemExit(1)

    _prompt_and_reload_apache(installer, yes)
    console.print()
    _print_init_next_steps(mode)


@waf.command("enable")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
def waf_enable(yes):
    """Switch ModSecurity from DetectionOnly to blocking mode."""
    from nssec.modules.waf import ModSecurityInstaller

    installer = ModSecurityInstaller()
    pf = installer.preflight()
    _require_root_and_modsec(pf, "sudo nssec waf enable")

    if pf.modsec_mode and pf.modsec_mode.lower() == "on":
        console.print("[green]ModSecurity is already in blocking mode.[/green]")
        return

    console.print(
        "[bold yellow]Warning:[/bold yellow] Switching to blocking mode "
        "will actively reject requests that match ModSecurity rules."
    )
    console.print(
        "Ensure you have reviewed "
        "[cyan]/var/log/apache2/modsec_audit.log[/cyan] for false positives."
    )
    console.print()

    if not yes and not click.confirm("Switch SecRuleEngine to On?"):
        console.print("[yellow]Aborted.[/yellow]")
        return

    result = installer.set_mode("On")
    if result.success:
        console.print(f"[green]{result.message}[/green]")
        console.print()
        console.print("[bold]Tip:[/bold] To also enable HTTP flood protection, run:")
        console.print(f"  [cyan]{sudo_hint('waf evasive enable')}[/cyan]")
    else:
        console.print(f"[red]Error: {result.error}[/red]")
        raise SystemExit(1)


@waf.command("disable")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
def waf_disable(yes):
    """Switch ModSecurity to DetectionOnly mode (logs but does not block)."""
    from nssec.modules.waf import ModSecurityInstaller

    installer = ModSecurityInstaller()
    pf = installer.preflight()
    _require_root_and_modsec(pf, "sudo nssec waf disable")

    if pf.modsec_mode and pf.modsec_mode.lower() == "detectiononly":
        console.print("[green]ModSecurity is already in DetectionOnly mode.[/green]")
        return

    console.print(
        "Switching to [cyan]DetectionOnly[/cyan] mode. "
        "ModSecurity will log violations but not block requests."
    )
    console.print()

    if not yes and not click.confirm("Switch SecRuleEngine to DetectionOnly?"):
        console.print("[yellow]Aborted.[/yellow]")
        return

    result = installer.set_mode("DetectionOnly")
    if result.success:
        console.print(f"[green]{result.message}[/green]")
    else:
        console.print(f"[red]Error: {result.error}[/red]")
        raise SystemExit(1)


@waf.command("remove")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
def waf_remove(yes):
    """Disable the ModSecurity Apache module entirely.

    This disables the security2 module in Apache, effectively turning off
    the WAF completely. Use 'nssec waf init' to re-enable.
    """
    from nssec.core.ssh import is_root
    from nssec.modules.waf.config import SECURITY2_LOAD
    from nssec.modules.waf.utils import file_exists, run_cmd

    if not is_root():
        console.print(f"[red]Error: Must run as root ({sudo_hint('waf remove')})[/red]")
        raise SystemExit(1)

    if not file_exists(SECURITY2_LOAD):
        console.print("[green]ModSecurity module is already disabled.[/green]")
        return

    console.print(
        "[bold yellow]Warning:[/bold yellow] This will completely disable "
        "the ModSecurity WAF module."
    )
    console.print()

    if not yes and not click.confirm("Disable ModSecurity module?"):
        console.print("[yellow]Aborted.[/yellow]")
        return

    _, stderr, rc = run_cmd(["a2dismod", "security2"])
    if rc != 0:
        console.print(f"[red]Error:[/red] Failed to disable module: {stderr}")
        raise SystemExit(1)
    console.print("[green]Done:[/green] Disabled security2 module")

    _, stderr, rc = run_cmd(["systemctl", "reload", "apache2"])
    if rc != 0:
        console.print(f"[red]Error:[/red] Apache reload failed: {stderr}")
        raise SystemExit(1)
    console.print("[green]Done:[/green] Apache reloaded")

    console.print()
    console.print("ModSecurity is now disabled. To re-enable, run:")
    console.print(f"  [cyan]{sudo_hint('waf init')}[/cyan]")


@waf.command("update-exclusions")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be done without making changes",
)
@_exclusion_toggle_options
@_cluster_options
def waf_update_exclusions(
    yes, dry_run, no_cluster, no_public_ip_lookup, exclude_hosts, **toggle_flags
):
    """Re-deploy NetSapiens WAF exclusion rules.

    Updates /etc/modsecurity/netsapiens-exclusions.conf from the latest
    nssec templates without re-running the full waf init. Also refreshes
    the security2.conf include layout so the exclusions load before the
    CRS rules (required for the localhost/IP allowlist exclusions to
    suppress phase-1 rules).

    \b
    The optional rules (--device-walk, --block-harvest-ua, --token-audit,
    each with a --no- form) keep their current setting unless given.
    """
    from nssec.modules.waf import ModSecurityInstaller

    installer = ModSecurityInstaller(dry_run=dry_run)
    pf = installer.preflight()
    _require_root_and_modsec(pf, "sudo nssec waf update-exclusions")

    console.print("[bold]Updating NetSapiens WAF exclusions...[/bold]")

    # Fetch NodePing monitoring probe IPs for WAF allowlisting
    from nssec.modules.waf import fetch_nodeping_probe_ips

    nodeping_ips, np_err = fetch_nodeping_probe_ips()
    if np_err:
        console.print(f"  [yellow]Warning:[/yellow] {np_err}")
    elif nodeping_ips:
        console.print(f"  Fetched {len(nodeping_ips)} NodePing probe IPs for WAF allowlisting")

    cluster = _resolve_cluster(no_cluster, no_public_ip_lookup, exclude_hosts, save=not dry_run)

    from nssec.modules.waf import restrict as restrict_mod
    from nssec.modules.waf.config import EVASIVE_CONF, NS_EXCLUSIONS_CONF
    from nssec.modules.waf.utils import restore_snapshot, snapshot_files

    # Snapshot everything this command rewrites so a failed configtest undoes
    # exactly this run.
    snapshot = snapshot_files([NS_EXCLUSIONS_CONF, EVASIVE_CONF, restrict_mod.RESTRICT_CONF_PATH])

    toggles = _toggle_overrides(toggle_flags)
    result = installer.install_exclusions(
        nodeping_ips=nodeping_ips, toggles=toggles, cluster=cluster
    )
    if not result.success:
        console.print(f"  [red]Error:[/red] {result.error}")
        raise SystemExit(1)
    console.print(f"  [green]Done:[/green] {result.message}")

    # Keep the cluster peers identical in every config that lists them.
    evasive = installer.refresh_evasive_cluster(cluster)
    _print_step(evasive)
    if not evasive.success:
        restore_snapshot(snapshot)
        raise SystemExit(1)
    if not dry_run:
        restrict = restrict_mod.rerender_with_cluster(cluster)
        _print_step(restrict)
        if not restrict.success:
            restore_snapshot(snapshot)
            raise SystemExit(1)

    # Rewrite security2.conf so the exclusions load before the CRS rules
    # (no-op on wildcard-include setups, where they already do).
    sec2 = installer.write_security2_conf()
    if not sec2.success:
        console.print(f"  [red]Error:[/red] {sec2.error}")
        raise SystemExit(1)
    if sec2.skipped:
        console.print(f"  [dim]Skipped:[/dim] {sec2.message}")
    else:
        console.print(f"  [green]Done:[/green] {sec2.message}")

    if dry_run:
        console.print("\n[yellow]Dry run \u2014 no further changes.[/yellow]")
        return

    val = installer.validate_config(snapshot=snapshot)
    if not val.success:
        console.print(f"  [red]Error:[/red] {val.error}")
        raise SystemExit(1)
    console.print(f"  [green]Done:[/green] {val.message}")

    _prompt_and_reload_apache(installer, yes)


@waf.command("status")
def waf_status():
    """Show WAF/ModSecurity status."""
    from nssec.modules.waf.status import get_waf_status

    status = get_waf_status()

    console.print("[bold]WAF Status[/bold]\n")
    console.print(_build_status_table(status))

    if status.recent_log_lines:
        console.print("\n[bold]Recent audit log entries:[/bold]")
        for line in status.recent_log_lines:
            console.print(f"  [dim]{line}[/dim]")


@waf.command("update")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompts")
def waf_update(yes):
    """Check ModSecurity version and re-enable CRS rules after upgrade.

    \b
    If ModSecurity < 2.9.6, shows instructions for adding the Digitalwave
    ModSecurity repository to get a compatible version.

    \b
    If ModSecurity >= 2.9.6 (user already upgraded), re-enables any CRS
    rules that were disabled during init and validates the Apache config.
    """
    from nssec.modules.waf import ModSecurityInstaller
    from nssec.modules.waf.config import (
        CRS_INSTALL_DIR,
        DIGITALWAVE_KEY_URL,
        DIGITALWAVE_KEYRING,
        DIGITALWAVE_LIST,
        DIGITALWAVE_REPO_URL,
    )
    from nssec.modules.waf.utils import detect_modsec_version, version_gte

    installer = ModSecurityInstaller()
    pf = installer.preflight()
    _require_root_and_modsec(pf, "sudo nssec waf update")

    current_ver = detect_modsec_version()
    console.print(f"[bold]Current ModSecurity version:[/bold] {current_ver or 'unknown'}")

    if not version_gte(current_ver, "2.9.6"):
        console.print()
        console.print("[yellow]ModSecurity < 2.9.6 — some CRS v4 rules are disabled.[/yellow]")
        console.print(
            "Ubuntu 22.04 ships ModSecurity 2.9.5 which lacks support for "
            "multipart rules introduced in 2.9.6."
        )
        console.print()
        console.print("[bold]To upgrade, add the Digitalwave ModSecurity repository:[/bold]")
        console.print()
        keyring = DIGITALWAVE_KEYRING
        console.print(
            f"  [cyan]curl -fsSL {DIGITALWAVE_KEY_URL} | sudo gpg --dearmor -o {keyring}[/cyan]"
        )
        console.print()
        # Escape square brackets so Rich doesn't treat [signed-by=...] as markup
        signed = f"\\[signed-by={keyring}]"
        repo = DIGITALWAVE_REPO_URL
        lst = DIGITALWAVE_LIST
        console.print(
            f'  [cyan]echo "deb {signed} {repo} $(lsb_release -sc) main" | sudo tee {lst}[/cyan]'
        )
        console.print(
            f'  [cyan]echo "deb {signed} {repo} $(lsb_release -sc)-backports main" '
            f"| sudo tee -a {lst}[/cyan]"
        )
        console.print()
        console.print("  [cyan]sudo apt-get update[/cyan]")
        console.print(
            "  [cyan]sudo apt-get install -t $(lsb_release -sc)-backports "
            "libapache2-mod-security2[/cyan]"
        )
        console.print()
        console.print(
            "After upgrading, run [cyan]nssec waf update[/cyan] again to "
            "re-enable the disabled CRS rules."
        )
        return

    # ModSec >= 2.9.6 — re-enable any disabled rules
    crs_path = pf.crs_path or CRS_INSTALL_DIR
    reenabled = installer._reenable_crs_rules(crs_path)
    if not reenabled:
        console.print(
            "[green]ModSecurity >= 2.9.6 and all CRS rules are active. Nothing to do.[/green]"
        )
        return

    console.print(
        f"  [green]Done:[/green] Re-enabled {len(reenabled)} CRS rule(s): " + ", ".join(reenabled)
    )

    val = installer.validate_config()
    if not val.success:
        console.print(f"  [red]Error:[/red] {val.error}")
        raise SystemExit(1)
    console.print(f"  [green]Done:[/green] {val.message}")

    _prompt_and_reload_apache(installer, yes)


@waf.group("allowlist", invoke_without_command=True)
@click.pass_context
def waf_allowlist(ctx):
    """Manage allowlisted IPs for reduced WAF strictness."""
    if ctx.invoked_subcommand is None:
        # Default behavior: show allowlist
        from nssec.modules.waf import get_allowlisted_ips

        ips = get_allowlisted_ips()
        if not ips:
            console.print("[dim]No IPs currently allowlisted.[/dim]")
            return

        console.print(f"[bold]Allowlisted IPs[/bold] ({len(ips)})\n")
        for ip in ips:
            console.print(f"  {ip}")


@waf_allowlist.command("show")
def waf_allowlist_show():
    """Show every IP with reduced WAF strictness: admin, cluster peers, NodePing."""
    from nssec.modules.waf import get_allowlisted_ips, get_nodeping_ips
    from nssec.modules.waf.cluster import deployed_exclusions_peers

    ips = get_allowlisted_ips()
    if ips:
        console.print(f"[bold]Allowlisted IPs[/bold] ({len(ips)})")
        for ip in ips:
            console.print(f"  {ip}")
    else:
        console.print("[dim]No IPs currently allowlisted.[/dim]")
    console.print("  [dim]Manage with: nssec waf allowlist add|delete[/dim]")

    peers = deployed_exclusions_peers()
    console.print()
    if peers:
        console.print(f"[bold]Cluster peers[/bold] ({len(peers)})")
        width = max(len(ip) for ip in peers)
        for ip, host in peers.items():
            console.print(f"  {ip.ljust(width)}  [dim]{host}[/dim]")
    else:
        console.print("[dim]No cluster peers deployed.[/dim]")
    console.print("  [dim]Managed from the SBUS manifest: nssec waf cluster show|refresh[/dim]")

    nodeping = get_nodeping_ips()
    console.print()
    console.print(f"[bold]NodePing probes[/bold] ({len(nodeping)})")
    console.print("  [dim]Refreshed by: nssec waf update-exclusions[/dim]")

    console.print()
    console.print("[dim]Localhost (127.0.0.1, ::1) is always allowlisted.[/dim]")


@waf_allowlist.command("add")
@click.argument("ip")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
def waf_allowlist_add(ip, yes):
    """Add an IP address to the WAF allowlist.

    IP can be a single address (192.168.1.1) or CIDR notation (10.0.0.0/8).
    Allowlisted IPs bypass OWASP CRS rules for reduced false positives.
    """
    from nssec.modules.waf import (
        ModSecurityInstaller,
        add_allowlisted_ip,
        get_allowlisted_ips,
        normalize_ipmatch_entry,
    )

    installer = ModSecurityInstaller()
    pf = installer.preflight()
    _require_root_and_modsec(pf, "sudo nssec waf allowlist add")

    ip = normalize_ipmatch_entry(ip)
    current_ips = get_allowlisted_ips()
    if ip in current_ips:
        console.print(f"[yellow]IP {ip} is already allowlisted.[/yellow]")
        return

    console.print(f"Adding [cyan]{ip}[/cyan] to WAF allowlist...")

    result = add_allowlisted_ip(ip)
    if not result.success:
        console.print(f"  [red]Error:[/red] {result.error}")
        raise SystemExit(1)
    console.print(f"  [green]Done:[/green] {result.message}")

    val = installer.validate_config()
    if not val.success:
        console.print(f"  [red]Error:[/red] {val.error}")
        raise SystemExit(1)
    console.print(f"  [green]Done:[/green] {val.message}")

    _prompt_and_reload_apache(installer, yes)


@waf_allowlist.command("delete")
@click.argument("ip")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
def waf_allowlist_delete(ip, yes):
    """Remove an IP address from the WAF allowlist.

    IP must match exactly as it was added (including CIDR notation if used).
    """
    from nssec.modules.waf import (
        ModSecurityInstaller,
        get_allowlisted_ips,
        normalize_ipmatch_entry,
        remove_allowlisted_ip,
    )

    installer = ModSecurityInstaller()
    pf = installer.preflight()
    _require_root_and_modsec(pf, "sudo nssec waf allowlist delete")

    ip = normalize_ipmatch_entry(ip)
    current_ips = get_allowlisted_ips()
    if ip not in current_ips:
        from nssec.modules.waf.cluster import deployed_exclusions_peers

        peers = deployed_exclusions_peers()
        if ip in peers:
            console.print(
                f"[yellow]{ip} is a cluster peer ({peers[ip]}), not a manual allowlist "
                "entry.[/yellow]"
            )
            console.print(
                "Cluster peers come from the SBUS manifest; to leave a host out run "
                "[cyan]nssec waf cluster refresh --exclude-host PATTERN[/cyan]."
            )
            return
        console.print(f"[yellow]IP {ip} is not in the allowlist.[/yellow]")
        if current_ips:
            console.print("\nCurrent allowlisted IPs:")
            for existing_ip in current_ips:
                console.print(f"  {existing_ip}")
        return

    console.print(f"Removing [cyan]{ip}[/cyan] from WAF allowlist...")

    result = remove_allowlisted_ip(ip)
    if not result.success:
        console.print(f"  [red]Error:[/red] {result.error}")
        raise SystemExit(1)
    console.print(f"  [green]Done:[/green] {result.message}")

    val = installer.validate_config()
    if not val.success:
        console.print(f"  [red]Error:[/red] {val.error}")
        raise SystemExit(1)
    console.print(f"  [green]Done:[/green] {val.message}")

    _prompt_and_reload_apache(installer, yes)


# ─── EVASIVE SUBCOMMANDS ───


@waf.group("evasive", invoke_without_command=True)
@click.pass_context
def waf_evasive(ctx):
    """Manage mod_evasive (HTTP flood protection)."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(waf_evasive_status)


@waf_evasive.command("enable")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
@click.option(
    "--profile",
    type=click.Choice(["standard", "strict"]),
    default="standard",
    help="Threshold profile: standard (safe default) or strict (tuned for NS traffic)",
)
def waf_evasive_enable(yes, profile):
    """Enable mod_evasive HTTP flood protection.

    mod_evasive has NO detection-only mode — it WILL block IPs that exceed
    the configured thresholds (HTTP 403).

    \b
    Profiles:
      standard  High thresholds (100 req/page, 500 req/site). Safe default
                that only catches extreme floods. Start here.
      strict    Tight thresholds (15 req/page, 60 req/site) tuned for
                NetSapiens traffic. Use after reviewing traffic patterns.

    Review your traffic with the Apache API Usage dashboard or access logs
    before switching to the strict profile.
    """
    from nssec.modules.waf import ModSecurityInstaller
    from nssec.modules.waf.config import EVASIVE_PACKAGE, EVASIVE_PROFILES
    from nssec.modules.waf.utils import package_installed

    installer = ModSecurityInstaller()
    pf = installer.preflight()

    if not pf.is_root:
        console.print(f"[red]Error: Must run as root ({sudo_hint('waf evasive enable')})[/red]")
        raise SystemExit(1)

    if not package_installed(EVASIVE_PACKAGE):
        console.print("[red]Error: mod_evasive is not installed. Run 'nssec waf init' first.[/red]")
        raise SystemExit(1)

    thresholds = EVASIVE_PROFILES[profile]
    console.print(
        "[bold yellow]Warning:[/bold yellow] mod_evasive has no detection-only mode. "
        "When enabled it [bold]will block[/bold] IPs that exceed thresholds (HTTP 403)."
    )
    console.print(f"  Profile:          [cyan]{profile}[/cyan]")
    console.print(f"  DOSPageCount:     {thresholds['page_count']} req/page/s")
    console.print(f"  DOSSiteCount:     {thresholds['site_count']} req/IP/s")
    console.print(f"  DOSBlockingPeriod: {thresholds['blocking_period']}s")
    console.print()
    console.print(
        "Review traffic patterns before enabling. Use the Apache API Usage "
        "dashboard or [cyan]tail -f /var/log/apache2/access.log[/cyan]."
    )
    console.print()

    if not yes and not click.confirm("Enable mod_evasive?"):
        console.print("[yellow]Aborted.[/yellow]")
        return

    config_result = installer.setup_evasive_config(profile=profile)
    if not config_result.success and not config_result.skipped:
        console.print(f"[red]Error: {config_result.error}[/red]")
        raise SystemExit(1)
    console.print(f"  [green]Done:[/green] {config_result.message}")

    result = installer.set_evasive_state(enable=True)
    if result.skipped:
        console.print(f"  [green]{result.message}[/green]")
    elif not result.success:
        console.print(f"[red]Error: {result.error}[/red]")
        raise SystemExit(1)
    else:
        console.print(f"  [green]Done:[/green] {result.message}")

    _prompt_and_reload_apache(installer, yes)


@waf_evasive.command("disable")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
def waf_evasive_disable(yes):
    """Disable mod_evasive HTTP flood protection."""
    from nssec.core.ssh import is_root
    from nssec.modules.waf import ModSecurityInstaller

    if not is_root():
        console.print(f"[red]Error: Must run as root ({sudo_hint('waf evasive disable')})[/red]")
        raise SystemExit(1)

    console.print(
        "[bold yellow]Warning:[/bold yellow] Disabling mod_evasive removes "
        "HTTP flood protection. The server will be vulnerable to "
        "application-layer DDoS attacks."
    )
    console.print()

    if not yes and not click.confirm("Disable mod_evasive?"):
        console.print("[yellow]Aborted.[/yellow]")
        return

    installer = ModSecurityInstaller()
    result = installer.set_evasive_state(enable=False)
    if result.skipped:
        console.print(f"[green]{result.message}[/green]")
        return

    if not result.success:
        console.print(f"[red]Error: {result.error}[/red]")
        raise SystemExit(1)

    console.print(f"[green]{result.message}[/green]")
    _prompt_and_reload_apache(installer, yes)


@waf_evasive.command("status")
def waf_evasive_status():
    """Show mod_evasive status."""
    from nssec.modules.waf.config import EVASIVE_CONF, EVASIVE_LOAD, EVASIVE_PACKAGE
    from nssec.modules.waf.utils import file_exists, package_installed, read_file

    installed = package_installed(EVASIVE_PACKAGE)
    enabled = file_exists(EVASIVE_LOAD)
    configured = file_exists(EVASIVE_CONF)

    console.print("[bold]mod_evasive Status[/bold]\n")

    if not installed:
        console.print("  Installed:  [red]no[/red]")
        console.print("\n  Run [cyan]nssec waf init[/cyan] to install.")
        return

    console.print("  Installed:  [green]yes[/green]")
    console.print(f"  Configured: {_yn(configured)}")

    if enabled:
        console.print("  Module:     [green]enabled[/green]")
    else:
        console.print("  Module:     [yellow]disabled[/yellow]")

    # Show active profile from config comment
    if configured:
        content = read_file(EVASIVE_CONF) or ""
        profile = "unknown"
        for line in content.splitlines():
            if line.startswith("# Profile:"):
                profile = line.split(":", 1)[1].strip()
                break
        console.print(f"  Profile:    [cyan]{profile}[/cyan]")

    if not enabled:
        console.print(f"\n  Enable with: [cyan]{sudo_hint('waf evasive enable')}[/cyan]")


# ─── RESTRICT SUBCOMMANDS ───


def _validate_and_prompt_reload_for_restrict(yes) -> bool:
    """Run apache2ctl configtest then prompt for Apache reload.

    Returns True if Apache was reloaded, False if the reload was skipped.
    Exits the process if configtest or the reload itself fails.
    """
    from nssec.modules.waf.utils import run_cmd

    stdout, stderr, rc = run_cmd(["apache2ctl", "configtest"])
    if rc != 0:
        console.print(f"  [red]Error:[/red] Apache config test failed: {stderr or stdout}")
        raise SystemExit(1)
    console.print("  [green]Done:[/green] Apache config test passed")

    console.print()
    if yes or click.confirm("Reload Apache to apply changes?"):
        _, stderr, rc = run_cmd(["systemctl", "reload", "apache2"])
        if rc != 0:
            console.print(f"  [red]Error:[/red] Apache reload failed: {stderr}")
            raise SystemExit(1)
        console.print("  [green]Done:[/green] Apache reloaded")
        return True

    console.print("[yellow]Skipped Apache reload. Run manually:[/yellow]")
    console.print("  [cyan]sudo systemctl reload apache2[/cyan]")
    return False


@waf.group("restrict", invoke_without_command=True)
@click.pass_context
def waf_restrict(ctx):
    """Manage admin-UI IP restrictions via an Apache config."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(waf_restrict_show)


@waf_restrict.command("show")
def waf_restrict_show():
    """Show the admin-UI IP restriction status."""
    from nssec.core.server_types import detect_server_type
    from nssec.modules.waf.restrict import get_restrict_status, load_cached_ips

    server_type = detect_server_type().value
    status = get_restrict_status(server_type)

    if not status["segments"] and not status["legacy"]:
        console.print("[dim]No applicable admin UIs for this server type.[/dim]")
        return

    console.print(f"[bold]Restrict config:[/bold] {status['path']}")
    if not status["exists"]:
        state = "[red]not present[/red]"
    elif status["managed"]:
        state = "[green]managed[/green]"
    else:
        state = "[yellow]unmanaged (not created by nssec)[/yellow]"
    console.print(f"[bold]Status:[/bold] {state}")

    if status["segments"]:
        console.print(f"[bold]Protected admin UIs:[/bold] {', '.join(status['components'])}")
        console.print(f"  [dim]LocationMatch ^/({'|'.join(status['segments'])})/[/dim]")

    if status["ips"]:
        console.print(f"\n[bold]Allowed IPs[/bold] ({len(status['ips'])}):")
        for ip in status["ips"]:
            console.print(f"  {ip}")

    cached = load_cached_ips()
    if cached:
        console.print(f"\n[bold]IP cache:[/bold] [green]{len(cached)} IP(s) saved[/green]")
        console.print("  Run [cyan]nssec waf restrict reapply[/cyan] to restore after an upgrade")
    elif status["managed"]:
        console.print("\n[bold]IP cache:[/bold] [yellow]not saved[/yellow]")
        console.print(
            "  Run [cyan]nssec waf restrict init[/cyan] to save IPs for reapply after upgrades"
        )

    if status["legacy"]:
        console.print(
            f"\n[yellow]Legacy .htaccess files still present[/yellow] ({len(status['legacy'])}):"
        )
        for path in status["legacy"]:
            console.print(f"  {path}")
        console.print(
            f"  Migrate and remove them with [cyan]{sudo_hint('waf restrict init')}[/cyan]"
        )


@waf_restrict.command("init")
@click.option("--ip", "ips", multiple=True, help="IP address or CIDR to allow (repeatable)")
@click.option("--dry-run", is_flag=True, help="Show what would be done without making changes")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompts")
def waf_restrict_init(ips, dry_run, yes):
    """Restrict the NetSapiens admin UIs to an IP allowlist.

    Writes a single Apache config (/etc/apache2/conf.d/nssec-restrict.conf)
    using mod_authz_core <LocationMatch> + Require ip directives. This survives
    NetSapiens package upgrades and is honored under PHP-FPM, unlike the legacy
    per-directory .htaccess files it replaces (which are removed on migration).

    \b
    127.0.0.1 is always included automatically. You should also include:
      - NetSapiens TAC support IPs
      - Your admin office IP(s)

    Use --ip to specify IPs, or omit to be prompted interactively. Existing IPs
    (from the current config, legacy .htaccess files, or the cache) are shown
    and you are asked whether to keep or overwrite them.
    """
    import ipaddress

    from nssec.core.server_types import detect_server_type
    from nssec.core.ssh import is_root
    from nssec.modules.waf.restrict import (
        collect_existing_ips,
        find_legacy_managed_htaccess,
        init_restrictions,
        remove_legacy_htaccess,
    )

    if not is_root():
        console.print(f"[red]Error: Must run as root ({sudo_hint('waf restrict init')})[/red]")
        raise SystemExit(1)

    server_type = detect_server_type().value

    # Check for existing IPs on disk / in cache
    existing_ips = collect_existing_ips(server_type)
    merge_existing = True

    if existing_ips and not dry_run:
        console.print(f"[bold]Existing IPs found[/bold] ({len(existing_ips)}):")
        for eip in existing_ips:
            console.print(f"  {eip}")
        console.print()
        if not yes:
            keep = click.confirm(
                "Keep these existing IPs? (No = overwrite with only the IPs you provide)",
                default=True,
            )
            merge_existing = keep
        # When --yes is passed, default to keeping existing IPs

    # Collect IPs
    ip_list = list(ips)
    if not ip_list:
        keeping_existing = bool(existing_ips) and merge_existing
        if keeping_existing:
            console.print(
                f"[bold]Enter any additional IP addresses to allow[/bold] — these are "
                f"added on top of the {len(existing_ips)} existing IP(s) you kept."
            )
            console.print("  One per line, or space/comma separated.")
            console.print("  Include NetSapiens TAC IPs and your admin office IPs.")
            console.print("  127.0.0.1 is always included automatically.")
            console.print(
                "  Press Enter on a blank line to add none and keep only the existing IPs."
            )
        else:
            console.print(
                "[bold]Enter IP addresses to allow access[/bold] "
                "(one per line, or space/comma separated)."
            )
            console.print("  Include NetSapiens TAC IPs and your admin office IPs.")
            console.print("  127.0.0.1 is always included automatically.")
            console.print("  Press Enter on a blank line when done.")
        console.print()
        lines: list[str] = []
        while True:
            line = click.prompt("IP", default="", show_default=False)
            if not line.strip():
                break
            lines.append(line)
        # Split on commas and whitespace across all lines
        raw = " ".join(lines)
        ip_list = [s.strip() for s in raw.replace(",", " ").split() if s.strip()]

    # Validate each IP
    for ip_str in ip_list:
        try:
            if "/" in ip_str:
                ipaddress.ip_network(ip_str, strict=False)
            else:
                ipaddress.ip_address(ip_str)
        except ValueError:
            console.print(f"[red]Error: Invalid IP address or CIDR: {ip_str}[/red]")
            raise SystemExit(1)

    console.print(f"\n[bold]Server type:[/bold] {server_type}")
    console.print(f"[bold]IPs to allow:[/bold] 127.0.0.1 {' '.join(ip_list)}")
    if existing_ips and merge_existing:
        console.print(f"[bold]Keeping:[/bold] {len(existing_ips)} existing IP(s)")
    elif existing_ips and not merge_existing:
        console.print("[yellow]Overwriting existing IPs[/yellow]")
    console.print()

    if dry_run:
        results = init_restrictions(
            server_type, ip_list, dry_run=True, merge_existing=merge_existing
        )
        for name, result in results:
            label = f"[cyan]{name}:[/cyan] " if name else ""
            console.print(f"  {label}{result.message}")
        for path, result in remove_legacy_htaccess(dry_run=True):
            console.print(f"  {result.message}")
        console.print("\n[yellow]Dry run — no changes made.[/yellow]")
        return

    if not yes and not click.confirm("Write admin-UI IP restrictions?"):
        console.print("[yellow]Aborted.[/yellow]")
        return

    results = init_restrictions(server_type, ip_list, merge_existing=merge_existing)
    any_error = False
    for name, result in results:
        label = f"[cyan]{name}:[/cyan] " if name else ""
        if result.skipped:
            console.print(f"  [dim]Skipped:[/dim] {label}{result.message}")
        elif result.success:
            console.print(f"  [green]Done:[/green] {label}{result.message}")
        else:
            console.print(f"  [red]Error:[/red] {label}{result.error}")
            any_error = True

    if any_error:
        raise SystemExit(1)

    reloaded = _validate_and_prompt_reload_for_restrict(yes)

    # Only remove the legacy .htaccess files once the new config is actually
    # live, so the admin UI is never left unprotected mid-migration.
    if reloaded:
        for path, result in remove_legacy_htaccess():
            if result.success:
                console.print(f"  [green]Done:[/green] {result.message}")
            else:
                console.print(f"  [red]Error:[/red] {result.error}")
    elif find_legacy_managed_htaccess():
        console.print(
            "[yellow]Legacy .htaccess files left in place.[/yellow] Reload Apache, then "
            f"re-run [cyan]{sudo_hint('waf restrict init')}[/cyan] to remove them."
        )


@waf_restrict.command("add")
@click.argument("ip")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompts")
def waf_restrict_add(ip, yes):
    """Add an IP address to the managed admin-UI restrict config.

    IP can be a single address (192.168.1.1) or CIDR notation (10.0.0.0/8).
    """
    import ipaddress

    from nssec.core.server_types import detect_server_type
    from nssec.core.ssh import is_root
    from nssec.modules.waf.restrict import add_restricted_ip

    if not is_root():
        console.print(f"[red]Error: Must run as root ({sudo_hint('waf restrict add')})[/red]")
        raise SystemExit(1)

    # Validate IP
    try:
        if "/" in ip:
            ipaddress.ip_network(ip, strict=False)
        else:
            ipaddress.ip_address(ip)
    except ValueError:
        console.print(f"[red]Error: Invalid IP address or CIDR: {ip}[/red]")
        raise SystemExit(1)

    server_type = detect_server_type().value
    console.print(f"Adding [cyan]{ip}[/cyan] to the restrict config...")

    results = add_restricted_ip(server_type, ip)
    any_changed = False
    for name, result in results:
        label = f"[cyan]{name}:[/cyan] " if name else ""
        if result.skipped:
            console.print(f"  [dim]Skipped:[/dim] {label}{result.message}")
        elif result.success:
            console.print(f"  [green]Done:[/green] {label}{result.message}")
            any_changed = True
        else:
            console.print(f"  [red]Error:[/red] {label}{result.error}")
            raise SystemExit(1)

    if any_changed:
        _validate_and_prompt_reload_for_restrict(yes)


@waf_restrict.command("remove")
@click.argument("ip")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompts")
def waf_restrict_remove(ip, yes):
    """Remove an IP address from the managed admin-UI restrict config.

    Cannot remove 127.0.0.1 (localhost is always required).
    """
    from nssec.core.server_types import detect_server_type
    from nssec.core.ssh import is_root
    from nssec.modules.waf.restrict import remove_restricted_ip

    if not is_root():
        console.print(f"[red]Error: Must run as root ({sudo_hint('waf restrict remove')})[/red]")
        raise SystemExit(1)

    server_type = detect_server_type().value
    console.print(f"Removing [cyan]{ip}[/cyan] from the restrict config...")

    results = remove_restricted_ip(server_type, ip)
    any_changed = False
    any_error = False
    for name, result in results:
        label = f"[cyan]{name}:[/cyan] " if name else ""
        if not result.success and result.error:
            console.print(f"  [red]Error:[/red] {label}{result.error}")
            any_error = True
        elif result.skipped:
            console.print(f"  [dim]Skipped:[/dim] {label}{result.message}")
        elif result.success:
            console.print(f"  [green]Done:[/green] {label}{result.message}")
            any_changed = True

    if any_error:
        raise SystemExit(1)

    if any_changed:
        _validate_and_prompt_reload_for_restrict(yes)


@waf_restrict.command("reapply")
@click.option("--dry-run", is_flag=True, help="Show what would be done without making changes")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompts")
def waf_restrict_reapply(dry_run, yes):
    """Re-deploy the admin-UI restrict config from cached IPs.

    Use if the config is removed or after a NetSapiens upgrade. Reads the saved
    IP list from /etc/nssec/restrict-ips.json and re-writes the Apache config.
    """
    from nssec.core.server_types import detect_server_type
    from nssec.core.ssh import is_root
    from nssec.modules.waf.restrict import load_cached_ips, reapply_restrictions

    if not is_root():
        console.print(f"[red]Error: Must run as root ({sudo_hint('waf restrict reapply')})[/red]")
        raise SystemExit(1)

    cached_ips = load_cached_ips()
    if cached_ips:
        console.print(f"[bold]Cached IPs[/bold] ({len(cached_ips)}):")
        for ip in cached_ips:
            console.print(f"  {ip}")
        console.print()

    server_type = detect_server_type().value

    if dry_run:
        results = reapply_restrictions(server_type, dry_run=True)
        for name, result in results:
            label = f"[cyan]{name}:[/cyan] " if name else ""
            if result.skipped:
                console.print(f"  [dim]Skipped:[/dim] {label}{result.message}")
            else:
                console.print(f"  {label}{result.message}")
        console.print("\n[yellow]Dry run — no changes made.[/yellow]")
        return

    if not yes and not click.confirm("Re-deploy .htaccess restrictions from cache?"):
        console.print("[yellow]Aborted.[/yellow]")
        return

    results = reapply_restrictions(server_type)
    any_error = False
    any_changed = False
    for name, result in results:
        label = f"[cyan]{name}:[/cyan] " if name else ""
        if result.skipped:
            console.print(f"  [dim]Skipped:[/dim] {label}{result.message}")
        elif result.success:
            console.print(f"  [green]Done:[/green] {label}{result.message}")
            any_changed = True
        else:
            console.print(f"  [red]Error:[/red] {label}{result.error}")
            any_error = True

    if any_error:
        raise SystemExit(1)

    if any_changed:
        _validate_and_prompt_reload_for_restrict(yes)


# ---------------------------------------------------------------------------
# Cluster peers (SBUS manifest)
# ---------------------------------------------------------------------------


@waf.group("cluster", invoke_without_command=True)
@click.pass_context
def waf_cluster(ctx):
    """Allowlist this server's SBUS cluster peers.

    \b
    Cluster members deliver SBUS events to each other over HTTP, often from
    public IPs. Without an allowlist, mod_evasive can mistake a burst of
    events for a flood; SBUS retries the denied deliveries, so the block
    keeps itself going. Peers come from the SBusClusterManifest in sbus.ini
    and are written to mod_evasive, the ModSecurity exclusions and the
    admin-UI restrictions.
    """
    if ctx.invoked_subcommand is None:
        ctx.invoke(waf_cluster_show)


def _print_peer_table(title, peers, evasive_listed=None):
    from nssec.core.cluster import is_ipv4

    table = Table(title=title, show_header=True)
    table.add_column("IP")
    table.add_column("Host")
    if evasive_listed is not None:
        table.add_column("mod_evasive")
    for ip, host in peers.items():
        row = [ip, host]
        if evasive_listed is not None:
            if not is_ipv4(ip):
                row.append("[dim]n/a (IPv6)[/dim]")
            else:
                row.append(_yn(ip in evasive_listed))
        table.add_row(*row)
    console.print(table)


@waf_cluster.command("show")
def waf_cluster_show():
    """Show the cached cluster peers and what each config allowlists."""
    from nssec.modules.waf.cluster import (
        cached_cluster_peers,
        deployed_evasive_peers,
        deployed_exclusions_peers,
        evasive_drift,
        format_age,
    )
    from nssec.modules.waf.config import EVASIVE_CONF
    from nssec.modules.waf.utils import read_file

    cluster = cached_cluster_peers()
    if not cluster.peers:
        console.print("[yellow]No cluster peers cached.[/yellow]")
        console.print(f"Run [cyan]{sudo_hint('waf cluster refresh')}[/cyan] to discover them.")
        return

    console.print(f"[bold]Manifest:[/bold]   {cluster.manifest_url}")
    age = format_age(cluster.discovered_at)
    console.print(f"[bold]Discovered:[/bold] {cluster.discovered_at} ({age} ago)")
    console.print(f"[bold]Hosts:[/bold]      {', '.join(cluster.hosts)}")
    console.print()
    evasive_content = read_file(EVASIVE_CONF) or ""
    _print_peer_table(
        f"Cluster peers ({len(cluster.peers)})",
        cluster.peers,
        evasive_listed=deployed_evasive_peers(evasive_content),
    )
    console.print(f"ModSecurity exclusions allowlist {len(deployed_exclusions_peers())} of them.")
    drift = evasive_drift(cluster, evasive_content)
    if drift:
        console.print(
            f"[yellow]Warning:[/yellow] no mod_evasive entry for: {', '.join(drift)} "
            f"— run [cyan]{sudo_hint('waf cluster refresh')}[/cyan]"
        )


@waf_cluster.command("refresh")
@click.option("--dry-run", is_flag=True, help="Show the peer changes without writing anything")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompts")
@click.option(
    "--no-public-ip-lookup",
    is_flag=True,
    help="Do not add this server's public IP (from api.ipify.org) to the peers.",
)
@click.option(
    "--exclude-host",
    "exclude_hosts",
    multiple=True,
    metavar="PATTERN",
    help="Leave manifest hosts matching this glob out of the peers (repeatable).",
)
def waf_cluster_refresh(dry_run, yes, no_public_ip_lookup, exclude_hosts):
    """Re-discover cluster peers and rewrite every config that lists them.

    \b
    Shows the added/removed peers, rewrites mod_evasive, the ModSecurity
    exclusions and the admin-UI restrictions (whichever are deployed), runs
    apachectl configtest, and reloads Apache gracefully. A failed configtest
    puts all three files back exactly as they were.
    """
    from nssec.core.ssh import is_root
    from nssec.modules.waf import ModSecurityInstaller
    from nssec.modules.waf import restrict as restrict_mod
    from nssec.modules.waf.cluster import (
        SOURCE_DISCOVERED,
        deployed_evasive_peers,
        deployed_peers,
        diff_peers,
        resolve_cluster_peers,
    )
    from nssec.modules.waf.config import EVASIVE_CONF, NS_EXCLUSIONS_CONF
    from nssec.modules.waf.utils import file_exists, restore_snapshot, snapshot_files

    if not dry_run and not is_root():
        console.print(
            f"[red]Error:[/red] root required. Run: [cyan]{sudo_hint('waf cluster refresh')}[/cyan]"
        )
        raise SystemExit(1)

    console.print("[bold]Discovering SBUS cluster peers...[/bold]")
    cluster = resolve_cluster_peers(
        discover=True,
        lookup_public=not no_public_ip_lookup,
        exclude=exclude_hosts,
        save=False,
    )
    if cluster.source != SOURCE_DISCOVERED:
        for warning in cluster.warnings:
            console.print(f"  [red]Error:[/red] {warning}")
        console.print("Nothing changed; the deployed configs keep their current peers.")
        raise SystemExit(1)
    for warning in cluster.warnings:
        console.print(f"  [yellow]Warning:[/yellow] {warning}")
    console.print(
        f"  {len(cluster.peers)} peer IP(s) from {len(cluster.hosts)} host(s) "
        f"in {cluster.manifest_url}"
    )

    current = deployed_peers()
    added, removed = diff_peers(current, cluster.peers)
    console.print()
    for ip in added:
        console.print(f"  [green]+ {ip}[/green]  {cluster.peers[ip]}")
    for ip in removed:
        console.print(f"  [red]- {ip}[/red]  {current[ip]}")
    evasive_missing = (
        [ip for ip, _ in cluster.ipv4 if ip not in deployed_evasive_peers()]
        if file_exists(EVASIVE_CONF)
        else []
    )
    if not added and not removed and not evasive_missing:
        console.print("  No peer changes.")
    if cluster.ipv6:
        console.print(
            f"  [dim]{len(cluster.ipv6)} IPv6 address(es) go to ModSecurity and the "
            "restrictions only (DOSWhitelist is IPv4-only)[/dim]"
        )

    if dry_run:
        console.print("\n[yellow]Dry run — no changes made.[/yellow]")
        return

    restrict_path = restrict_mod.RESTRICT_CONF_PATH
    snapshot = snapshot_files([NS_EXCLUSIONS_CONF, EVASIVE_CONF, restrict_path])
    installer = ModSecurityInstaller()
    console.print()
    steps = []
    if file_exists(NS_EXCLUSIONS_CONF):
        steps.append(lambda: installer.install_exclusions(cluster=cluster))
    steps.append(lambda: installer.refresh_evasive_cluster(cluster))
    steps.append(lambda: restrict_mod.rerender_with_cluster(cluster))
    for step in steps:
        result = step()
        _print_step(result)
        if not result.success:
            restore_snapshot(snapshot)
            console.print("Restored the previous configs.")
            raise SystemExit(1)

    val = installer.validate_config(snapshot=snapshot)
    if not val.success:
        console.print(f"  [red]Error:[/red] {val.error}")
        raise SystemExit(1)
    console.print(f"  [green]Done:[/green] {val.message}")

    from nssec.core.cluster import save_cached_cluster
    from nssec.modules.waf.cluster import as_discovery

    if not save_cached_cluster(as_discovery(cluster)):
        console.print("  [yellow]Warning:[/yellow] could not write the cluster peer cache")

    _prompt_and_reload_apache(installer, yes)
