"""WAF/ModSecurity CLI commands for nssec."""

import click
from rich.table import Table

from nssec.cli import console
from nssec.core.validators import validate_ip_address, validate_ip_network


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
        table.add_row("mod_evasive", "", "install if missing")

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
        console.print(f"[red]Error: Must run as root ({command_hint})[/red]")
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


def _yn(val, false_color="red"):
    """Format a boolean as a colored yes/no string."""
    return "[green]yes[/green]" if val else f"[{false_color}]no[/{false_color}]"


def _build_status_table(status):
    """Build and return the WAF status Rich table."""
    table = Table(show_header=False, padding=(0, 2))
    table.add_column("Property", style="cyan")
    table.add_column("Value")

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
    else:
        table.add_row("OWASP CRS", "[red]not installed[/red]")

    table.add_row("NS exclusions", _yn(status.exclusions_present, "yellow"))
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
def waf_init(mode, skip_evasive, yes, dry_run):
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

    console.print()
    result = installer.run()
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
    else:
        console.print(f"[red]Error: {result.error}[/red]")
        raise SystemExit(1)


@waf.command("update-exclusions")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be done without making changes",
)
def waf_update_exclusions(yes, dry_run):
    """Re-deploy NetSapiens WAF exclusion rules.

    Updates /etc/modsecurity/netsapiens-exclusions.conf from the latest
    nssec templates without re-running the full waf init.
    """
    from nssec.modules.waf import ModSecurityInstaller

    installer = ModSecurityInstaller(dry_run=dry_run)
    pf = installer.preflight()
    _require_root_and_modsec(pf, "sudo nssec waf update-exclusions")

    console.print("[bold]Updating NetSapiens WAF exclusions...[/bold]")

    result = installer.install_exclusions()
    if not result.success:
        console.print(f"  [red]Error:[/red] {result.error}")
        raise SystemExit(1)
    console.print(f"  [green]Done:[/green] {result.message}")

    if dry_run:
        console.print("\n[yellow]Dry run \u2014 no further changes.[/yellow]")
        return

    val = installer.validate_config()
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


@waf.group("rules")
def waf_rules():
    """Manage ModSecurity rules."""
    pass


@waf_rules.command("list")
def waf_rules_list():
    """List available rule sets."""
    console.print("[bold]Available Rule Sets[/bold]\n")
    console.print("[yellow]Rule listing not yet implemented.[/yellow]")


@waf_rules.command("enable")
@click.argument("ruleset")
def waf_rules_enable(ruleset):
    """Enable a rule set."""
    console.print(f"[bold]Enabling rule set: {ruleset}[/bold]")
    console.print("[yellow]Rule management not yet implemented.[/yellow]")


@waf.group("allowlist")
def waf_allowlist():
    """Manage IP allowlist."""
    pass


@waf_allowlist.command("show")
def waf_allowlist_show():
    """Show current allowlisted IPs."""
    from nssec.modules.waf import get_allowlisted_ips

    ips = get_allowlisted_ips()
    if not ips:
        console.print("[dim]No IPs currently allowlisted.[/dim]")
        return

    console.print(f"[bold]Allowlisted IPs[/bold] ({len(ips)})\n")
    for ip in ips:
        console.print(f"  {ip}")


def _validate_ip_or_cidr(ip):
    """Validate an IP address or CIDR notation string."""
    try:
        if "/" in ip:
            validate_ip_network(ip)
        else:
            validate_ip_address(ip)
    except ValueError as e:
        raise click.BadParameter(str(e))


@waf_allowlist.command("add")
@click.argument("ip")
def waf_allowlist_add(ip):
    """Add IP to allowlist."""
    _validate_ip_or_cidr(ip)
    console.print(f"[bold]Adding {ip} to allowlist...[/bold]")
    console.print("[yellow]Allowlist management not yet implemented.[/yellow]")


@waf_allowlist.command("remove")
@click.argument("ip")
def waf_allowlist_remove(ip):
    """Remove IP from allowlist."""
    _validate_ip_or_cidr(ip)
    console.print(f"[bold]Removing {ip} from allowlist...[/bold]")
    console.print("[yellow]Allowlist management not yet implemented.[/yellow]")
