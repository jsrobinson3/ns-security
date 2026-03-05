"""mTLS management CLI commands for nssec."""

from __future__ import annotations

import click

from nssec.cli import console


@click.group(invoke_without_command=True)
@click.pass_context
def mtls(ctx):
    """Manage mTLS device provisioning for NetSapiens NDP servers.

    Requires mTLSProtect to be installed. See:
    https://github.com/OITApps/mTLSProtect
    """
    if ctx.invoked_subcommand is None:
        console.print("[bold]mTLS Management[/bold]\n")
        console.print("  Manages IP allowlists in the mTLSProtect configuration")
        console.print("  so monitoring and trusted IPs are not blocked by")
        console.print("  client certificate requirements.\n")
        console.print("[bold]Allowlist Commands:[/bold]")
        console.print("  [cyan]nssec mtls allowlist show[/cyan]      Show all whitelisted IPs")
        console.print("  [cyan]nssec mtls allowlist add[/cyan]       Add an IP to the allowlist")
        console.print(
            "  [cyan]nssec mtls allowlist remove[/cyan]    Remove an IP from the allowlist"
        )
        console.print()
        console.print("[bold]NodePing Commands:[/bold]")
        console.print("  [cyan]nssec mtls nodeping show[/cyan]       Show current NodePing IPs")
        console.print(
            "  [cyan]nssec mtls nodeping fetch[/cyan]      Fetch IPs from NodePing (dry run)"
        )
        console.print("  [cyan]nssec mtls nodeping update[/cyan]     Fetch and apply NodePing IPs")
        console.print("  [cyan]nssec mtls nodeping remove[/cyan]     Remove NodePing IPs section")


@mtls.group("nodeping", invoke_without_command=True)
@click.pass_context
def mtls_nodeping(ctx):
    """Manage NodePing monitoring IPs in mTLS config."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(nodeping_show)


@mtls_nodeping.command("show")
def nodeping_show():
    """Show current NodePing IPs in ndp_mtls.conf."""
    from nssec.modules.mtls import get_current_nodeping_ips
    from nssec.modules.mtls.config import NDP_MTLS_CONF
    from nssec.modules.mtls.utils import file_exists

    if not file_exists(NDP_MTLS_CONF):
        console.print(f"[yellow]mTLS config not found:[/yellow] {NDP_MTLS_CONF}")
        console.print("[dim]Is mTLSProtect installed?[/dim]")
        return

    ips = get_current_nodeping_ips()
    if not ips:
        console.print("[dim]No NodePing IPs currently configured.[/dim]")
        console.print("\nTo add NodePing IPs, run:")
        console.print("  [cyan]sudo nssec mtls nodeping update[/cyan]")
        return

    _display_ip_list(ips, "NodePing IPs")


@mtls_nodeping.command("fetch")
def nodeping_fetch():
    """Fetch and display NodePing IPs (dry run, no changes)."""
    from nssec.modules.mtls.utils import fetch_nodeping_ips

    console.print("[bold]Fetching NodePing IPs...[/bold]")
    ips, error = fetch_nodeping_ips()

    if error:
        console.print(f"[red]Error:[/red] {error}")
        raise SystemExit(1)

    console.print(f"\n[green]Fetched {len(ips)} IPs from NodePing[/green]\n")
    _display_ip_list(ips, "Available IPs")

    console.print("\n[dim]This was a dry run. To apply, run:[/dim]")
    console.print("  [cyan]sudo nssec mtls nodeping update[/cyan]")


def _require_root(command_path: str) -> None:
    """Exit with error if not running as root."""
    from nssec.core.ssh import is_root

    if not is_root():
        console.print(f"[red]Error: Must run as root (sudo nssec mtls {command_path})[/red]")
        raise SystemExit(1)


def _validate_and_reload(yes: bool) -> None:
    """Validate Apache config and optionally reload."""
    from nssec.modules.mtls import reload_apache, rollback, validate_apache_config
    from nssec.modules.mtls.config import NDP_MTLS_CONF

    val_result = validate_apache_config()
    if not val_result.success:
        console.print(f"  [red]Error:[/red] {val_result.error}")
        console.print("[yellow]Rolling back changes...[/yellow]")
        rollback(NDP_MTLS_CONF)
        raise SystemExit(1)
    console.print(f"  [green]Done:[/green] {val_result.message}")

    console.print()
    if yes or click.confirm("Reload Apache to apply changes?"):
        reload_result = reload_apache()
        if reload_result.success:
            console.print(f"  [green]Done:[/green] {reload_result.message}")
        else:
            console.print(f"  [red]Error:[/red] {reload_result.error}")
            raise SystemExit(1)
    else:
        console.print("[yellow]Skipped Apache reload. Run manually:[/yellow]")
        console.print("  [cyan]sudo systemctl reload apache2[/cyan]")


@mtls_nodeping.command("update")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompts")
@click.option("--dry-run", is_flag=True, help="Show what would be done without changes")
def nodeping_update(yes, dry_run):
    """Fetch NodePing IPs and update ndp_mtls.conf."""
    from nssec.modules.mtls import update_nodeping_ips

    _require_root("nodeping update")
    console.print("[bold]Updating NodePing IPs...[/bold]")

    result = update_nodeping_ips(dry_run=dry_run)

    if result.skipped:
        console.print(f"[green]{result.message}[/green]")
        return

    if not result.success:
        console.print(f"[red]Error:[/red] {result.error}")
        raise SystemExit(1)

    console.print(f"  [green]Done:[/green] {result.message}")

    if dry_run:
        console.print("\n[yellow]Dry run - no changes made.[/yellow]")
        return

    _validate_and_reload(yes)


@mtls_nodeping.command("remove")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
def nodeping_remove(yes):
    """Remove NodePing IPs section from ndp_mtls.conf."""
    from nssec.modules.mtls import remove_nodeping_ips

    _require_root("nodeping remove")

    console.print(
        "[bold yellow]Warning:[/bold yellow] This will remove all NodePing IPs from mTLS config."
    )
    console.print()

    if not yes and not click.confirm("Remove NodePing IPs section?"):
        console.print("[yellow]Aborted.[/yellow]")
        return

    result = remove_nodeping_ips()

    if result.skipped:
        console.print(f"[dim]{result.message}[/dim]")
        return

    if not result.success:
        console.print(f"[red]Error:[/red] {result.error}")
        raise SystemExit(1)

    console.print(f"  [green]Done:[/green] {result.message}")
    _validate_and_reload(yes)


def _display_ip_list(ips: list[str], title: str) -> None:
    """Display a list of IPs grouped by version."""
    ipv4 = [ip for ip in ips if ":" not in ip]
    ipv6 = [ip for ip in ips if ":" in ip]

    console.print(f"[bold]{title}[/bold] ({len(ips)} total)\n")

    if ipv4:
        console.print(f"[cyan]IPv4[/cyan] ({len(ipv4)}):")
        for ip in sorted(ipv4):
            console.print(f"  {ip}")

    if ipv6:
        console.print(f"\n[cyan]IPv6[/cyan] ({len(ipv6)}):")
        for ip in sorted(ipv6):
            console.print(f"  {ip}")


# --- Allowlist commands ---


@mtls.group("allowlist", invoke_without_command=True)
@click.pass_context
def mtls_allowlist(ctx):
    """Manage IP allowlist in mTLS config."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(allowlist_show)


@mtls_allowlist.command("show")
def allowlist_show():
    """Show all whitelisted IPs in ndp_mtls.conf."""
    from nssec.modules.mtls import get_allowlist_ips
    from nssec.modules.mtls.config import NDP_MTLS_CONF
    from nssec.modules.mtls.utils import file_exists

    if not file_exists(NDP_MTLS_CONF):
        console.print(f"[yellow]mTLS config not found:[/yellow] {NDP_MTLS_CONF}")
        console.print("[dim]Is mTLSProtect installed?[/dim]")
        return

    entries = get_allowlist_ips()
    if not entries:
        console.print("[dim]No IPs currently in allowlist.[/dim]")
        console.print("\nTo add an IP, run:")
        console.print("  [cyan]sudo nssec mtls allowlist add <IP>[/cyan]")
        return

    manual = [e["ip"] for e in entries if not e["managed"]]
    managed = [e["ip"] for e in entries if e["managed"]]

    if manual:
        _display_ip_list(manual, "Manual Allowlist IPs")

    if managed:
        if manual:
            console.print()
        _display_ip_list(managed, "NodePing IPs (auto-managed)")
        console.print("\n[dim]NodePing IPs are managed via 'nssec mtls nodeping update'[/dim]")

    if not manual and not managed:
        console.print("[dim]No IPs currently in allowlist.[/dim]")


@mtls_allowlist.command("add")
@click.argument("ip")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompts")
def allowlist_add(ip, yes):
    """Add an IP to the mTLS allowlist.

    The IP will be added to the <RequireAny> block in ndp_mtls.conf,
    allowing it to bypass client certificate requirements.
    """
    from nssec.core.validators import validate_ip_address
    from nssec.modules.mtls import add_allowlist_ip

    _require_root("allowlist add")

    try:
        validate_ip_address(ip)
    except ValueError:
        console.print(f"[red]Error:[/red] '{ip}' is not a valid IP address")
        raise SystemExit(1)

    console.print(f"Adding [bold]{ip}[/bold] to mTLS allowlist...")

    result = add_allowlist_ip(ip)
    if not result.success:
        console.print(f"[red]Error:[/red] {result.error}")
        raise SystemExit(1)

    console.print(f"  [green]Done:[/green] {result.message}")
    _validate_and_reload(yes)


@mtls_allowlist.command("remove")
@click.argument("ip")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompts")
def allowlist_remove(ip, yes):
    """Remove an IP from the mTLS allowlist.

    Only manually-added IPs can be removed. NodePing IPs are managed
    separately via 'nssec mtls nodeping'.
    """
    from nssec.modules.mtls import remove_allowlist_ip

    _require_root("allowlist remove")

    if not yes and not click.confirm(f"Remove {ip} from mTLS allowlist?"):
        console.print("[yellow]Aborted.[/yellow]")
        return

    result = remove_allowlist_ip(ip)
    if not result.success:
        console.print(f"[red]Error:[/red] {result.error}")
        raise SystemExit(1)

    console.print(f"  [green]Done:[/green] {result.message}")
    _validate_and_reload(yes)
