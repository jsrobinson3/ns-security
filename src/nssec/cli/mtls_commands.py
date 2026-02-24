"""mTLS management CLI commands for nssec."""

import click

from nssec.cli import console


@click.group()
def mtls():
    """mTLS device provisioning management commands."""
    pass


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


def _require_root(command_name: str) -> None:
    """Exit with error if not running as root."""
    from nssec.core.ssh import is_root

    if not is_root():
        console.print(
            f"[red]Error: Must run as root (sudo nssec mtls nodeping {command_name})[/red]"
        )
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

    _require_root("update")
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

    _require_root("remove")

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
