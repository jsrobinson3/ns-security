"""Main CLI entry point for nssec."""

import click
from rich.table import Table

from nssec import __version__
from nssec.cli import ALLOWED_CONFIG_DIRS, console, validate_path
from nssec.core.server_types import (
    ServerType,
    detect_server_type,
    get_applicable_security_modules,
    get_server_info,
)


@click.group()
@click.version_option(version=__version__, prog_name="nssec")
@click.pass_context
def cli(ctx):
    """NS-Security: Open-source NetSapiens security platform.

    Audit tools and hardening automation for NetSapiens clusters.
    """
    ctx.ensure_object(dict)


# ─── SERVER COMMANDS ───


@cli.group()
def server():
    """Server management and detection commands."""
    pass


def _print_detection_results(info):
    """Print component and active-service tables."""
    if info["components"]:
        comp_table = Table(title="Detected Components")
        comp_table.add_column("Component", style="cyan")
        comp_table.add_column("Description")
        comp_table.add_column("Package")
        comp_table.add_column("Service", style="green")

        for name, comp in info["components"].items():
            if not comp["service"]:
                status = "[dim]N/A[/dim]"
            elif comp["active"]:
                status = "[green]Active[/green]"
            else:
                status = "[yellow]Inactive[/yellow]"
            comp_table.add_row(name, comp["description"], comp["package"], status)

        console.print(comp_table)

    if info["active_services"]:
        console.print(f"\n[bold]Active Services:[/bold] {len(info['active_services'])}")
        for svc in info["active_services"][:10]:
            console.print(f"  - {svc}")
        if len(info["active_services"]) > 10:
            console.print(f"  ... and {len(info['active_services']) - 10} more")


@server.command("detect")
@click.option(
    "--host",
    "-H",
    help="Remote host to detect via SSH (e.g., user@hostname)",
)
def server_detect(host):
    """Detect the NetSapiens server type."""
    from nssec.core.cache import session_cache
    from nssec.core.ssh import SSHExecutor, set_remote_host

    if host:
        console.print(f"[bold]Connecting to {host}...[/bold]")
        executor = SSHExecutor(host)
        success, message = executor.test_connection()
        if not success:
            console.print(f"[red]SSH connection failed: {message}[/red]")
            raise SystemExit(1)
        console.print(f"[green]{message}[/green]\n")
        set_remote_host(host)
        session_cache.clear()

    info = get_server_info()

    table = Table(title="NetSapiens Server Detection")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Server Type", info["server_type"].upper())
    table.add_row("Is Combo", "Yes" if info["is_combo"] else "No")
    console.print(table)

    _print_detection_results(info)

    modules = get_applicable_security_modules()
    console.print(f"\n[bold]Applicable Security Modules:[/bold] {', '.join(modules)}")


@server.command("info")
def server_info():
    """Show detailed server security status."""
    get_server_info()
    server_type = detect_server_type()

    console.print(f"\n[bold cyan]Server Type:[/bold cyan] {server_type.value.upper()}")

    if server_type == ServerType.UNKNOWN:
        console.print(
            "\n[yellow]Warning:[/yellow] No NetSapiens components detected. "
            "This tool is designed for NetSapiens servers."
        )
        return

    modules = get_applicable_security_modules(server_type)
    console.print("\n[bold]Security modules for this server:[/bold]")
    for module in modules:
        console.print(f"  - {module}")


# ─── INIT COMMAND ───


@cli.command()
@click.option(
    "--config-dir",
    default="/etc/nssec",
    help="Directory for configuration files",
)
def init(config_dir):
    """Initialize nssec configuration."""
    from nssec.core.config import create_default_config

    config_path = validate_path(
        config_dir,
        param_name="--config-dir",
        allowed_bases=ALLOWED_CONFIG_DIRS,
    )

    server_type = detect_server_type()

    console.print("[bold]Initializing nssec configuration...[/bold]")
    console.print(f"  Server type: {server_type.value}")
    console.print(f"  Config directory: {config_path}")

    try:
        create_default_config(config_path, server_type)
        console.print(f"\n[green]Configuration created at {config_path}/config.yaml[/green]")
    except PermissionError:
        console.print(
            "\n[red]Error:[/red] Permission denied. Try running with sudo:\n  sudo nssec init"
        )
    except Exception as e:
        console.print(f"\n[red]Error:[/red] {e}")


# ─── CERTIFICATE COMMANDS ───


@cli.group()
def certs():
    """Certificate management commands."""
    pass


@certs.command("status")
def certs_status():
    """Show certificate status."""
    console.print("[bold]Certificate Status[/bold]\n")
    console.print("[yellow]Certificate status check not yet implemented.[/yellow]")


@certs.command("sync")
def certs_sync():
    """Synchronize certificates across domains."""
    console.print("[bold]Synchronizing certificates...[/bold]")
    console.print("[yellow]Certificate sync not yet implemented.[/yellow]")


@certs.command("rekey")
@click.option("--domain", "-d", help="Specific domain to rekey")
def certs_rekey(domain):
    """Regenerate certificate keys."""
    if domain:
        console.print(f"[bold]Regenerating keys for {domain}...[/bold]")
    else:
        console.print("[bold]Regenerating all certificate keys...[/bold]")
    console.print("[yellow]Certificate rekeying not yet implemented.[/yellow]")


# ─── REGISTER SUB-COMMAND GROUPS ───

from nssec.cli.audit import audit  # noqa: E402
from nssec.cli.waf_commands import waf  # noqa: E402

cli.add_command(audit)
cli.add_command(waf)


if __name__ == "__main__":
    cli()
