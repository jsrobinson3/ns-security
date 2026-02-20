"""Audit CLI commands for nssec."""

import html
import json
import socket
from datetime import datetime

import click
from rich.table import Table

from nssec.cli import console, validate_path
from nssec.core.server_types import ServerType, detect_server_type


@click.group()
def audit():
    """Security audit commands."""
    pass


_STATUS_ICONS = {
    "pass": "[green]\u2713[/green]",
    "fail": "[red]\u2717[/red]",
    "warn": "[yellow]![/yellow]",
    "skip": "[dim]-[/dim]",
    "error": "[red]E[/red]",
}

_SEVERITY_COLORS = {
    "critical": "red bold",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

_CATEGORY_PREFIXES = {
    "apiban": "APIBAN-",
    "firewall": "FW-",
    "ssh": "SSH-",
    "mysql": "MYSQL-",
    "netsapiens": "NS-",
}


def _print_failed_checks(checks):
    """Print failed checks with severity and remediation."""
    for r in checks:
        color = _SEVERITY_COLORS.get(r.severity.value, "white")
        icon = _STATUS_ICONS[r.status.value]
        console.print(
            f"  {icon} [{color}][{r.severity.value.upper()}][/{color}] {r.check_id}: {r.name}"
        )
        console.print(f"      {r.message}")
        if r.details:
            console.print(f"      [dim]{r.details}[/dim]")
        if r.remediation:
            console.print(f"      [green]Fix:[/green] {r.remediation}")


def _print_simple_checks(checks, show_message=False, verbose_extras=False):
    """Print checks with optional message and verbose detail lines."""
    for r in checks:
        icon = _STATUS_ICONS[r.status.value]
        label = f"{r.check_id}: {r.name}"
        if show_message:
            label += f" - {r.message}"
        console.print(f"  {icon} {label}")
        if verbose_extras:
            if r.details:
                console.print(f"      [dim]{r.details}[/dim]")
            if r.remediation:
                console.print(f"      [green]Fix:[/green] {r.remediation}")


def _display_check_results(results, verbose):
    """Display grouped audit check results.

    Returns (failed, warnings, passed, skipped) lists.
    """
    from nssec.core.checklist import CheckStatus

    failed = [r for r in results if r.status == CheckStatus.FAIL]
    warnings = [r for r in results if r.status == CheckStatus.WARN]
    passed = [r for r in results if r.status == CheckStatus.PASS]
    skipped = [r for r in results if r.status in (CheckStatus.SKIP, CheckStatus.ERROR)]

    if failed:
        console.print("[bold red]FAILED CHECKS[/bold red]")
        _print_failed_checks(failed)
        console.print()

    if warnings:
        console.print("[bold yellow]WARNINGS[/bold yellow]")
        _print_simple_checks(warnings, verbose_extras=verbose)
        console.print()

    if verbose and passed:
        console.print("[bold green]PASSED[/bold green]")
        _print_simple_checks(passed)
        console.print()

    if verbose and skipped:
        console.print("[bold dim]SKIPPED[/bold dim]")
        _print_simple_checks(skipped, show_message=True)
        console.print()

    return failed, warnings, passed, skipped


def _display_audit_summary(failed, warnings, passed, skipped, results):
    """Display the audit summary table and critical issues warning."""
    from nssec.core.checklist import Severity

    table = Table(title="Audit Summary")
    table.add_column("Status", style="bold")
    table.add_column("Count", justify="right")

    table.add_row("[red]Failed[/red]", str(len(failed)))
    table.add_row("[yellow]Warnings[/yellow]", str(len(warnings)))
    table.add_row("[green]Passed[/green]", str(len(passed)))
    table.add_row("[dim]Skipped[/dim]", str(len(skipped)))
    table.add_row("[bold]Total[/bold]", str(len(results)))

    console.print(table)

    critical = [r for r in failed if r.severity == Severity.CRITICAL]
    if critical:
        console.print(
            f"\n[bold red]\u26a0 {len(critical)} CRITICAL issue(s) "
            f"require immediate attention![/bold red]"
        )


def _connect_remote_host(host):
    """Set up SSH connection to a remote host for auditing."""
    from nssec.core.cache import session_cache
    from nssec.core.ssh import SSHExecutor, set_remote_host

    console.print(f"[bold]Connecting to {host}...[/bold]")
    executor = SSHExecutor(host)
    success, message = executor.test_connection()
    if not success:
        console.print(f"[red]SSH connection failed: {message}[/red]")
        raise SystemExit(1)
    console.print(f"[green]{message}[/green]\n")
    set_remote_host(host)
    session_cache.clear()


def _filter_checks(applicable, category, checks, skip):
    """Apply category, include, and exclude filters to check list."""
    if category:
        prefix = _CATEGORY_PREFIXES.get(category, "")
        applicable = [c for c in applicable if c.check_id.startswith(prefix)]
    if checks:
        applicable = [c for c in applicable if c.check_id in checks]
    if skip:
        applicable = [c for c in applicable if c.check_id not in skip]
    return applicable


@audit.command("run")
@click.option(
    "--host",
    "-H",
    help="Remote host to audit via SSH (e.g., user@hostname)",
)
@click.option(
    "--checks",
    "-c",
    multiple=True,
    help="Specific check IDs to run (e.g., SSH-001)",
)
@click.option("--skip", "-s", multiple=True, help="Check IDs to skip")
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Show all checks including passed",
)
@click.option(
    "--category",
    type=click.Choice(["apiban", "firewall", "ssh", "mysql", "netsapiens"]),
    help="Run only checks in category",
)
def audit_run(host, checks, skip, verbose, category):
    """Run a full security audit.

    Use --host to audit a remote server via SSH:
        nssec audit run --host ubuntu@myserver.example.com
    """
    from nssec.core.checks import get_checks_for_server_type

    if host:
        _connect_remote_host(host)

    server_type = detect_server_type()
    console.print(f"[bold]Security Audit - {server_type.value.upper()} Server[/bold]\n")

    if server_type == ServerType.UNKNOWN:
        console.print(
            "[yellow]Warning: No NetSapiens installation detected. Running basic checks.[/yellow]\n"
        )

    applicable = get_checks_for_server_type(server_type.value)
    applicable = _filter_checks(applicable, category, checks, skip)

    results = []
    for check in applicable:
        try:
            results.append(check.run())
        except Exception as e:
            console.print(f"[red]Error running {check.check_id}: {e}[/red]")

    groups = _display_check_results(results, verbose)
    _display_audit_summary(*groups, results)


# ─── REPORT GENERATION ───


def _collect_check_results(server_type):
    """Run all checks and collect serializable result dicts."""
    from nssec.core.checks import get_checks_for_server_type

    applicable = get_checks_for_server_type(server_type.value)
    results = []

    for check in applicable:
        try:
            result = check.run()
            entry = {
                "check_id": result.check_id,
                "name": result.name,
                "status": result.status.value,
                "severity": result.severity.value,
                "message": result.message,
                "details": result.details,
                "remediation": result.remediation,
            }
        except Exception as e:
            entry = {
                "check_id": check.check_id,
                "name": check.name,
                "status": "error",
                "severity": check.severity.value,
                "message": str(e),
            }
        results.append(entry)

    return results


@audit.command("report")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["html", "json", "md"]),
    default="json",
    help="Output format",
)
@click.option("--output", "-o", help="Output file path")
def audit_report(output_format, output):
    """Generate a security audit report."""
    if output:
        validate_path(output, param_name="--output", must_be_within_cwd=True)

    server_type = detect_server_type()
    hostname = socket.gethostname()
    results = _collect_check_results(server_type)

    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "hostname": hostname,
        "server_type": server_type.value,
        "summary": {
            "total": len(results),
            "passed": sum(1 for r in results if r["status"] == "pass"),
            "failed": sum(1 for r in results if r["status"] == "fail"),
            "warnings": sum(1 for r in results if r["status"] == "warn"),
            "skipped": sum(1 for r in results if r["status"] in ("skip", "error")),
        },
        "results": results,
    }

    formatters = {
        "json": lambda: json.dumps(report, indent=2),
        "md": lambda: _generate_markdown_report(report),
        "html": lambda: _generate_html_report(report),
    }
    output_text = formatters[output_format]()

    if output:
        with open(output, "w") as f:
            f.write(output_text)
        console.print(f"[green]Report saved to {output}[/green]")
    else:
        console.print(output_text)


def _md_failed_section(results: list) -> list:
    """Build markdown lines for failed checks section."""
    failed = [r for r in results if r["status"] == "fail"]
    if not failed:
        return []
    lines = ["## Failed Checks", ""]
    for r in failed:
        lines.append(f"### {r['check_id']}: {r['name']}")
        lines.append(f"- **Severity:** {r['severity'].upper()}")
        lines.append(f"- **Message:** {r['message']}")
        if r.get("details"):
            lines.append(f"- **Details:** {r['details']}")
        if r.get("remediation"):
            lines.append(f"- **Remediation:** `{r['remediation']}`")
        lines.append("")
    return lines


def _generate_markdown_report(report: dict) -> str:
    s = report["summary"]
    lines = [
        "# NetSapiens Security Audit Report",
        "",
        f"**Generated:** {report['generated_at']}",
        f"**Hostname:** {report['hostname']}",
        f"**Server Type:** {report['server_type']}",
        "",
        "## Summary",
        "",
        "| Status | Count |",
        "|--------|-------|",
        f"| Passed | {s['passed']} |",
        f"| Failed | {s['failed']} |",
        f"| Warnings | {s['warnings']} |",
        f"| Skipped | {s['skipped']} |",
        f"| **Total** | **{s['total']}** |",
        "",
    ]
    lines.extend(_md_failed_section(report["results"]))
    return "\n".join(lines)


_HTML_STYLE = (
    "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI',"
    " Roboto, sans-serif; max-width: 900px; margin: 0 auto;"
    " padding: 20px; }\n"
    "h1 { color: #333; }\n"
    ".summary { display: flex; gap: 20px; margin: 20px 0; }\n"
    ".stat { padding: 15px 25px; border-radius: 8px;"
    " text-align: center; }\n"
    ".stat.failed { background: #fee; color: #c00; }\n"
    ".stat.passed { background: #efe; color: #080; }\n"
    ".stat.warnings { background: #ffe; color: #a80; }\n"
    ".check { padding: 15px; margin: 10px 0; border-radius: 8px;"
    " border-left: 4px solid; }\n"
    ".check.fail { background: #fee; border-color: #c00; }\n"
    ".check.warn { background: #ffe; border-color: #a80; }\n"
    ".severity { padding: 2px 8px; border-radius: 4px; font-size: 12px;"
    " font-weight: bold; }\n"
    ".severity.critical { background: #c00; color: white; }\n"
    ".severity.high { background: #e44; color: white; }\n"
    ".severity.medium { background: #fa0; color: white; }\n"
    ".details { color: #666; font-size: 14px; }\n"
    ".remediation code { background: #f0f0f0; padding: 2px 6px;"
    " border-radius: 4px; }"
)


def _html_check_card(r: dict, h) -> str:
    """Render a single failed check as an HTML card."""
    details = f"<p class='details'>{h(r['details'])}</p>" if r.get("details") else ""
    remediation = (
        f"<p class='remediation'><strong>Fix:</strong> <code>{h(r['remediation'])}</code></p>"
        if r.get("remediation")
        else ""
    )
    return (
        f'<div class="check fail">'
        f"<h3>{h(r['check_id'])}: {h(r['name'])}</h3>"
        f'<span class="severity {h(r["severity"])}">'
        f"{h(r['severity'].upper())}</span>"
        f"<p>{h(r['message'])}</p>"
        f"{details}{remediation}</div>"
    )


def _generate_html_report(report: dict) -> str:
    """Generate HTML format report."""
    h = html.escape
    failed = [r for r in report["results"] if r["status"] == "fail"]
    cards = "\n".join(_html_check_card(r, h) for r in failed)
    issues = cards if cards else "<p>No failed checks!</p>"

    hostname = h(report["hostname"])
    server_type = h(report["server_type"])
    generated = h(report["generated_at"])
    s = report["summary"]

    return (
        f"<!DOCTYPE html>\n<html>\n<head>\n"
        f"<title>NetSapiens Security Audit - {hostname}</title>\n"
        f"<style>{_HTML_STYLE}</style>\n"
        f"</head>\n<body>\n"
        f"<h1>NetSapiens Security Audit Report</h1>\n"
        f"<p><strong>Hostname:</strong> {hostname} | "
        f"<strong>Type:</strong> {server_type} | "
        f"<strong>Generated:</strong> {generated}</p>\n"
        f'<div class="summary">\n'
        f'<div class="stat failed">'
        f"<strong>{s['failed']}</strong><br>Failed</div>\n"
        f'<div class="stat warnings">'
        f"<strong>{s['warnings']}</strong><br>Warnings</div>\n"
        f'<div class="stat passed">'
        f"<strong>{s['passed']}</strong><br>Passed</div>\n"
        f"</div>\n"
        f"<h2>Issues</h2>\n{issues}\n"
        f"</body>\n</html>"
    )
