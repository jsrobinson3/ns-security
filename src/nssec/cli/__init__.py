"""CLI commands for nssec.

Shared utilities used by CLI sub-modules (audit, waf_commands, etc.).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click
from rich.console import Console

console = Console()


def _running_in_venv() -> bool:
    """Return True if nssec is running from a Python virtual environment."""
    return sys.prefix != sys.base_prefix or "VIRTUAL_ENV" in os.environ


def sudo_hint(command: str = "") -> str:
    """Return the correct privileged invocation for an nssec subcommand.

    When nssec is installed in a virtualenv, a plain ``sudo nssec ...`` fails
    with ``sudo: nssec: command not found`` because the venv's bin directory is
    not on root's PATH. In that case we preserve the caller's PATH into sudo's
    environment so the venv ``nssec`` resolves. Outside a venv (pipx / system
    install) the plain form works and is shown unchanged.

    Accepts a bare subcommand ("waf init") or a legacy full string
    ("sudo nssec waf init"), which is normalized -- so existing call sites that
    pass the whole hint keep working.
    """
    sub = command.strip()
    for prefix in ("sudo nssec", "nssec"):
        if sub.startswith(prefix):
            sub = sub[len(prefix) :].strip()
            break
    target = f"nssec {sub}".strip()
    if _running_in_venv():
        return f'sudo env "PATH=$PATH" {target}'
    return f"sudo {target}"


# Allowed directories for configuration files
ALLOWED_CONFIG_DIRS = (
    Path("/etc/nssec"),
    Path.home() / ".config" / "nssec",
    Path.cwd(),
)


def _is_within_allowed_bases(resolved: Path, bases: tuple[Path, ...]) -> bool:
    """Check if resolved path is within any of the allowed base directories."""
    for base in bases:
        try:
            base_resolved = base.resolve()
            if resolved == base_resolved or base_resolved in resolved.parents:
                return True
        except (OSError, ValueError):
            continue
    return False


def validate_path(
    path_str: str,
    param_name: str,
    allowed_bases: tuple[Path, ...] | None = None,
    must_be_within_cwd: bool = False,
) -> Path:
    """Validate a path to prevent path traversal attacks.

    Raises click.BadParameter if the path contains traversal components,
    is outside allowed base directories, or outside cwd when required.
    """
    try:
        resolved = Path(path_str).resolve()
    except (OSError, ValueError) as e:
        raise click.BadParameter(
            f"Invalid path: {e}",
            param_hint=f"'{param_name}'",
        )

    if ".." in Path(path_str).parts:
        raise click.BadParameter(
            "Path traversal is not allowed",
            param_hint=f"'{param_name}'",
        )

    if allowed_bases and not _is_within_allowed_bases(resolved, allowed_bases):
        allowed_str = ", ".join(str(b) for b in allowed_bases)
        raise click.BadParameter(
            f"Path must be within allowed locations: {allowed_str}",
            param_hint=f"'{param_name}'",
        )

    if must_be_within_cwd:
        cwd = Path.cwd().resolve()
        if resolved != cwd and cwd not in resolved.parents:
            raise click.BadParameter(
                f"Path must be within current working directory: {cwd}",
                param_hint=f"'{param_name}'",
            )

    return resolved
