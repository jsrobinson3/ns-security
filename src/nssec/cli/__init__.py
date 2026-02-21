"""CLI commands for nssec.

Shared utilities used by CLI sub-modules (audit, waf_commands, etc.).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import click
from rich.console import Console

console = Console()

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
    allowed_bases: Optional[tuple[Path, ...]] = None,
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
