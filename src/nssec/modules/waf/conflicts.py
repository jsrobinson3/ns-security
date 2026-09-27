"""Find ModSecurity rule ids that would collide with the CRS nssec installs.

ModSecurity refuses to start when two loaded rules share an id, so rules
loaded from files nssec does not manage must be checked before init adds
the CRS includes.
"""

from __future__ import annotations

import re
from typing import Callable

from nssec.modules.waf.config import APACHE2_CONF, APACHE_SERVER_ROOT, CRS_RESERVED_ID_RANGE
from nssec.modules.waf.types import RuleConflict
from nssec.modules.waf.utils import read_file, run_cmd

# "  (*) /etc/apache2/apache2.conf" or "    (146) /etc/apache2/mods-enabled/x.load"
_DUMP_LINE = re.compile(r"^\s*\((?:\*|\d+)\)\s+(\S.*?)\s*$")
_INCLUDE = re.compile(r"^\s*Include(?:Optional)?\s+(.+?)\s*$", re.IGNORECASE)
_RULE_ID = re.compile(r"(?<![\w.])id\s*:\s*'?(\d+)")
_WILDCARD = re.compile(r"[*?\[]")


def parse_dump_includes(output: str) -> list[str]:
    """Config file paths from ``apache2ctl -t -D DUMP_INCLUDES`` output.

    Each file is on its own line: "(*) path" for the root config, "(N) path"
    for a file included from line N of its parent, indented by nesting level.
    """
    matches = (_DUMP_LINE.match(line) for line in output.splitlines())
    return [m.group(1) for m in matches if m]


def _directive_lines(content: str) -> list[str]:
    """Non-comment lines, with backslash continuations joined as Apache does."""
    lines: list[str] = []
    pending = ""
    for raw in content.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        lines.append(pending + line)
        pending = ""
    if pending:
        lines.append(pending)
    return [line for line in lines if not line.lstrip().startswith("#")]


def parse_include_directives(content: str) -> list[str]:
    """Targets of the Include/IncludeOptional directives in a config file."""
    targets = []
    for line in _directive_lines(content):
        m = _INCLUDE.match(line)
        if m:
            targets.append(m.group(1).strip("\"'"))
    return targets


def extract_rule_ids(content: str) -> set[int]:
    """Rule ids ("id:NNN") set on non-comment lines of a ModSecurity config."""
    ids: set[int] = set()
    for line in _directive_lines(content):
        ids.update(int(rule_id) for rule_id in _RULE_ID.findall(line))
    return ids


def expand_config_path(pattern: str) -> list[str]:
    """Files an Include target names: a file, a directory (recursively), or a glob.

    SSH-aware: expanded with ``find`` on the target host.
    """
    parts = pattern.split("/")
    fixed = next((i for i, part in enumerate(parts) if _WILDCARD.search(part)), len(parts))
    cmd = ["find", "-L", "/".join(parts[:fixed]) or "/"]
    if fixed < len(parts):
        depth = str(len(parts) - fixed)
        cmd += ["-mindepth", depth, "-maxdepth", depth, "-path", pattern]
    stdout, _, _ = run_cmd(cmd + ["-type", "f"])
    return sorted(line for line in stdout.splitlines() if line.strip())


def resolve_includes(
    patterns: list[str],
    read: Callable[[str], str | None],
    expand: Callable[[str], list[str]],
) -> list[str]:
    """Every file loaded by following Include directives from ``patterns``.

    Relative targets resolve against ServerRoot. Files come back in load
    order, each once.
    """
    files: list[str] = []

    def visit(pattern: str) -> None:
        if not pattern.startswith("/"):
            pattern = f"{APACHE_SERVER_ROOT}/{pattern}"
        for path in expand(pattern):
            if path in files:
                continue
            files.append(path)
            for target in parse_include_directives(read(path) or ""):
                visit(target)

    for pattern in patterns:
        visit(pattern)
    return files


def list_loaded_configs() -> list[str]:
    """Every config file Apache loads.

    Asks Apache itself first; if that fails (e.g. the current config does
    not parse), follows the Include directives from apache2.conf instead.
    """
    stdout, _, rc = run_cmd(["apache2ctl", "-t", "-D", "DUMP_INCLUDES"])
    files = parse_dump_includes(stdout) if rc == 0 else []
    return files or resolve_includes([APACHE2_CONF], read_file, expand_config_path)


def read_crs_rule_ids(crs_path: str) -> set[int]:
    """Rule ids defined in a CRS install's rules/*.conf (empty if unreadable)."""
    paths = expand_config_path(f"{crs_path}/rules/*.conf")
    if not paths:
        return set()
    stdout, _, _ = run_cmd(["cat"] + paths)
    return extract_rule_ids(stdout)


def find_rule_conflicts(files: dict[str, str], crs_ids: set[int] | None) -> list[RuleConflict]:
    """Files (path -> content) whose rule ids collide with ``crs_ids``.

    ``crs_ids`` None means the CRS to be installed is not on disk yet, so any
    id in the reserved CRS range counts as a collision.
    """
    low, high = CRS_RESERVED_ID_RANGE
    conflicts = []
    for path, content in files.items():
        ids = extract_rule_ids(content)
        if crs_ids is None:
            clashing = {rule_id for rule_id in ids if low <= rule_id <= high}
        else:
            clashing = ids & crs_ids
        if clashing:
            conflicts.append(RuleConflict(path=path, ids=sorted(clashing)))
    return conflicts


def describe_conflict(conflict: RuleConflict, examples: int = 3) -> str:
    """One-line summary of a conflict for preflight output."""
    sample = ", ".join(str(rule_id) for rule_id in conflict.ids[:examples])
    more = ", ..." if len(conflict.ids) > examples else ""
    return (
        f"{conflict.path} defines {len(conflict.ids)} rule id(s) that collide with "
        f"OWASP CRS (e.g. {sample}{more})"
    )
