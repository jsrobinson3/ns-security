"""Security audit checklist engine."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from nssec.core import ssh


class Severity(Enum):
    """Severity level for audit findings."""

    CRITICAL = "critical"  # Immediate action required
    HIGH = "high"  # Should be fixed soon
    MEDIUM = "medium"  # Should be addressed
    LOW = "low"  # Nice to have
    INFO = "info"  # Informational only


class CheckStatus(Enum):
    """Status of an audit check."""

    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"
    ERROR = "error"


@dataclass
class CheckResult:
    """Result of a single audit check."""

    check_id: str
    name: str
    status: CheckStatus
    severity: Severity
    message: str
    details: Optional[str] = None
    remediation: Optional[str] = None
    reference: Optional[str] = None


@dataclass
class AuditReport:
    """Complete audit report."""

    server_type: str
    hostname: str
    results: list[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.status == CheckStatus.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if r.status == CheckStatus.FAIL)

    @property
    def warnings(self) -> int:
        return sum(1 for r in self.results if r.status == CheckStatus.WARN)

    @property
    def critical_issues(self) -> list[CheckResult]:
        return [
            r
            for r in self.results
            if r.status == CheckStatus.FAIL and r.severity == Severity.CRITICAL
        ]

    @property
    def high_issues(self) -> list[CheckResult]:
        return [
            r for r in self.results if r.status == CheckStatus.FAIL and r.severity == Severity.HIGH
        ]


class BaseCheck(ABC):
    """Base class for security checks."""

    check_id: str = ""
    name: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    applies_to: Optional[list[str]] = None  # Server types this check applies to
    reference: Optional[str] = None  # Documentation reference

    @abstractmethod
    def run(self) -> CheckResult:
        """Execute the check and return result."""
        pass

    def _pass(self, message: str, details: Optional[str] = None) -> CheckResult:
        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=CheckStatus.PASS,
            severity=self.severity,
            message=message,
            details=details,
            reference=self.reference,
        )

    def _fail(
        self, message: str, details: Optional[str] = None, remediation: Optional[str] = None
    ) -> CheckResult:
        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=CheckStatus.FAIL,
            severity=self.severity,
            message=message,
            details=details,
            remediation=remediation,
            reference=self.reference,
        )

    def _warn(
        self, message: str, details: Optional[str] = None, remediation: Optional[str] = None
    ) -> CheckResult:
        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=CheckStatus.WARN,
            severity=self.severity,
            message=message,
            details=details,
            remediation=remediation,
            reference=self.reference,
        )

    def _skip(self, message: str) -> CheckResult:
        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=CheckStatus.SKIP,
            severity=self.severity,
            message=message,
        )

    def _error(self, message: str, details: Optional[str] = None) -> CheckResult:
        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=CheckStatus.ERROR,
            severity=self.severity,
            message=message,
            details=details,
        )


def run_command(cmd: list[str], timeout: int = 30) -> tuple[Optional[str], Optional[str], int]:
    """Run a command locally or remotely (if SSH host is configured).

    Args:
        cmd: Command and arguments to run.
        timeout: Timeout in seconds.

    Returns:
        Tuple of (stdout, stderr, return_code).
    """
    stdout, stderr, rc = ssh.run_command(cmd, timeout)
    return stdout if stdout else None, stderr if stderr else None, rc


def _line_matches_pattern(line: str, pattern: str, ignore_comments: bool) -> bool:
    """Check if a line contains a pattern, optionally ignoring comments."""
    if ignore_comments and line.strip().startswith("#"):
        return False
    return pattern in line


def file_contains(path: Path, pattern: str, ignore_comments: bool = True) -> bool:
    """Check if a file contains a pattern (works locally or via SSH)."""
    content = ssh.read_file(str(path))
    if content is None:
        return False

    for line in content.splitlines():
        if _line_matches_pattern(line, pattern, ignore_comments):
            return True
    return False


def _extract_config_value(line: str, key: str, separator: str) -> Optional[str]:
    """Extract a value from a config line if it matches the key."""
    line = line.strip()
    if line.startswith("#"):
        return None
    if not line.startswith(key):
        return None
    parts = line.split(separator, 1)
    if len(parts) > 1:
        return parts[1].strip()
    return None


def get_file_value(path: Path, key: str, separator: str = " ") -> Optional[str]:
    """Get a configuration value from a file (works locally or via SSH)."""
    content = ssh.read_file(str(path))
    if content is None:
        return None

    for line in content.splitlines():
        value = _extract_config_value(line, key, separator)
        if value is not None:
            return value
    return None


def package_installed(package_name: str) -> bool:
    """Check if a package is installed via dpkg."""
    stdout, _, rc = run_command(["dpkg", "-l", package_name])
    return rc == 0 and stdout is not None and "ii" in stdout


def service_active(service_name: str) -> bool:
    """Check if a systemd service is active."""
    _, _, rc = run_command(["systemctl", "is-active", "--quiet", service_name])
    return rc == 0


def service_enabled(service_name: str) -> bool:
    """Check if a systemd service is enabled."""
    _, _, rc = run_command(["systemctl", "is-enabled", "--quiet", service_name])
    return rc == 0
