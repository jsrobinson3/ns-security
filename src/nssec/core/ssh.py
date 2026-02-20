"""SSH remote execution for running audits on remote servers.

This module provides SSH-based execution of commands and file reads,
allowing nssec to audit remote NetSapiens servers.

Usage:
    from nssec.core.ssh import SSHExecutor, set_remote_host

    # Set the remote host for all subsequent operations
    set_remote_host("ubuntu@development-core")

    # Now all checks will run via SSH
    nssec audit run
"""

import subprocess
from pathlib import Path
from typing import Optional

# Global remote host - when set, all commands execute via SSH
_remote_host: Optional[str] = None


def set_remote_host(host: Optional[str]) -> None:
    """Set the remote host for SSH execution.

    Args:
        host: SSH host string (e.g., "user@hostname" or "hostname").
              Set to None to disable SSH and run locally.
    """
    global _remote_host
    _remote_host = host


def get_remote_host() -> Optional[str]:
    """Get the current remote host, or None if running locally."""
    return _remote_host


def is_remote() -> bool:
    """Check if we're configured to run remotely."""
    return _remote_host is not None


class SSHExecutor:
    """Execute commands and read files over SSH."""

    def __init__(self, host: str, timeout: int = 30):
        """Initialize SSH executor.

        Args:
            host: SSH host string (e.g., "user@hostname").
            timeout: Default timeout for SSH commands in seconds.
        """
        self.host = host
        self.timeout = timeout
        # SSH options for non-interactive, reliable execution
        self.ssh_opts = [
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "StrictHostKeyChecking=accept-new",
        ]

    def run_command(
        self,
        cmd: list[str],
        timeout: Optional[int] = None,
    ) -> tuple[str, str, int]:
        """Run a command on the remote host via SSH.

        Args:
            cmd: Command and arguments to run.
            timeout: Timeout in seconds (uses default if not specified).

        Returns:
            Tuple of (stdout, stderr, return_code).
        """
        if timeout is None:
            timeout = self.timeout

        # Build SSH command
        # Quote the remote command properly
        remote_cmd = " ".join(_shell_quote(arg) for arg in cmd)
        ssh_cmd = ["ssh"] + self.ssh_opts + [self.host, remote_cmd]

        try:
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", f"SSH command timed out after {timeout}s", -1
        except Exception as e:
            return "", str(e), -1

    def read_file(self, path: str) -> Optional[str]:
        """Read a file from the remote host.

        Args:
            path: Path to the file on the remote host.

        Returns:
            File contents, or None if file doesn't exist or can't be read.
        """
        stdout, stderr, rc = self.run_command(["cat", path])
        if rc == 0:
            return stdout
        return None

    def file_exists(self, path: str) -> bool:
        """Check if a file exists on the remote host.

        Args:
            path: Path to check.

        Returns:
            True if file exists, False otherwise.
        """
        _, _, rc = self.run_command(["test", "-e", path])
        return rc == 0

    def is_directory(self, path: str) -> bool:
        """Check if a path is a directory on the remote host.

        Args:
            path: Path to check.

        Returns:
            True if path is a directory, False otherwise.
        """
        _, _, rc = self.run_command(["test", "-d", path])
        return rc == 0

    def test_connection(self) -> tuple[bool, str]:
        """Test the SSH connection.

        Returns:
            Tuple of (success, message).
        """
        stdout, stderr, rc = self.run_command(["echo", "ok"])
        if rc == 0 and "ok" in stdout:
            return True, f"Connected to {self.host}"
        return False, f"Failed to connect: {stderr}"


def _shell_quote(s: str) -> str:
    """Quote a string for shell execution.

    Args:
        s: String to quote.

    Returns:
        Shell-quoted string.
    """
    # If the string is simple (alphanumeric, dash, underscore, dot, slash),
    # no quoting needed
    if s and all(c.isalnum() or c in "-_./=" for c in s):
        return s
    # Otherwise, use single quotes and escape any single quotes in the string
    return "'" + s.replace("'", "'\"'\"'") + "'"


# Global executor instance (created when remote host is set)
_executor: Optional[SSHExecutor] = None


def get_executor() -> Optional[SSHExecutor]:
    """Get the global SSH executor, or None if running locally."""
    global _executor
    if _remote_host and _executor is None:
        _executor = SSHExecutor(_remote_host)
    elif not _remote_host:
        _executor = None
    return _executor


def run_command(cmd: list[str], timeout: int = 30) -> tuple[str, str, int]:
    """Run a command locally or remotely depending on configuration.

    This is a drop-in replacement for subprocess-based command execution
    that transparently handles SSH when a remote host is configured.

    Args:
        cmd: Command and arguments to run.
        timeout: Timeout in seconds.

    Returns:
        Tuple of (stdout, stderr, return_code).
    """
    executor = get_executor()
    if executor:
        return executor.run_command(cmd, timeout)

    # Local execution
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", -1
    except Exception as e:
        return "", str(e), -1


def read_file(path: str) -> Optional[str]:
    """Read a file locally or remotely depending on configuration.

    Args:
        path: Path to the file.

    Returns:
        File contents, or None if file doesn't exist or can't be read.
    """
    executor = get_executor()
    if executor:
        return executor.read_file(path)

    # Local read
    try:
        return Path(path).read_text()
    except (FileNotFoundError, PermissionError, OSError):
        return None


def file_exists(path: str) -> bool:
    """Check if a file exists locally or remotely.

    Args:
        path: Path to check.

    Returns:
        True if file exists, False otherwise.
    """
    executor = get_executor()
    if executor:
        return executor.file_exists(path)

    return Path(path).exists()


def is_directory(path: str) -> bool:
    """Check if a path is a directory locally or remotely.

    Args:
        path: Path to check.

    Returns:
        True if path is a directory, False otherwise.
    """
    executor = get_executor()
    if executor:
        return executor.is_directory(path)

    return Path(path).is_dir()
