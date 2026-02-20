"""Session-level caching for expensive operations.

This module provides caching for subprocess calls (dpkg, systemctl) and file reads
to improve performance during security audits. The cache is designed to be cleared
between audit runs.

Works transparently over SSH when a remote host is configured.

Usage:
    from nssec.core.cache import session_cache

    # Check if package is installed (uses cache)
    if session_cache.cached_package_installed("nginx"):
        ...

    # Clear cache between runs
    session_cache.clear()
"""

import threading
import time
from pathlib import Path
from typing import Optional, Union

from nssec.core import ssh


def _run_subprocess(cmd: list[str], timeout: int = 30) -> tuple[str, int]:
    """Run a subprocess command safely (locally or via SSH).

    Args:
        cmd: Command and arguments to run.
        timeout: Timeout in seconds.

    Returns:
        Tuple of (stdout, return_code). Returns ("", -1) on error.
    """
    stdout, _, rc = ssh.run_command(cmd, timeout)
    return stdout, rc


def _parse_dpkg_line(line: str) -> Optional[str]:
    """Parse a dpkg -l output line to extract package name if installed.

    Args:
        line: A single line from dpkg -l output.

    Returns:
        Package name if line indicates installed package, None otherwise.
    """
    if not (line.startswith("ii ") or line.startswith("ii\t")):
        return None
    parts = line.split()
    if len(parts) < 2:
        return None
    # Package name may include architecture suffix like "package:amd64"
    return parts[1].split(":")[0]


def _parse_service_line(line: str) -> tuple[Optional[str], Optional[str]]:
    """Parse a systemctl list-units output line to extract service names.

    Args:
        line: A single line from systemctl list-units output.

    Returns:
        Tuple of (service_name_without_suffix, full_unit_name), or (None, None).
    """
    parts = line.split()
    if not parts:
        return None, None
    service_unit = parts[0]
    service_name = service_unit.removesuffix(".service")
    return service_name, service_unit


def _read_ufw_files() -> str:
    """Read UFW rules from config files (locally or via SSH).

    Returns:
        Combined content from UFW rule files, or empty string if unreadable.
    """
    ufw_files = [
        "/etc/ufw/user.rules",
        "/etc/ufw/user6.rules",
    ]
    content = ""
    for rules_file in ufw_files:
        file_content = _safe_read_file(rules_file)
        if file_content:
            content += file_content
    return content


def _safe_read_file(path: Union[str, Path]) -> Optional[str]:
    """Safely read a file, returning None on any error (locally or via SSH).

    Args:
        path: Path to the file.

    Returns:
        File contents or None if file cannot be read.
    """
    return ssh.read_file(str(path))


class SessionCache:
    """Session-level cache for expensive operations.

    Caches results of subprocess calls (dpkg, systemctl) and file contents
    to avoid repeated expensive operations during a single audit session.

    Attributes:
        ttl: Time-to-live in seconds. 0 means no automatic expiry (default).
             Cache entries older than TTL are considered stale and refreshed.
    """

    def __init__(self, ttl: float = 0) -> None:
        """Initialize the session cache.

        Args:
            ttl: Time-to-live in seconds for cache entries.
                 0 means no automatic expiry (manual clear() required).
        """
        self._ttl = ttl
        self._lock = threading.RLock()

        # Package (dpkg) cache
        self._dpkg_loaded: bool = False
        self._dpkg_installed: dict[str, bool] = {}
        self._dpkg_time: float = 0

        # Service (systemctl) cache
        self._active_services: Optional[set[str]] = None
        self._services_time: float = 0

        # File content cache
        self._files: dict[str, Optional[str]] = {}
        self._file_times: dict[str, float] = {}

        # UFW rules cache
        self._ufw_rules: Optional[str] = None
        self._ufw_rules_loaded: bool = False
        self._ufw_time: float = 0

    def _is_expired(self, cache_time: float) -> bool:
        """Check if a cache entry has expired based on TTL."""
        if self._ttl <= 0:
            return False
        return (time.time() - cache_time) > self._ttl

    def clear(self) -> None:
        """Clear all cached data.

        Call this between audit runs to ensure fresh data.
        """
        with self._lock:
            self._clear_dpkg_cache()
            self._clear_services_cache()
            self._clear_files_cache()
            self._clear_ufw_cache()

    def _clear_dpkg_cache(self) -> None:
        """Clear dpkg cache (internal, no lock)."""
        self._dpkg_loaded = False
        self._dpkg_installed.clear()
        self._dpkg_time = 0

    def _clear_services_cache(self) -> None:
        """Clear services cache (internal, no lock)."""
        self._active_services = None
        self._services_time = 0

    def _clear_files_cache(self) -> None:
        """Clear files cache (internal, no lock)."""
        self._files.clear()
        self._file_times.clear()

    def _clear_ufw_cache(self) -> None:
        """Clear UFW cache (internal, no lock)."""
        self._ufw_rules = None
        self._ufw_rules_loaded = False
        self._ufw_time = 0

    def invalidate_files(self) -> None:
        """Invalidate only the file cache."""
        with self._lock:
            self._clear_files_cache()

    def invalidate_packages(self) -> None:
        """Invalidate only the package cache."""
        with self._lock:
            self._clear_dpkg_cache()

    def invalidate_services(self) -> None:
        """Invalidate only the service cache."""
        with self._lock:
            self._clear_services_cache()

    def invalidate_ufw(self) -> None:
        """Invalidate only the UFW rules cache."""
        with self._lock:
            self._clear_ufw_cache()

    def _load_dpkg_cache(self) -> None:
        """Load all installed packages into cache by running dpkg -l once."""
        stdout, rc = _run_subprocess(["dpkg", "-l"])
        self._dpkg_time = time.time()
        self._dpkg_loaded = True

        if rc != 0:
            return

        for line in stdout.splitlines():
            pkg_name = _parse_dpkg_line(line)
            if pkg_name:
                self._dpkg_installed[pkg_name] = True

    def cached_package_installed(self, package_name: str) -> bool:
        """Check if a package is installed using cached dpkg data.

        On first call, runs `dpkg -l` once and caches all package statuses.
        Subsequent calls query the cache directly.

        Args:
            package_name: Name of the package to check.

        Returns:
            True if the package is installed, False otherwise.
        """
        with self._lock:
            if not self._dpkg_loaded or self._is_expired(self._dpkg_time):
                self._load_dpkg_cache()
            return self._dpkg_installed.get(package_name, False)

    def _load_services_cache(self) -> None:
        """Load all active services into cache by running systemctl once."""
        cmd = [
            "systemctl",
            "list-units",
            "--type=service",
            "--state=active",
            "--no-legend",
            "--plain",
        ]
        stdout, rc = _run_subprocess(cmd)
        self._services_time = time.time()
        self._active_services = set()

        if rc != 0:
            return

        for line in stdout.splitlines():
            service_name, service_unit = _parse_service_line(line)
            if service_name:
                self._active_services.add(service_name)
            if service_unit:
                self._active_services.add(service_unit)

    def cached_service_active(self, service_name: str) -> bool:
        """Check if a systemd service is active using cached data.

        On first call, runs `systemctl list-units` once and caches all active services.
        Subsequent calls query the cache directly.

        Args:
            service_name: Name of the service to check (with or without .service suffix).

        Returns:
            True if the service is active, False otherwise.
        """
        with self._lock:
            if self._active_services is None or self._is_expired(self._services_time):
                self._load_services_cache()

            normalized = service_name.removesuffix(".service")
            return (
                normalized in self._active_services
                or f"{normalized}.service" in self._active_services
            )

    def cached_file_read(self, path: Union[str, Path]) -> Optional[str]:
        """Read file contents with caching.

        Caches file contents by path. Subsequent reads return cached content
        until cache is cleared or TTL expires.

        Args:
            path: Path to the file to read.

        Returns:
            File contents as string, or None if file cannot be read.
        """
        path_str = str(path)

        with self._lock:
            is_cached, content = self._get_valid_cached_file(path_str)
            if is_cached:
                return content
            return self._load_and_cache_file(path, path_str)

    def _get_valid_cached_file(self, path_str: str) -> tuple[bool, Optional[str]]:
        """Get cached file content if valid and not expired.

        Args:
            path_str: String path used as cache key.

        Returns:
            Tuple of (is_cached, content). is_cached is True if we have a valid
            cache entry (even if content is None for unreadable files).
        """
        if path_str not in self._files:
            return False, None
        if self._is_expired(self._file_times.get(path_str, 0)):
            return False, None
        return True, self._files[path_str]

    def _load_and_cache_file(self, path: Union[str, Path], path_str: str) -> Optional[str]:
        """Load a file and store it in cache (internal, called with lock held).

        Args:
            path: Original path argument.
            path_str: String version of the path for cache key.

        Returns:
            File contents or None if unreadable.
        """
        path_obj = Path(path) if isinstance(path, str) else path
        content = _safe_read_file(path_obj)
        self._files[path_str] = content
        self._file_times[path_str] = time.time()
        return content

    def cached_ufw_rules(self) -> Optional[str]:
        """Read UFW rules from config files with caching.

        Reads UFW rules from /etc/ufw/user.rules and /etc/ufw/user6.rules.
        Falls back to `ufw status` command if files are not readable.

        Returns:
            Combined UFW rules content, or None if rules cannot be read.
        """
        with self._lock:
            if self._ufw_rules_loaded and not self._is_expired(self._ufw_time):
                return self._ufw_rules
            return self._load_ufw_rules()

    def _load_ufw_rules(self) -> Optional[str]:
        """Load UFW rules into cache (internal, called with lock held).

        Returns:
            UFW rules content or None.
        """
        # Try reading from files first
        content = _read_ufw_files()
        if content:
            return self._cache_ufw_result(content)

        # Fallback to ufw status command
        stdout, rc = _run_subprocess(["ufw", "status"])
        if rc == 0 and stdout:
            return self._cache_ufw_result(stdout)

        return self._cache_ufw_result(None)

    def _cache_ufw_result(self, content: Optional[str]) -> Optional[str]:
        """Store UFW result in cache and return it.

        Args:
            content: UFW rules content or None.

        Returns:
            The same content passed in.
        """
        self._ufw_rules = content
        self._ufw_rules_loaded = True
        self._ufw_time = time.time()
        return content

    def get_stats(self) -> dict[str, int]:
        """Get cache statistics for debugging/monitoring.

        Returns:
            Dictionary with counts of cached items.
        """
        with self._lock:
            services_count = len(self._active_services) if self._active_services else 0
            return {
                "packages_cached": len(self._dpkg_installed),
                "services_cached": services_count,
                "files_cached": len(self._files),
                "ufw_cached": 1 if self._ufw_rules_loaded else 0,
            }


# Singleton instance for session-level caching
session_cache = SessionCache()


# Convenience functions that use the singleton cache
def cached_package_installed(package_name: str) -> bool:
    """Check if a package is installed (uses session cache).

    This is a convenience wrapper around session_cache.cached_package_installed().

    Args:
        package_name: Name of the package to check.

    Returns:
        True if the package is installed, False otherwise.
    """
    return session_cache.cached_package_installed(package_name)


def cached_service_active(service_name: str) -> bool:
    """Check if a systemd service is active (uses session cache).

    This is a convenience wrapper around session_cache.cached_service_active().

    Args:
        service_name: Name of the service to check.

    Returns:
        True if the service is active, False otherwise.
    """
    return session_cache.cached_service_active(service_name)


def cached_file_read(path: Union[str, Path]) -> Optional[str]:
    """Read file contents with caching (uses session cache).

    This is a convenience wrapper around session_cache.cached_file_read().

    Args:
        path: Path to the file to read.

    Returns:
        File contents as string, or None if file cannot be read.
    """
    return session_cache.cached_file_read(path)


def cached_ufw_rules() -> Optional[str]:
    """Read UFW rules with caching (uses session cache).

    This is a convenience wrapper around session_cache.cached_ufw_rules().

    Returns:
        Combined UFW rules content, or None if rules cannot be read.
    """
    return session_cache.cached_ufw_rules()
