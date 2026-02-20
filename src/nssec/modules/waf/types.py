"""Data types for the WAF module."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class StepResult:
    """Result of a single installation step."""

    success: bool = True
    skipped: bool = False
    message: str = ""
    error: str = ""


@dataclass
class PreflightResult:
    """Result of preflight checks before installation."""

    is_root: bool = False
    apache_installed: bool = False
    apache_running: bool = False
    modsec_installed: bool = False
    modsec_enabled: bool = False
    modsec_mode: Optional[str] = None
    crs_installed: bool = False
    crs_version: Optional[str] = None
    crs_path: Optional[str] = None
    security2_has_wildcard: bool = False
    security2_has_crs_load: bool = False
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def can_proceed(self) -> bool:
        return self.is_root and self.apache_installed


@dataclass
class InstallResult:
    """Result of the full installation process."""

    success: bool = False
    mode: str = "DetectionOnly"
    steps_completed: list[str] = field(default_factory=list)
    steps_skipped: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
