"""Shared pytest fixtures for nssec tests."""

import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture
def mock_run_cmd():
    """Mock run_cmd to avoid executing real system commands."""
    with patch("nssec.modules.waf.utils.run_cmd") as mock:
        mock.return_value = ("", "", 0)
        yield mock


@pytest.fixture
def mock_file_ops():
    """Mock file operations for WAF module.

    Patches at the point of use (nssec.modules.waf) not definition (utils).
    """
    with patch("nssec.modules.waf.file_exists") as exists, \
         patch("nssec.modules.waf.read_file") as read, \
         patch("nssec.modules.waf.write_file") as write, \
         patch("nssec.modules.waf.backup_file") as backup, \
         patch("nssec.modules.waf.render") as render_mock:
        exists.return_value = True
        read.return_value = ""
        write.return_value = True
        backup.return_value = True
        render_mock.return_value = "rendered content"
        yield {
            "exists": exists,
            "read": read,
            "write": write,
            "backup": backup,
            "render": render_mock,
        }


@pytest.fixture
def mock_preflight():
    """Mock preflight result for CLI tests."""
    from nssec.modules.waf.types import PreflightResult

    pf = PreflightResult()
    pf.is_root = True
    pf.apache_installed = True
    pf.modsec_installed = True
    pf.modsec_enabled = True
    pf.modsec_mode = "On"
    return pf


@pytest.fixture
def cli_runner():
    """Click CLI test runner."""
    from click.testing import CliRunner
    return CliRunner()
