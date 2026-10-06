"""A failed configtest during ``run()`` must restore this run's starting state.

Rollback used to copy every ``*.bak.nssec`` over its target. A step that is
skipped writes no backup, so a stale one from an earlier run overwrote a
working file.
"""

from unittest.mock import patch

import pytest

from nssec.modules.waf import ModSecurityInstaller
from nssec.modules.waf.types import PreflightResult, StepResult

STOCK = "stock security2.conf\n"
WIRED = "wired security2.conf\n"
OLD_EXCLUSIONS = "previous exclusions\n"
NEW_EXCLUSIONS = "new exclusions with a duplicate id\n"


@pytest.fixture
def host(tmp_path):
    paths = {
        "modsec": tmp_path / "modsecurity.conf",
        "sec2": tmp_path / "security2.conf",
        "excl": tmp_path / "netsapiens-exclusions.conf",
        "evasive": tmp_path / "evasive.conf",
    }
    paths["modsec"].write_text("modsec\n")
    paths["sec2"].write_text(WIRED)
    paths["excl"].write_text(OLD_EXCLUSIONS)
    paths["evasive"].write_text("evasive\n")
    # Left behind by an earlier run, before security2.conf was wired.
    (tmp_path / "security2.conf.bak.nssec").write_text(STOCK)
    return paths


def _run_with_failing_configtest(host):
    installer = ModSecurityInstaller()
    installer.preflight = lambda: PreflightResult(is_root=True, apache_installed=True)

    for name in (
        "install_packages",
        "enable_modules",
        "setup_config",
        "setup_evasive_config",
        "install_crs_v4",
    ):
        setattr(installer, name, lambda *a, **k: StepResult(message="ok"))
    installer.set_evasive_state = lambda enable: StepResult(message="ok")
    installer.write_security2_conf = lambda: StepResult(skipped=True, message="already wired")

    def write_new_exclusions(*args, **kwargs):
        host["excl"].write_text(NEW_EXCLUSIONS)
        return StepResult(message="wrote")

    installer.install_exclusions = write_new_exclusions

    patches = {
        "MODSEC_CONF": str(host["modsec"]),
        "SECURITY2_CONF": str(host["sec2"]),
        "NS_EXCLUSIONS_CONF": str(host["excl"]),
        "EVASIVE_CONF": str(host["evasive"]),
    }
    with patch.multiple("nssec.modules.waf", **patches), patch(
        "nssec.modules.waf.run_cmd", return_value=("", "configtest failed", 1)
    ):
        return installer.run()


def test_failed_configtest_reports_failure(host):
    result = _run_with_failing_configtest(host)
    assert result.success is False
    assert any("Apache config test failed" in e for e in result.errors)


def test_stale_backup_does_not_overwrite_a_skipped_security2(host):
    _run_with_failing_configtest(host)
    assert host["sec2"].read_text() == WIRED


def test_files_written_by_the_run_are_reverted(host):
    _run_with_failing_configtest(host)
    assert host["excl"].read_text() == OLD_EXCLUSIONS


def test_file_that_did_not_exist_is_removed(host):
    host["excl"].unlink()
    _run_with_failing_configtest(host)
    assert not host["excl"].exists()
