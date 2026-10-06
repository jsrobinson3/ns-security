"""A failed configtest during run() must restore every file it wrote."""

from unittest.mock import patch

import pytest

from nssec.modules.waf import ModSecurityInstaller
from nssec.modules.waf import utils as waf_utils
from nssec.modules.waf.types import PreflightResult, StepResult

CRS = "/opt/crs"

WIRED_SECURITY2 = f"""\
<IfModule security2_module>
    IncludeOptional /etc/modsecurity/*.conf
    IncludeOptional {CRS}/crs-setup.conf
    IncludeOptional {CRS}/rules/*.conf
</IfModule>
"""

STALE_STOCK_SECURITY2 = """\
<IfModule security2_module>
    IncludeOptional /etc/modsecurity/*.conf
    IncludeOptional /usr/share/modsecurity-crs/*.load
</IfModule>
"""

DEPLOYED_EXCLUSIONS = "# deployed exclusions\n"


@pytest.fixture
def files(tmp_path, monkeypatch):
    paths = {
        "security2": tmp_path / "security2.conf",
        "exclusions": tmp_path / "netsapiens-exclusions.conf",
        "modsec": tmp_path / "modsecurity.conf",
        "evasive": tmp_path / "evasive.conf",
    }
    paths["security2"].write_text(WIRED_SECURITY2)
    paths["exclusions"].write_text(DEPLOYED_EXCLUSIONS)
    # A backup left over from an earlier install, older than the wired file.
    (tmp_path / "security2.conf.bak.nssec").write_text(STALE_STOCK_SECURITY2)

    import nssec.modules.waf as waf

    monkeypatch.setattr(waf_utils, "SECURITY2_CONF", str(paths["security2"]))
    monkeypatch.setattr(waf, "SECURITY2_CONF", str(paths["security2"]))
    monkeypatch.setattr(waf, "NS_EXCLUSIONS_CONF", str(paths["exclusions"]))
    monkeypatch.setattr(waf, "MODSEC_CONF", str(paths["modsec"]))
    monkeypatch.setattr(waf, "EVASIVE_CONF", str(paths["evasive"]))
    return paths


def test_failed_configtest_restores_wired_security2_and_exclusions(files):
    installer = ModSecurityInstaller()
    pf = PreflightResult()
    pf.is_root = True
    pf.apache_installed = True
    pf.security2_has_wildcard = True
    pf.crs_path = CRS

    def rewrite_exclusions(*args, **kwargs):
        files["exclusions"].write_text("# new exclusions\n")
        return StepResult(message="wrote")

    ok = StepResult(message="ok")
    with patch.object(ModSecurityInstaller, "preflight", return_value=pf), patch.object(
        ModSecurityInstaller, "install_packages", return_value=ok
    ), patch.object(ModSecurityInstaller, "enable_modules", return_value=ok), patch.object(
        ModSecurityInstaller, "setup_config", return_value=ok
    ), patch.object(
        ModSecurityInstaller, "setup_evasive_config", return_value=ok
    ), patch.object(
        ModSecurityInstaller, "set_evasive_state", return_value=ok
    ), patch.object(
        ModSecurityInstaller, "install_crs_v4", return_value=ok
    ), patch.object(
        ModSecurityInstaller, "install_exclusions", side_effect=rewrite_exclusions
    ), patch(
        "nssec.modules.waf.run_cmd", return_value=("", "bad config", 1)
    ):
        result = installer.run()

    assert not result.success
    assert any("rolled back" in e for e in result.errors)
    assert files["security2"].read_text() == WIRED_SECURITY2
    assert files["exclusions"].read_text() == DEPLOYED_EXCLUSIONS
