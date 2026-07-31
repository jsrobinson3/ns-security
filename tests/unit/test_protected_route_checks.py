"""Tests for the admin-route IP restriction checks (APACHE-002/003, NS-002).

These checks must recognize the current Apache-config restriction method
(/etc/apache2/conf.d/nssec-restrict.conf) as protection, while still
crediting legacy / hand-written per-directory .htaccess files.
"""

from contextlib import ExitStack
from unittest.mock import patch

from nssec.core.checklist import CheckStatus
from nssec.modules.waf.config import RESTRICT_CONF_PATH

SIPBX_DIR = "/usr/local/NetSapiens/SiPbx/html/SiPbx"
NDP_DIR = "/usr/local/NetSapiens/ndp"
LICF_DIR = "/usr/local/NetSapiens/LiCf/html/LiCf"

RESTRICT_CONF_ALL = (
    "# Managed by nssec\n"
    '<LocationMatch "^/(SiPbx|ndp|LiCf)/">\n'
    "    <RequireAny>\n"
    "        Require ip 127.0.0.1\n"
    "        Require ip 203.0.113.10\n"
    "    </RequireAny>\n"
    "</LocationMatch>\n"
)

RESTRICT_CONF_SIPBX_ONLY = (
    "# Managed by nssec\n"
    '<LocationMatch "^/(SiPbx)/">\n'
    "    <RequireAny>\n"
    "        Require ip 127.0.0.1\n"
    "    </RequireAny>\n"
    "</LocationMatch>\n"
)

HTACCESS_LEGACY = "Order deny,allow\nDeny from all\nAllow from 203.0.113.10\n"


def _run(check_cls, files=None, dirs=None):
    """Run a check against a fake filesystem.

    Files are read through two paths: nssec.core.checks imports
    file_exists/is_directory/read_file directly, while file_contains and
    the waf restrict helpers go through nssec.core.ssh at call time.
    Patch both layers against the same maps.
    """
    files = files or {}
    dirs = set(dirs or [])

    def fake_exists(path):
        return path in files

    def fake_read(path):
        return files.get(path)

    def fake_is_dir(path):
        return path in dirs

    with ExitStack() as stack:
        for target, side_effect in [
            ("nssec.core.checks.file_exists", fake_exists),
            ("nssec.core.checks.read_file", fake_read),
            ("nssec.core.checks.is_directory", fake_is_dir),
            ("nssec.core.ssh.file_exists", fake_exists),
            ("nssec.core.ssh.read_file", fake_read),
            ("nssec.core.ssh.is_directory", fake_is_dir),
        ]:
            stack.enter_context(patch(target, side_effect=side_effect))
        return check_cls().run()


# ---------------------------------------------------------------------------
# APACHE-003 ProtectedRoutesCheck
# ---------------------------------------------------------------------------


def _run_apache_003(files=None, dirs=None):
    from nssec.core.checks import ProtectedRoutesCheck

    return _run(ProtectedRoutesCheck, files, dirs)


def test_apache_003_passes_with_restrict_conf():
    result = _run_apache_003(
        files={RESTRICT_CONF_PATH: RESTRICT_CONF_ALL},
        dirs=[SIPBX_DIR, NDP_DIR, LICF_DIR],
    )
    assert result.status == CheckStatus.PASS
    assert "SiPbx Admin UI" in result.message
    assert "NDP" in result.message
    assert "LiCf Recording" in result.message


def test_apache_003_fails_without_any_restrictions():
    result = _run_apache_003(dirs=[SIPBX_DIR, NDP_DIR])
    assert result.status == CheckStatus.FAIL
    assert "SiPbx Admin UI (no IP restrictions)" in result.message
    assert RESTRICT_CONF_PATH in result.remediation


def test_apache_003_fails_when_component_missing_from_conf():
    result = _run_apache_003(
        files={RESTRICT_CONF_PATH: RESTRICT_CONF_SIPBX_ONLY},
        dirs=[SIPBX_DIR, NDP_DIR],
    )
    assert result.status == CheckStatus.FAIL
    assert f"NDP (not covered by {RESTRICT_CONF_PATH})" in result.message


def test_apache_003_conf_without_ips_is_not_protection():
    conf = '<LocationMatch "^/(SiPbx)/">\n    <RequireAny>\n    </RequireAny>\n</LocationMatch>\n'
    result = _run_apache_003(
        files={RESTRICT_CONF_PATH: conf},
        dirs=[SIPBX_DIR],
    )
    assert result.status == CheckStatus.FAIL


def test_apache_003_credits_legacy_htaccess():
    result = _run_apache_003(
        files={f"{NDP_DIR}/.htaccess": HTACCESS_LEGACY},
        dirs=[NDP_DIR],
    )
    assert result.status == CheckStatus.PASS
    assert "legacy .htaccess" in result.message


def test_apache_003_htaccess_without_ip_directives_fails():
    result = _run_apache_003(
        files={f"{NDP_DIR}/.htaccess": "# nothing here\n"},
        dirs=[NDP_DIR],
    )
    assert result.status == CheckStatus.FAIL


def test_apache_003_mixed_conf_and_htaccess():
    result = _run_apache_003(
        files={
            RESTRICT_CONF_PATH: RESTRICT_CONF_SIPBX_ONLY,
            f"{NDP_DIR}/.htaccess": HTACCESS_LEGACY,
        },
        dirs=[SIPBX_DIR, NDP_DIR],
    )
    assert result.status == CheckStatus.PASS


def test_apache_003_skips_when_no_directories():
    result = _run_apache_003(files={RESTRICT_CONF_PATH: RESTRICT_CONF_ALL})
    assert result.status == CheckStatus.SKIP


# ---------------------------------------------------------------------------
# NS-002 AdminUIProtectionCheck
# ---------------------------------------------------------------------------


def _run_ns_002(files=None):
    from nssec.core.checks import AdminUIProtectionCheck

    return _run(AdminUIProtectionCheck, files)


def test_ns_002_passes_with_restrict_conf():
    result = _run_ns_002({RESTRICT_CONF_PATH: RESTRICT_CONF_ALL})
    assert result.status == CheckStatus.PASS
    assert RESTRICT_CONF_PATH in result.message


def test_ns_002_conf_without_sipbx_segment_is_not_protection():
    conf = RESTRICT_CONF_ALL.replace("SiPbx|ndp|LiCf", "ndp|LiCf")
    result = _run_ns_002({RESTRICT_CONF_PATH: conf})
    assert result.status == CheckStatus.WARN


def test_ns_002_passes_with_legacy_htaccess():
    result = _run_ns_002({f"{SIPBX_DIR}/.htaccess": HTACCESS_LEGACY})
    assert result.status == CheckStatus.PASS
    assert "legacy .htaccess" in result.message


def test_ns_002_fails_when_htaccess_has_no_ip_directives():
    result = _run_ns_002({f"{SIPBX_DIR}/.htaccess": "# empty\n"})
    assert result.status == CheckStatus.FAIL


def test_ns_002_warns_when_nothing_configured():
    result = _run_ns_002({})
    assert result.status == CheckStatus.WARN


# ---------------------------------------------------------------------------
# APACHE-002 ApacheHtaccessCheck
# ---------------------------------------------------------------------------


def _run_apache_002(files=None):
    from nssec.core.checks import ApacheHtaccessCheck

    return _run(ApacheHtaccessCheck, files)


def test_apache_002_skips_when_restrict_conf_active():
    result = _run_apache_002(
        {
            RESTRICT_CONF_PATH: RESTRICT_CONF_ALL,
            "/etc/apache2/apache2.conf": "AllowOverride None\n",
        }
    )
    assert result.status == CheckStatus.SKIP
    assert RESTRICT_CONF_PATH in result.message


def test_apache_002_still_warns_without_restrict_conf():
    result = _run_apache_002({"/etc/apache2/apache2.conf": "AllowOverride None\n"})
    assert result.status == CheckStatus.WARN


def test_apache_002_still_passes_without_restrict_conf():
    result = _run_apache_002({"/etc/apache2/apache2.conf": "AllowOverride All\n"})
    assert result.status == CheckStatus.PASS
