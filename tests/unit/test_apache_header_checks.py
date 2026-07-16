"""Tests for the Apache security response headers check (APACHE-004)."""

from unittest.mock import patch

from nssec.core.checklist import CheckStatus

SECURITY_CONF = "/etc/apache2/conf-enabled/security.conf"


def _run_check(file_map):
    """Run APACHE-004 with file_exists/read_file backed by file_map."""
    from nssec.core.checks import ApacheSecurityHeadersCheck

    def fake_exists(path):
        return path in file_map

    def fake_read(path):
        return file_map.get(path)

    with (
        patch("nssec.core.checks.file_exists", side_effect=fake_exists),
        patch("nssec.core.checks.read_file", side_effect=fake_read),
    ):
        return ApacheSecurityHeadersCheck().run()


def test_all_headers_present_passes():
    content = (
        'Header unset X-Powered-By\n'
        'Header set X-Content-Type-Options "nosniff"\n'
    )
    result = _run_check({SECURITY_CONF: content})
    assert result.status == CheckStatus.PASS


def test_matching_is_case_insensitive_and_allows_always():
    content = (
        "HEADER UNSET X-Powered-By\n"
        'Header always set x-content-type-options "nosniff"\n'
    )
    result = _run_check({SECURITY_CONF: content})
    assert result.status == CheckStatus.PASS


def test_missing_x_powered_by_warns():
    content = 'Header set X-Content-Type-Options "nosniff"\n'
    result = _run_check({SECURITY_CONF: content})

    assert result.status == CheckStatus.WARN
    assert "X-Powered-By" in result.message
    assert "X-Content-Type-Options" not in result.message
    assert "Header unset X-Powered-By" in result.remediation


def test_missing_both_warns_and_lists_both():
    content = "# no security headers configured here\n"
    result = _run_check({SECURITY_CONF: content})

    assert result.status == CheckStatus.WARN
    assert "X-Powered-By" in result.message
    assert "X-Content-Type-Options" in result.message


def test_commented_directives_treated_as_missing():
    content = (
        "# Header unset X-Powered-By\n"
        '# Header set X-Content-Type-Options "nosniff"\n'
    )
    result = _run_check({SECURITY_CONF: content})
    assert result.status == CheckStatus.WARN


def test_falls_back_to_apache2_conf():
    content = (
        'Header unset X-Powered-By\n'
        'Header set X-Content-Type-Options "nosniff"\n'
    )
    result = _run_check({"/etc/apache2/apache2.conf": content})
    assert result.status == CheckStatus.PASS


def test_config_absent_skips():
    result = _run_check({})
    assert result.status == CheckStatus.SKIP


def test_unreadable_config_skips():
    # file_exists is True but read_file returns None (e.g. permission denied)
    result = _run_check({SECURITY_CONF: None})
    assert result.status == CheckStatus.SKIP
