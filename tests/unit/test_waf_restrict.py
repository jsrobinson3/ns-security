"""Tests for WAF restrict module functions (Apache-config method)."""

import json
from unittest.mock import patch

from jinja2 import Template


class TestLoadCachedIps:
    """Tests for load_cached_ips function."""

    def test_returns_ips_from_cache(self):
        from nssec.modules.waf.restrict import load_cached_ips

        cache = json.dumps({"ips": ["127.0.0.1", "10.0.0.1"]})
        with patch("nssec.modules.waf.restrict.read_file", return_value=cache):
            assert load_cached_ips() == ["127.0.0.1", "10.0.0.1"]

    def test_returns_empty_when_no_cache(self):
        from nssec.modules.waf.restrict import load_cached_ips

        with patch("nssec.modules.waf.restrict.read_file", return_value=None):
            assert load_cached_ips() == []

    def test_returns_empty_on_invalid_json(self):
        from nssec.modules.waf.restrict import load_cached_ips

        with patch("nssec.modules.waf.restrict.read_file", return_value="not json"):
            assert load_cached_ips() == []


class TestSaveCachedIps:
    """Tests for save_cached_ips function."""

    def test_saves_ips_to_json(self):
        from nssec.modules.waf.restrict import save_cached_ips

        with patch("nssec.modules.waf.restrict.write_file", return_value=True) as mock_write:
            result = save_cached_ips(["127.0.0.1", "10.0.0.1"])

        assert result is True
        written_content = mock_write.call_args[0][1]
        assert json.loads(written_content)["ips"] == ["127.0.0.1", "10.0.0.1"]


class TestGetApplicableComponents:
    """Tests for get_applicable_components function."""

    def test_core_server_gets_sipbx_only(self):
        """Core gets SiPbx; ns-api is intentionally not restricted."""
        from nssec.modules.waf.restrict import get_applicable_components

        with patch("nssec.modules.waf.restrict.is_directory", return_value=True):
            components = get_applicable_components("core")

        names = [c["name"] for c in components]
        assert names == ["SiPbx Admin UI"]

    def test_ndp_server_gets_ndp(self):
        from nssec.modules.waf.restrict import get_applicable_components

        with patch("nssec.modules.waf.restrict.is_directory", return_value=True):
            components = get_applicable_components("ndp")

        assert [c["segment"] for c in components] == ["ndp"]

    def test_recording_server_gets_licf(self):
        from nssec.modules.waf.restrict import get_applicable_components

        with patch("nssec.modules.waf.restrict.is_directory", return_value=True):
            components = get_applicable_components("recording")

        assert [c["segment"] for c in components] == ["LiCf"]

    def test_combo_server_gets_all_three(self):
        from nssec.modules.waf.restrict import get_applicable_components

        with patch("nssec.modules.waf.restrict.is_directory", return_value=True):
            components = get_applicable_components("combo")

        assert [c["segment"] for c in components] == ["SiPbx", "ndp", "LiCf"]

    def test_filters_by_directory_existence(self):
        from nssec.modules.waf.restrict import get_applicable_components

        def mock_is_dir(path):
            return "/SiPbx" in path

        with patch("nssec.modules.waf.restrict.is_directory", side_effect=mock_is_dir):
            components = get_applicable_components("combo")

        assert [c["segment"] for c in components] == ["SiPbx"]

    def test_unknown_server_type_returns_empty(self):
        from nssec.modules.waf.restrict import get_applicable_components

        with patch("nssec.modules.waf.restrict.is_directory", return_value=True):
            assert get_applicable_components("unknown") == []


class TestParseIps:
    """Tests for parse_ips function."""

    def test_parses_require_ip_lines(self):
        from nssec.modules.waf.restrict import parse_ips

        content = """\
<RequireAny>
    Require ip 127.0.0.1
    Require ip 192.168.1.100
    Require ip 10.0.0.0/8
</RequireAny>
"""
        with patch("nssec.modules.waf.restrict.read_file", return_value=content):
            assert parse_ips("/some/path") == ["127.0.0.1", "192.168.1.100", "10.0.0.0/8"]

    def test_ignores_commented_placeholder_lines(self):
        from nssec.modules.waf.restrict import parse_ips

        content = (
            "# Example, replace with your IP:\n"
            "# Require ip <ADMIN-IP>\n"
            "Require ip 207.45.79.249\n"
            "# Allow from <YOUR-IP>\n"
        )
        with patch("nssec.modules.waf.restrict.read_file", return_value=content):
            ips = parse_ips("/fake/.htaccess")
        assert ips == ["207.45.79.249"]
        assert "<ADMIN-IP>" not in ips

    def test_returns_empty_for_missing_file(self):
        from nssec.modules.waf.restrict import parse_ips

        with patch("nssec.modules.waf.restrict.read_file", return_value=None):
            assert parse_ips("/nonexistent") == []

    def test_parses_legacy_allow_from_lines(self):
        from nssec.modules.waf.restrict import parse_ips

        content = "Order deny,allow\nAllow from 192.168.1.100\nAllow from 10.0.0.0/8\n"
        with patch("nssec.modules.waf.restrict.read_file", return_value=content):
            assert parse_ips("/some/path") == ["192.168.1.100", "10.0.0.0/8"]

    def test_deduplicates_ips_across_syntaxes(self):
        from nssec.modules.waf.restrict import parse_ips

        content = "Require ip 192.168.1.100\nAllow from 192.168.1.100\nAllow from 10.0.0.1\n"
        with patch("nssec.modules.waf.restrict.read_file", return_value=content):
            assert parse_ips("/some/path") == ["192.168.1.100", "10.0.0.1"]


class TestParseConfSegments:
    """Tests for parse_conf_segments function."""

    def test_parses_locationmatch_segments(self):
        from nssec.modules.waf.restrict import parse_conf_segments

        content = '<LocationMatch "^/(SiPbx|ndp|LiCf)/">\n</LocationMatch>\n'
        with patch("nssec.modules.waf.restrict.read_file", return_value=content):
            assert parse_conf_segments("/x") == ["SiPbx", "ndp", "LiCf"]

    def test_returns_empty_when_no_locationmatch(self):
        from nssec.modules.waf.restrict import parse_conf_segments

        with patch("nssec.modules.waf.restrict.read_file", return_value="# nothing here\n"):
            assert parse_conf_segments("/x") == []

    def test_returns_empty_for_missing_file(self):
        from nssec.modules.waf.restrict import parse_conf_segments

        with patch("nssec.modules.waf.restrict.read_file", return_value=None):
            assert parse_conf_segments("/x") == []


class TestIsNssecManaged:
    """Tests for is_nssec_managed function."""

    def test_returns_true_for_managed_file(self):
        from nssec.modules.waf.config import RESTRICT_MANAGED_MARKER
        from nssec.modules.waf.restrict import is_nssec_managed

        content = f"{RESTRICT_MANAGED_MARKER}\n<LocationMatch>\n"
        with patch("nssec.modules.waf.restrict.read_file", return_value=content):
            assert is_nssec_managed("/some/path") is True

    def test_returns_false_for_unmanaged_file(self):
        from nssec.modules.waf.restrict import is_nssec_managed

        with patch("nssec.modules.waf.restrict.read_file", return_value="Require ip 1.2.3.4\n"):
            assert is_nssec_managed("/some/path") is False

    def test_returns_false_for_missing_file(self):
        from nssec.modules.waf.restrict import is_nssec_managed

        with patch("nssec.modules.waf.restrict.read_file", return_value=None):
            assert is_nssec_managed("/nonexistent") is False


class TestFindLegacyManagedHtaccess:
    """Tests for find_legacy_managed_htaccess function."""

    def test_returns_managed_legacy_files(self):
        from nssec.modules.waf.restrict import find_legacy_managed_htaccess

        with patch("nssec.modules.waf.restrict.file_exists", return_value=True), patch(
            "nssec.modules.waf.restrict.is_nssec_managed", return_value=True
        ):
            found = find_legacy_managed_htaccess()

        assert len(found) == 4  # all LEGACY_HTACCESS_PATHS
        assert all(p.endswith("/.htaccess") for p in found)

    def test_skips_unmanaged_files(self):
        """Hand-written .htaccess (no marker) is never reported."""
        from nssec.modules.waf.restrict import find_legacy_managed_htaccess

        with patch("nssec.modules.waf.restrict.file_exists", return_value=True), patch(
            "nssec.modules.waf.restrict.is_nssec_managed", return_value=False
        ):
            assert find_legacy_managed_htaccess() == []

    def test_skips_missing_files(self):
        from nssec.modules.waf.restrict import find_legacy_managed_htaccess

        with patch("nssec.modules.waf.restrict.file_exists", return_value=False):
            assert find_legacy_managed_htaccess() == []


class TestRenderConf:
    """Tests for the rendered restrict Apache config."""

    def test_render_produces_locationmatch_require_ip(self):
        from nssec.modules.waf.restrict import _render_conf

        conf = _render_conf(["SiPbx", "ndp", "LiCf"], ["127.0.0.1", "203.0.113.5"])

        assert '<LocationMatch "^/(SiPbx|ndp|LiCf)/">' in conf
        assert "<RequireAny>" in conf
        assert "Require ip 127.0.0.1" in conf
        assert "Require ip 203.0.113.5" in conf
        assert "</RequireAny>" in conf
        assert "</LocationMatch>" in conf
        assert conf.endswith("\n")

    def test_render_uses_no_legacy_syntax(self):
        """Must not emit deprecated Apache 2.2 Order/Allow directives."""
        from nssec.modules.waf.restrict import _render_conf

        conf = _render_conf(["SiPbx"], ["127.0.0.1"])
        assert "Order" not in conf
        assert "Allow from" not in conf


class TestCollectExistingIps:
    """Tests for collect_existing_ips function."""

    def test_collects_from_existing_config_and_htaccess(self):
        from nssec.modules.waf.restrict import collect_existing_ips

        content = "Require ip 127.0.0.1\nRequire ip 10.0.0.5\n"
        with patch("nssec.modules.waf.restrict.file_exists", return_value=True), patch(
            "nssec.modules.waf.restrict.read_file", return_value=content
        ), patch("nssec.modules.waf.restrict.load_cached_ips", return_value=[]):
            ips = collect_existing_ips("core")

        assert ips == ["10.0.0.5"]  # localhost excluded, deduped across sources

    def test_collects_from_cache(self):
        from nssec.modules.waf.restrict import collect_existing_ips

        with patch("nssec.modules.waf.restrict.file_exists", return_value=False), patch(
            "nssec.modules.waf.restrict.load_cached_ips", return_value=["127.0.0.1", "172.16.0.1"]
        ):
            ips = collect_existing_ips("core")

        assert ips == ["172.16.0.1"]

    def test_collects_legacy_allow_from(self):
        from nssec.modules.waf.restrict import collect_existing_ips

        content = "Order deny,allow\nAllow from 10.0.0.5\n"
        with patch("nssec.modules.waf.restrict.file_exists", return_value=True), patch(
            "nssec.modules.waf.restrict.read_file", return_value=content
        ), patch("nssec.modules.waf.restrict.load_cached_ips", return_value=[]):
            assert "10.0.0.5" in collect_existing_ips("core")

    def test_returns_empty_when_nothing_exists(self):
        from nssec.modules.waf.restrict import collect_existing_ips

        with patch("nssec.modules.waf.restrict.file_exists", return_value=False), patch(
            "nssec.modules.waf.restrict.load_cached_ips", return_value=[]
        ):
            assert collect_existing_ips("core") == []


class TestInitRestrictions:
    """Tests for init_restrictions function."""

    @patch("nssec.modules.waf.restrict.collect_existing_ips", return_value=[])
    @patch("nssec.modules.waf.restrict.save_cached_ips")
    @patch("nssec.modules.waf.restrict.write_file", return_value=True)
    @patch("nssec.modules.waf.restrict.backup_file")
    @patch("nssec.modules.waf.restrict.file_exists", return_value=False)
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    @patch("nssec.modules.waf.restrict.render", return_value="rendered")
    def test_writes_single_config(
        self, mock_render, mock_isdir, mock_exists, mock_backup, mock_write, mock_save, mock_collect
    ):
        from nssec.modules.waf.restrict import init_restrictions

        results = init_restrictions("core", ["192.168.1.100"])

        assert len(results) == 1
        assert results[0][1].success
        assert "Wrote" in results[0][1].message
        mock_write.assert_called_once()

    @patch("nssec.modules.waf.restrict.collect_existing_ips", return_value=[])
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    @patch("nssec.modules.waf.restrict.file_exists", return_value=False)
    def test_dry_run_does_not_write(self, mock_exists, mock_isdir, mock_collect):
        from nssec.modules.waf.restrict import init_restrictions

        with patch("nssec.modules.waf.restrict.write_file") as mock_write:
            results = init_restrictions("core", ["192.168.1.100"], dry_run=True)

        mock_write.assert_not_called()
        assert "Would write" in results[0][1].message

    def test_no_components_returns_skip(self):
        from nssec.modules.waf.restrict import init_restrictions

        with patch("nssec.modules.waf.restrict.collect_existing_ips", return_value=[]), patch(
            "nssec.modules.waf.restrict.is_directory", return_value=False
        ):
            results = init_restrictions("core", ["192.168.1.100"])

        assert len(results) == 1
        assert results[0][1].skipped

    @patch("nssec.modules.waf.restrict.collect_existing_ips", return_value=["10.0.0.5"])
    @patch("nssec.modules.waf.restrict.save_cached_ips")
    @patch("nssec.modules.waf.restrict.write_file", return_value=True)
    @patch("nssec.modules.waf.restrict.backup_file")
    @patch("nssec.modules.waf.restrict.file_exists", return_value=False)
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    @patch("nssec.modules.waf.restrict.render", return_value="rendered")
    def test_merges_existing_and_includes_localhost(
        self, mock_render, mock_isdir, mock_exists, mock_backup, mock_write, mock_save, mock_collect
    ):
        from nssec.modules.waf.restrict import init_restrictions

        init_restrictions("core", ["192.168.1.100"])

        ips = mock_render.call_args.kwargs["ips"]
        assert ips[0] == "127.0.0.1"
        assert "192.168.1.100" in ips
        assert "10.0.0.5" in ips

    @patch("nssec.modules.waf.restrict.collect_existing_ips", return_value=["10.0.0.5"])
    @patch("nssec.modules.waf.restrict.save_cached_ips")
    @patch("nssec.modules.waf.restrict.write_file", return_value=True)
    @patch("nssec.modules.waf.restrict.backup_file")
    @patch("nssec.modules.waf.restrict.file_exists", return_value=False)
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    @patch("nssec.modules.waf.restrict.render", return_value="rendered")
    def test_no_merge_uses_only_provided_ips(
        self, mock_render, mock_isdir, mock_exists, mock_backup, mock_write, mock_save, mock_collect
    ):
        from nssec.modules.waf.restrict import init_restrictions

        init_restrictions("core", ["192.168.1.100"], merge_existing=False)

        ips = mock_render.call_args.kwargs["ips"]
        assert ips == ["127.0.0.1", "192.168.1.100"]
        # collect_existing_ips must not be consulted when merging is disabled
        mock_collect.assert_not_called()

    @patch("nssec.modules.waf.restrict.collect_existing_ips", return_value=[])
    @patch("nssec.modules.waf.restrict.write_file", return_value=True)
    @patch("nssec.modules.waf.restrict.backup_file")
    @patch("nssec.modules.waf.restrict.file_exists", return_value=False)
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    @patch("nssec.modules.waf.restrict.render", return_value="rendered")
    def test_saves_ips_to_cache(
        self, mock_render, mock_isdir, mock_exists, mock_backup, mock_write, mock_collect
    ):
        from nssec.modules.waf.restrict import init_restrictions

        with patch("nssec.modules.waf.restrict.save_cached_ips") as mock_save:
            init_restrictions("core", ["192.168.1.100"])

        saved_ips = mock_save.call_args[0][0]
        assert "127.0.0.1" in saved_ips
        assert "192.168.1.100" in saved_ips


class TestAddRestrictedIp:
    """Tests for add_restricted_ip function."""

    @patch("nssec.modules.waf.restrict.save_cached_ips")
    @patch("nssec.modules.waf.restrict.load_cached_ips", return_value=["127.0.0.1"])
    @patch("nssec.modules.waf.restrict.write_file", return_value=True)
    @patch("nssec.modules.waf.restrict.backup_file")
    @patch("nssec.modules.waf.restrict.render", return_value="rendered")
    @patch("nssec.modules.waf.restrict.parse_conf_segments", return_value=["SiPbx"])
    @patch("nssec.modules.waf.restrict.parse_ips", return_value=["127.0.0.1"])
    @patch("nssec.modules.waf.restrict.is_nssec_managed", return_value=True)
    @patch("nssec.modules.waf.restrict.file_exists", return_value=True)
    def test_adds_ip_and_updates_cache(
        self,
        mock_exists,
        mock_managed,
        mock_parse,
        mock_segs,
        mock_render,
        mock_backup,
        mock_write,
        mock_load,
        mock_save,
    ):
        from nssec.modules.waf.restrict import add_restricted_ip

        results = add_restricted_ip("core", "192.168.1.100")

        assert results[0][1].success
        assert "Added" in results[0][1].message
        assert "192.168.1.100" in mock_save.call_args[0][0]

    @patch("nssec.modules.waf.restrict.parse_ips", return_value=["127.0.0.1", "192.168.1.100"])
    @patch("nssec.modules.waf.restrict.is_nssec_managed", return_value=True)
    @patch("nssec.modules.waf.restrict.file_exists", return_value=True)
    def test_skips_duplicate_ip(self, mock_exists, mock_managed, mock_parse):
        from nssec.modules.waf.restrict import add_restricted_ip

        results = add_restricted_ip("core", "192.168.1.100")
        assert results[0][1].skipped
        assert "already allowed" in results[0][1].message

    @patch("nssec.modules.waf.restrict.is_nssec_managed", return_value=False)
    @patch("nssec.modules.waf.restrict.file_exists", return_value=True)
    def test_skips_unmanaged_config(self, mock_exists, mock_managed):
        from nssec.modules.waf.restrict import add_restricted_ip

        results = add_restricted_ip("core", "192.168.1.100")
        assert results[0][1].skipped
        assert "unmanaged" in results[0][1].message.lower()

    @patch("nssec.modules.waf.restrict.file_exists", return_value=False)
    def test_skips_when_config_missing(self, mock_exists):
        from nssec.modules.waf.restrict import add_restricted_ip

        results = add_restricted_ip("core", "192.168.1.100")
        assert results[0][1].skipped
        assert "init first" in results[0][1].message


class TestRemoveRestrictedIp:
    """Tests for remove_restricted_ip function."""

    def test_refuses_to_remove_localhost(self):
        from nssec.modules.waf.restrict import remove_restricted_ip

        results = remove_restricted_ip("core", "127.0.0.1")
        assert not results[0][1].success
        assert "Cannot remove 127.0.0.1" in results[0][1].error

    @patch("nssec.modules.waf.restrict.save_cached_ips")
    @patch(
        "nssec.modules.waf.restrict.load_cached_ips", return_value=["127.0.0.1", "192.168.1.100"]
    )
    @patch("nssec.modules.waf.restrict.write_file", return_value=True)
    @patch("nssec.modules.waf.restrict.backup_file")
    @patch("nssec.modules.waf.restrict.render", return_value="rendered")
    @patch("nssec.modules.waf.restrict.parse_conf_segments", return_value=["SiPbx"])
    @patch("nssec.modules.waf.restrict.parse_ips", return_value=["127.0.0.1", "192.168.1.100"])
    @patch("nssec.modules.waf.restrict.is_nssec_managed", return_value=True)
    @patch("nssec.modules.waf.restrict.file_exists", return_value=True)
    def test_removes_ip_and_updates_cache(
        self,
        mock_exists,
        mock_managed,
        mock_parse,
        mock_segs,
        mock_render,
        mock_backup,
        mock_write,
        mock_load,
        mock_save,
    ):
        from nssec.modules.waf.restrict import remove_restricted_ip

        results = remove_restricted_ip("core", "192.168.1.100")

        assert results[0][1].success
        assert "Removed" in results[0][1].message
        saved = mock_save.call_args[0][0]
        assert "192.168.1.100" not in saved
        assert "127.0.0.1" in saved

    @patch("nssec.modules.waf.restrict.parse_ips", return_value=["127.0.0.1"])
    @patch("nssec.modules.waf.restrict.is_nssec_managed", return_value=True)
    @patch("nssec.modules.waf.restrict.file_exists", return_value=True)
    def test_skips_ip_not_present(self, mock_exists, mock_managed, mock_parse):
        from nssec.modules.waf.restrict import remove_restricted_ip

        results = remove_restricted_ip("core", "10.0.0.1")
        assert results[0][1].skipped
        assert "not found" in results[0][1].message

    @patch("nssec.modules.waf.restrict.is_nssec_managed", return_value=False)
    @patch("nssec.modules.waf.restrict.file_exists", return_value=True)
    def test_skips_unmanaged_config(self, mock_exists, mock_managed):
        from nssec.modules.waf.restrict import remove_restricted_ip

        results = remove_restricted_ip("core", "192.168.1.100")
        assert results[0][1].skipped
        assert "unmanaged" in results[0][1].message.lower()


class TestReapplyRestrictions:
    """Tests for reapply_restrictions function."""

    def test_returns_skip_when_no_cache(self):
        from nssec.modules.waf.restrict import reapply_restrictions

        with patch("nssec.modules.waf.restrict.read_file", return_value=None):
            results = reapply_restrictions("core")

        assert results[0][1].skipped
        assert "No cached IPs" in results[0][1].message

    @patch("nssec.modules.waf.restrict.write_file", return_value=True)
    @patch("nssec.modules.waf.restrict.backup_file")
    @patch("nssec.modules.waf.restrict.file_exists", return_value=False)
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    @patch("nssec.modules.waf.restrict.render", return_value="rendered")
    def test_restores_from_cache(
        self, mock_render, mock_isdir, mock_exists, mock_backup, mock_write
    ):
        from nssec.modules.waf.restrict import reapply_restrictions

        cached = json.dumps({"ips": ["127.0.0.1", "192.168.1.100"]})
        with patch("nssec.modules.waf.restrict.read_file", return_value=cached):
            results = reapply_restrictions("core")

        assert results[0][1].success
        assert "Restored" in results[0][1].message
        ips = mock_render.call_args.kwargs["ips"]
        assert "127.0.0.1" in ips
        assert "192.168.1.100" in ips

    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    def test_dry_run_does_not_write(self, mock_isdir):
        from nssec.modules.waf.restrict import reapply_restrictions

        cached = json.dumps({"ips": ["127.0.0.1", "10.0.0.1"]})
        with patch("nssec.modules.waf.restrict.read_file", return_value=cached), patch(
            "nssec.modules.waf.restrict.file_exists", return_value=False
        ), patch("nssec.modules.waf.restrict.write_file") as mock_write:
            results = reapply_restrictions("core", dry_run=True)

        mock_write.assert_not_called()
        assert "Would write" in results[0][1].message


class TestRemoveLegacyHtaccess:
    """Tests for remove_legacy_htaccess function."""

    @patch("nssec.modules.waf.restrict.remove_file", return_value=True)
    @patch(
        "nssec.modules.waf.restrict.find_legacy_managed_htaccess",
        return_value=["/usr/local/NetSapiens/SiPbx/html/SiPbx/.htaccess"],
    )
    def test_removes_managed_legacy_file(self, mock_find, mock_remove):
        from nssec.modules.waf.restrict import remove_legacy_htaccess

        results = remove_legacy_htaccess()

        assert len(results) == 1
        assert results[0][1].success
        assert "Removed legacy" in results[0][1].message
        mock_remove.assert_called_once()

    @patch(
        "nssec.modules.waf.restrict.find_legacy_managed_htaccess",
        return_value=["/usr/local/NetSapiens/ndp/.htaccess"],
    )
    def test_dry_run_does_not_delete(self, mock_find):
        from nssec.modules.waf.restrict import remove_legacy_htaccess

        with patch("nssec.modules.waf.restrict.remove_file") as mock_remove:
            results = remove_legacy_htaccess(dry_run=True)

        mock_remove.assert_not_called()
        assert "Would remove" in results[0][1].message

    @patch("nssec.modules.waf.restrict.find_legacy_managed_htaccess", return_value=[])
    def test_returns_empty_when_nothing_to_clean(self, mock_find):
        from nssec.modules.waf.restrict import remove_legacy_htaccess

        assert remove_legacy_htaccess() == []


class TestRestrictConfTemplate:
    """Tests for the restrict Apache config template (NetSapiens doc format)."""

    def test_template_matches_netsapiens_doc_format(self):
        from nssec.modules.waf.config import RESTRICT_CONF_TEMPLATE, RESTRICT_MANAGED_MARKER

        rendered = Template(RESTRICT_CONF_TEMPLATE).render(
            managed_marker=RESTRICT_MANAGED_MARKER,
            segments="SiPbx|LiCf|ndp",
            ips=["127.0.0.1", "203.0.113.5"],
        )

        assert RESTRICT_MANAGED_MARKER in rendered
        assert '<LocationMatch "^/(SiPbx|LiCf|ndp)/">' in rendered
        assert "<RequireAny>" in rendered
        assert "Require ip 127.0.0.1" in rendered
        assert "Require ip 203.0.113.5" in rendered
        # Must not use deprecated Apache 2.2 syntax
        assert "Order" not in rendered
        assert "Allow from" not in rendered


class TestInvalidIpFiltering:
    """Invalid tokens must never reach the Apache config or the cache."""

    def test_is_valid_ip(self):
        from nssec.modules.waf.restrict import is_valid_ip

        assert is_valid_ip("127.0.0.1")
        assert is_valid_ip("74.219.23.50")
        assert is_valid_ip("1.2.3.0/22")
        assert not is_valid_ip("<ADMIN-IP>")
        assert not is_valid_ip("not-an-ip")
        assert not is_valid_ip("999.1.1.1")

    def test_init_drops_invalid_existing_ips(self):
        from nssec.modules.waf.restrict import init_restrictions

        captured = {}
        with patch(
            "nssec.modules.waf.restrict.collect_existing_ips",
            return_value=["<ADMIN-IP>", "207.45.79.249"],
        ), patch(
            "nssec.modules.waf.restrict.get_applicable_components",
            return_value=[{"name": "SiPbx", "segment": "SiPbx"}],
        ), patch(
            "nssec.modules.waf.restrict.file_exists", return_value=False
        ), patch(
            "nssec.modules.waf.restrict.write_file",
            side_effect=lambda p, c: captured.update(content=c) or True,
        ), patch(
            "nssec.modules.waf.restrict.save_cached_ips",
            side_effect=lambda ips: captured.update(cached=ips),
        ), patch(
            "nssec.modules.waf.restrict.backup_file"
        ):
            results = init_restrictions("combo", [], merge_existing=True)

        # The invalid token is not written to the config...
        assert "<ADMIN-IP>" not in captured["content"]
        assert "Require ip 207.45.79.249" in captured["content"]
        # ...nor persisted to the cache (self-heals),
        assert "<ADMIN-IP>" not in captured["cached"]
        assert captured["cached"] == ["127.0.0.1", "207.45.79.249"]
        # ...and the skip is reported.
        assert "skipped 1 invalid" in results[0][1].message
        assert "<ADMIN-IP>" in results[0][1].message

    def test_render_conf_is_a_safety_net(self):
        from nssec.modules.waf.restrict import _render_conf

        content = _render_conf(["SiPbx"], ["127.0.0.1", "junk", "203.0.113.5"])
        assert "junk" not in content
        assert "Require ip 203.0.113.5" in content
