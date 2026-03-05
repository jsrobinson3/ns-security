"""Tests for WAF restrict module functions."""

import json
from unittest.mock import patch

from jinja2 import Template


class TestLoadCachedIps:
    """Tests for load_cached_ips function."""

    def test_returns_ips_from_cache(self):
        """Should return cached IPs from JSON file."""
        from nssec.modules.waf.restrict import load_cached_ips

        cache = json.dumps({"ips": ["127.0.0.1", "10.0.0.1"]})
        with patch("nssec.modules.waf.restrict.read_file", return_value=cache):
            result = load_cached_ips()

        assert result == ["127.0.0.1", "10.0.0.1"]

    def test_returns_empty_when_no_cache(self):
        """Should return empty list when cache file doesn't exist."""
        from nssec.modules.waf.restrict import load_cached_ips

        with patch("nssec.modules.waf.restrict.read_file", return_value=None):
            result = load_cached_ips()

        assert result == []

    def test_returns_empty_on_invalid_json(self):
        """Should return empty list when cache contains invalid JSON."""
        from nssec.modules.waf.restrict import load_cached_ips

        with patch("nssec.modules.waf.restrict.read_file", return_value="not json"):
            result = load_cached_ips()

        assert result == []


class TestSaveCachedIps:
    """Tests for save_cached_ips function."""

    def test_saves_ips_to_json(self):
        """Should write IPs as JSON to cache file."""
        from nssec.modules.waf.restrict import save_cached_ips

        with patch("nssec.modules.waf.restrict.write_file", return_value=True) as mock_write:
            result = save_cached_ips(["127.0.0.1", "10.0.0.1"])

        assert result is True
        mock_write.assert_called_once()
        written_content = mock_write.call_args[0][1]
        data = json.loads(written_content)
        assert data["ips"] == ["127.0.0.1", "10.0.0.1"]


class TestGetApplicableTargets:
    """Tests for get_applicable_targets function."""

    def test_core_server_gets_sipbx_and_nsapi(self):
        """Core server should get SiPbx Admin UI and ns-api targets."""
        from nssec.modules.waf.restrict import get_applicable_targets

        with patch("nssec.modules.waf.restrict.is_directory", return_value=True):
            targets = get_applicable_targets("core")

        names = [t["name"] for t in targets]
        assert "SiPbx Admin UI" in names
        assert "ns-api" in names
        assert "NDP Endpoints" not in names
        assert "LiCf Recording" not in names

    def test_ndp_server_gets_ndp_target(self):
        """NDP server should get NDP Endpoints target."""
        from nssec.modules.waf.restrict import get_applicable_targets

        with patch("nssec.modules.waf.restrict.is_directory", return_value=True):
            targets = get_applicable_targets("ndp")

        names = [t["name"] for t in targets]
        assert "NDP Endpoints" in names
        assert "SiPbx Admin UI" not in names

    def test_recording_server_gets_licf_target(self):
        """Recording server should get LiCf Recording target."""
        from nssec.modules.waf.restrict import get_applicable_targets

        with patch("nssec.modules.waf.restrict.is_directory", return_value=True):
            targets = get_applicable_targets("recording")

        names = [t["name"] for t in targets]
        assert "LiCf Recording" in names
        assert "SiPbx Admin UI" not in names

    def test_combo_server_gets_all_targets(self):
        """Combo server should get all targets."""
        from nssec.modules.waf.restrict import get_applicable_targets

        with patch("nssec.modules.waf.restrict.is_directory", return_value=True):
            targets = get_applicable_targets("combo")

        names = [t["name"] for t in targets]
        assert "SiPbx Admin UI" in names
        assert "ns-api" in names
        assert "NDP Endpoints" in names
        assert "LiCf Recording" in names

    def test_filters_by_directory_existence(self):
        """Should exclude targets whose directory doesn't exist."""
        from nssec.modules.waf.restrict import get_applicable_targets

        def mock_is_dir(path):
            return "/SiPbx" in path

        with patch("nssec.modules.waf.restrict.is_directory", side_effect=mock_is_dir):
            targets = get_applicable_targets("combo")

        names = [t["name"] for t in targets]
        assert "SiPbx Admin UI" in names
        assert "NDP Endpoints" not in names

    def test_unknown_server_type_returns_empty(self):
        """Unknown server type should return no targets."""
        from nssec.modules.waf.restrict import get_applicable_targets

        with patch("nssec.modules.waf.restrict.is_directory", return_value=True):
            targets = get_applicable_targets("unknown")

        assert targets == []


class TestParseHtaccessIps:
    """Tests for parse_htaccess_ips function."""

    def test_parses_require_ip_lines(self):
        """Should parse Require ip entries from .htaccess."""
        from nssec.modules.waf.restrict import parse_htaccess_ips

        content = """\
<RequireAll>
    Require all denied
    Require ip 127.0.0.1
    Require ip 192.168.1.100
    Require ip 10.0.0.0/8
</RequireAll>
"""
        with patch("nssec.modules.waf.restrict.read_file", return_value=content):
            ips = parse_htaccess_ips("/some/path")

        assert ips == ["127.0.0.1", "192.168.1.100", "10.0.0.0/8"]

    def test_returns_empty_for_missing_file(self):
        """Should return empty list when file doesn't exist."""
        from nssec.modules.waf.restrict import parse_htaccess_ips

        with patch("nssec.modules.waf.restrict.read_file", return_value=None):
            ips = parse_htaccess_ips("/nonexistent")

        assert ips == []

    def test_returns_empty_for_no_require_ip(self):
        """Should return empty list when no IP entries present."""
        from nssec.modules.waf.restrict import parse_htaccess_ips

        content = "# Just a comment\nAllow from all\n"
        with patch("nssec.modules.waf.restrict.read_file", return_value=content):
            ips = parse_htaccess_ips("/some/path")

        assert ips == []

    def test_parses_legacy_allow_from_lines(self):
        """Should parse legacy Apache 2.2 Allow from entries."""
        from nssec.modules.waf.restrict import parse_htaccess_ips

        content = """\
Order deny,allow
Deny from all
Allow from 192.168.1.100
Allow from 10.0.0.0/8
Allow from 172.16.0.1
"""
        with patch("nssec.modules.waf.restrict.read_file", return_value=content):
            ips = parse_htaccess_ips("/some/path")

        assert ips == ["192.168.1.100", "10.0.0.0/8", "172.16.0.1"]

    def test_parses_allow_from_with_multiple_ips_on_one_line(self):
        """Should parse multiple IPs on a single Allow from line."""
        from nssec.modules.waf.restrict import parse_htaccess_ips

        content = "Allow from 192.168.1.100 10.0.0.1, 172.16.0.1\n"
        with patch("nssec.modules.waf.restrict.read_file", return_value=content):
            ips = parse_htaccess_ips("/some/path")

        assert "192.168.1.100" in ips
        assert "10.0.0.1" in ips
        assert "172.16.0.1" in ips

    def test_deduplicates_ips_across_syntaxes(self):
        """Should deduplicate IPs found in both Require ip and Allow from."""
        from nssec.modules.waf.restrict import parse_htaccess_ips

        content = """\
Require ip 127.0.0.1
Require ip 192.168.1.100
Allow from 192.168.1.100
Allow from 10.0.0.1
"""
        with patch("nssec.modules.waf.restrict.read_file", return_value=content):
            ips = parse_htaccess_ips("/some/path")

        assert ips == ["127.0.0.1", "192.168.1.100", "10.0.0.1"]


class TestIsNssecManaged:
    """Tests for is_nssec_managed function."""

    def test_returns_true_for_managed_file(self):
        """Should return True when marker is present."""
        from nssec.modules.waf.config import RESTRICT_MANAGED_MARKER
        from nssec.modules.waf.restrict import is_nssec_managed

        content = f"{RESTRICT_MANAGED_MARKER}\n<RequireAll>\n</RequireAll>\n"
        with patch("nssec.modules.waf.restrict.read_file", return_value=content):
            assert is_nssec_managed("/some/path") is True

    def test_returns_false_for_unmanaged_file(self):
        """Should return False when marker is absent."""
        from nssec.modules.waf.restrict import is_nssec_managed

        content = "Allow from 192.168.1.0/24\n"
        with patch("nssec.modules.waf.restrict.read_file", return_value=content):
            assert is_nssec_managed("/some/path") is False

    def test_returns_false_for_missing_file(self):
        """Should return False when file doesn't exist."""
        from nssec.modules.waf.restrict import is_nssec_managed

        with patch("nssec.modules.waf.restrict.read_file", return_value=None):
            assert is_nssec_managed("/nonexistent") is False


class TestInitRestrictions:
    """Tests for init_restrictions function."""

    @patch("nssec.modules.waf.restrict.collect_existing_ips", return_value=[])
    @patch("nssec.modules.waf.restrict.save_cached_ips")
    @patch("nssec.modules.waf.restrict.write_file", return_value=True)
    @patch("nssec.modules.waf.restrict.backup_file")
    @patch("nssec.modules.waf.restrict.file_exists", return_value=False)
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    @patch("nssec.modules.waf.restrict.render", return_value="rendered")
    def test_creates_htaccess_files(
        self, mock_render, mock_isdir, mock_exists, mock_backup, mock_write, mock_save, mock_collect
    ):
        """Should create .htaccess files for applicable targets."""
        from nssec.modules.waf.restrict import init_restrictions

        results = init_restrictions("core", ["192.168.1.100"])

        assert len(results) == 2  # SiPbx + ns-api
        for name, result in results:
            assert result.success
            assert "Created" in result.message

    @patch("nssec.modules.waf.restrict.collect_existing_ips", return_value=[])
    @patch("nssec.modules.waf.restrict.save_cached_ips")
    @patch("nssec.modules.waf.restrict.write_file", return_value=True)
    @patch("nssec.modules.waf.restrict.backup_file")
    @patch("nssec.modules.waf.restrict.file_exists", return_value=True)
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    @patch("nssec.modules.waf.restrict.render", return_value="rendered")
    def test_overwrites_unmanaged_files(
        self, mock_render, mock_isdir, mock_exists, mock_backup, mock_write, mock_save, mock_collect
    ):
        """Should overwrite existing unmanaged .htaccess files."""
        from nssec.modules.waf.restrict import init_restrictions

        results = init_restrictions("core", ["192.168.1.100"])

        for name, result in results:
            assert result.success
            assert "Created" in result.message

    @patch("nssec.modules.waf.restrict.collect_existing_ips", return_value=[])
    @patch("nssec.modules.waf.restrict.file_exists", return_value=False)
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    def test_dry_run_does_not_write(self, mock_isdir, mock_exists, mock_collect):
        """Should not write files in dry run mode."""
        from nssec.modules.waf.restrict import init_restrictions

        with patch("nssec.modules.waf.restrict.write_file") as mock_write:
            results = init_restrictions("core", ["192.168.1.100"], dry_run=True)

        mock_write.assert_not_called()
        for name, result in results:
            assert result.success
            assert "Would create" in result.message

    def test_no_targets_returns_skip(self):
        """Should return skip result when no targets apply."""
        from nssec.modules.waf.restrict import init_restrictions

        with patch("nssec.modules.waf.restrict.collect_existing_ips", return_value=[]), patch(
            "nssec.modules.waf.restrict.is_directory", return_value=False
        ):
            results = init_restrictions("core", ["192.168.1.100"])

        assert len(results) == 1
        assert results[0][1].skipped

    @patch("nssec.modules.waf.restrict.collect_existing_ips", return_value=[])
    @patch("nssec.modules.waf.restrict.save_cached_ips")
    @patch("nssec.modules.waf.restrict.write_file", return_value=True)
    @patch("nssec.modules.waf.restrict.backup_file")
    @patch("nssec.modules.waf.restrict.file_exists", return_value=False)
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    @patch("nssec.modules.waf.restrict.render", return_value="rendered")
    def test_always_includes_localhost(
        self, mock_render, mock_isdir, mock_exists, mock_backup, mock_write, mock_save, mock_collect
    ):
        """Should always include 127.0.0.1 in rendered IPs."""
        from nssec.modules.waf.restrict import init_restrictions

        init_restrictions("core", ["192.168.1.100"])

        # Check that render was called with 127.0.0.1 in the ips list
        for call_args in mock_render.call_args_list:
            ips = call_args.kwargs.get("ips", call_args[1].get("ips", []))
            assert "127.0.0.1" in ips

    @patch("nssec.modules.waf.restrict.collect_existing_ips", return_value=["10.0.0.5"])
    @patch("nssec.modules.waf.restrict.save_cached_ips")
    @patch("nssec.modules.waf.restrict.write_file", return_value=True)
    @patch("nssec.modules.waf.restrict.backup_file")
    @patch("nssec.modules.waf.restrict.file_exists", return_value=True)
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    @patch("nssec.modules.waf.restrict.render", return_value="rendered")
    def test_merges_existing_ips_from_all_targets(
        self, mock_render, mock_isdir, mock_exists, mock_backup, mock_write, mock_save, mock_collect
    ):
        """Should merge existing IPs from all targets into every file."""
        from nssec.modules.waf.restrict import init_restrictions

        results = init_restrictions("core", ["192.168.1.100"])

        for name, result in results:
            assert result.success
            assert "Created" in result.message

        # Every target gets the full merged set
        for call_args in mock_render.call_args_list:
            ips = call_args.kwargs.get("ips", call_args[1].get("ips", []))
            assert "127.0.0.1" in ips
            assert "192.168.1.100" in ips
            assert "10.0.0.5" in ips

    @patch("nssec.modules.waf.restrict.collect_existing_ips", return_value=["10.0.0.5"])
    @patch("nssec.modules.waf.restrict.save_cached_ips")
    @patch("nssec.modules.waf.restrict.write_file", return_value=True)
    @patch("nssec.modules.waf.restrict.backup_file")
    @patch("nssec.modules.waf.restrict.file_exists", return_value=False)
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    @patch("nssec.modules.waf.restrict.render", return_value="rendered")
    def test_merges_ips_from_cache(
        self, mock_render, mock_isdir, mock_exists, mock_backup, mock_write, mock_save, mock_collect
    ):
        """Should merge IPs from cache file into new .htaccess files."""
        from nssec.modules.waf.restrict import init_restrictions

        results = init_restrictions("core", ["192.168.1.100"])

        for name, result in results:
            assert result.success

        # Check that render was called with collected IP merged in
        for call_args in mock_render.call_args_list:
            ips = call_args.kwargs.get("ips", call_args[1].get("ips", []))
            assert "10.0.0.5" in ips
            assert "192.168.1.100" in ips

    @patch("nssec.modules.waf.restrict.collect_existing_ips", return_value=[])
    @patch("nssec.modules.waf.restrict.write_file", return_value=True)
    @patch("nssec.modules.waf.restrict.backup_file")
    @patch("nssec.modules.waf.restrict.file_exists", return_value=False)
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    @patch("nssec.modules.waf.restrict.render", return_value="rendered")
    def test_saves_ips_to_cache_after_init(
        self, mock_render, mock_isdir, mock_exists, mock_backup, mock_write, mock_collect
    ):
        """Should save IPs to cache file after successful init."""
        from nssec.modules.waf.restrict import init_restrictions

        with patch("nssec.modules.waf.restrict.save_cached_ips") as mock_save:
            init_restrictions("core", ["192.168.1.100"])

        mock_save.assert_called_once()
        saved_ips = mock_save.call_args[0][0]
        assert "127.0.0.1" in saved_ips
        assert "192.168.1.100" in saved_ips


class TestCollectExistingIps:
    """Tests for collect_existing_ips function."""

    @patch("nssec.modules.waf.restrict.load_cached_ips", return_value=[])
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    def test_collects_ips_from_existing_htaccess(self, mock_isdir, mock_cache):
        """Should collect IPs from existing .htaccess files."""
        from nssec.modules.waf.restrict import collect_existing_ips

        content = "Require ip 127.0.0.1\nRequire ip 10.0.0.5\n"
        with patch("nssec.modules.waf.restrict.file_exists", return_value=True), patch(
            "nssec.modules.waf.restrict.read_file", return_value=content
        ):
            ips = collect_existing_ips("core")

        assert "10.0.0.5" in ips
        assert "127.0.0.1" not in ips  # localhost excluded

    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    def test_collects_ips_from_cache(self, mock_isdir):
        """Should include IPs from the cache file."""
        from nssec.modules.waf.restrict import collect_existing_ips

        with patch("nssec.modules.waf.restrict.file_exists", return_value=False), patch(
            "nssec.modules.waf.restrict.load_cached_ips", return_value=["127.0.0.1", "172.16.0.1"]
        ):
            ips = collect_existing_ips("core")

        assert "172.16.0.1" in ips
        assert "127.0.0.1" not in ips

    @patch("nssec.modules.waf.restrict.load_cached_ips", return_value=[])
    @patch("nssec.modules.waf.restrict.file_exists", return_value=False)
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    def test_returns_empty_when_nothing_exists(self, mock_isdir, mock_exists, mock_cache):
        """Should return empty list when no files or cache exist."""
        from nssec.modules.waf.restrict import collect_existing_ips

        ips = collect_existing_ips("core")
        assert ips == []

    @patch("nssec.modules.waf.restrict.load_cached_ips", return_value=[])
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    def test_collects_legacy_allow_from_ips(self, mock_isdir, mock_cache):
        """Should collect IPs from legacy Allow from syntax."""
        from nssec.modules.waf.restrict import collect_existing_ips

        content = "Order deny,allow\nDeny from all\nAllow from 10.0.0.5\n"
        with patch("nssec.modules.waf.restrict.file_exists", return_value=True), patch(
            "nssec.modules.waf.restrict.read_file", return_value=content
        ):
            ips = collect_existing_ips("core")

        assert "10.0.0.5" in ips


class TestInitRestrictionsNoMerge:
    """Tests for init_restrictions with merge_existing=False."""

    @patch("nssec.modules.waf.restrict.save_cached_ips")
    @patch("nssec.modules.waf.restrict.write_file", return_value=True)
    @patch("nssec.modules.waf.restrict.backup_file")
    @patch("nssec.modules.waf.restrict.file_exists", return_value=True)
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    @patch("nssec.modules.waf.restrict.render", return_value="rendered")
    def test_does_not_merge_existing_when_disabled(
        self, mock_render, mock_isdir, mock_exists, mock_backup, mock_write, mock_save
    ):
        """Should not merge existing IPs when merge_existing=False."""
        from nssec.modules.waf.restrict import init_restrictions

        results = init_restrictions("core", ["192.168.1.100"], merge_existing=False)

        for name, result in results:
            assert result.success

        # Render should only include provided IPs + localhost
        for call_args in mock_render.call_args_list:
            ips = call_args.kwargs.get("ips", call_args[1].get("ips", []))
            assert "127.0.0.1" in ips
            assert "192.168.1.100" in ips
            assert len(ips) == 2

    @patch("nssec.modules.waf.restrict.save_cached_ips")
    @patch("nssec.modules.waf.restrict.write_file", return_value=True)
    @patch("nssec.modules.waf.restrict.backup_file")
    @patch("nssec.modules.waf.restrict.file_exists", return_value=False)
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    @patch("nssec.modules.waf.restrict.render", return_value="rendered")
    def test_does_not_merge_cache_when_disabled(
        self, mock_render, mock_isdir, mock_exists, mock_backup, mock_write, mock_save
    ):
        """Should not merge cache IPs when merge_existing=False."""
        from nssec.modules.waf.restrict import init_restrictions

        init_restrictions("core", ["192.168.1.100"], merge_existing=False)

        # Render should only include provided IPs + localhost
        for call_args in mock_render.call_args_list:
            ips = call_args.kwargs.get("ips", call_args[1].get("ips", []))
            assert len(ips) == 2
            assert "192.168.1.100" in ips


class TestAddRestrictedIp:
    """Tests for add_restricted_ip function."""

    @patch("nssec.modules.waf.restrict.save_cached_ips")
    @patch("nssec.modules.waf.restrict.load_cached_ips", return_value=["127.0.0.1"])
    @patch("nssec.modules.waf.restrict.write_file", return_value=True)
    @patch("nssec.modules.waf.restrict.backup_file")
    @patch("nssec.modules.waf.restrict.render", return_value="rendered")
    @patch("nssec.modules.waf.restrict.is_nssec_managed", return_value=True)
    @patch("nssec.modules.waf.restrict.parse_htaccess_ips", return_value=["127.0.0.1"])
    @patch("nssec.modules.waf.restrict.file_exists", return_value=True)
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    def test_adds_ip_to_managed_files(
        self,
        mock_isdir,
        mock_exists,
        mock_parse,
        mock_managed,
        mock_render,
        mock_backup,
        mock_write,
        mock_load,
        mock_save,
    ):
        """Should add IP to all managed .htaccess files and update cache."""
        from nssec.modules.waf.restrict import add_restricted_ip

        results = add_restricted_ip("core", "192.168.1.100")

        for name, result in results:
            assert result.success
            assert "Added" in result.message

        # Should update cache with new IP
        mock_save.assert_called_once()
        saved_ips = mock_save.call_args[0][0]
        assert "192.168.1.100" in saved_ips

    @patch("nssec.modules.waf.restrict.is_nssec_managed", return_value=True)
    @patch(
        "nssec.modules.waf.restrict.parse_htaccess_ips", return_value=["127.0.0.1", "192.168.1.100"]
    )
    @patch("nssec.modules.waf.restrict.file_exists", return_value=True)
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    def test_skips_duplicate_ip(self, mock_isdir, mock_exists, mock_parse, mock_managed):
        """Should skip if IP already present in file."""
        from nssec.modules.waf.restrict import add_restricted_ip

        results = add_restricted_ip("core", "192.168.1.100")

        for name, result in results:
            assert result.skipped
            assert "already in" in result.message

    @patch("nssec.modules.waf.restrict.is_nssec_managed", return_value=False)
    @patch("nssec.modules.waf.restrict.file_exists", return_value=True)
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    def test_skips_unmanaged_files(self, mock_isdir, mock_exists, mock_managed):
        """Should skip unmanaged .htaccess files."""
        from nssec.modules.waf.restrict import add_restricted_ip

        results = add_restricted_ip("core", "192.168.1.100")

        for name, result in results:
            assert result.skipped
            assert "unmanaged" in result.message.lower()

    @patch("nssec.modules.waf.restrict.file_exists", return_value=False)
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    def test_skips_missing_files(self, mock_isdir, mock_exists):
        """Should skip when .htaccess doesn't exist."""
        from nssec.modules.waf.restrict import add_restricted_ip

        results = add_restricted_ip("core", "192.168.1.100")

        for name, result in results:
            assert result.skipped
            assert "init first" in result.message


class TestRemoveRestrictedIp:
    """Tests for remove_restricted_ip function."""

    def test_refuses_to_remove_localhost(self):
        """Should refuse to remove 127.0.0.1."""
        from nssec.modules.waf.restrict import remove_restricted_ip

        results = remove_restricted_ip("core", "127.0.0.1")

        assert len(results) == 1
        assert not results[0][1].success
        assert "Cannot remove 127.0.0.1" in results[0][1].error

    @patch("nssec.modules.waf.restrict.save_cached_ips")
    @patch(
        "nssec.modules.waf.restrict.load_cached_ips", return_value=["127.0.0.1", "192.168.1.100"]
    )
    @patch("nssec.modules.waf.restrict.write_file", return_value=True)
    @patch("nssec.modules.waf.restrict.backup_file")
    @patch("nssec.modules.waf.restrict.render", return_value="rendered")
    @patch("nssec.modules.waf.restrict.is_nssec_managed", return_value=True)
    @patch(
        "nssec.modules.waf.restrict.parse_htaccess_ips", return_value=["127.0.0.1", "192.168.1.100"]
    )
    @patch("nssec.modules.waf.restrict.file_exists", return_value=True)
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    def test_removes_user_added_ip(
        self,
        mock_isdir,
        mock_exists,
        mock_parse,
        mock_managed,
        mock_render,
        mock_backup,
        mock_write,
        mock_load,
        mock_save,
    ):
        """Should remove a user-added IP from managed files and update cache."""
        from nssec.modules.waf.restrict import remove_restricted_ip

        results = remove_restricted_ip("core", "192.168.1.100")

        for name, result in results:
            assert result.success
            assert "Removed" in result.message

        # Should update cache without the removed IP
        mock_save.assert_called_once()
        saved_ips = mock_save.call_args[0][0]
        assert "192.168.1.100" not in saved_ips
        assert "127.0.0.1" in saved_ips

    @patch("nssec.modules.waf.restrict.is_nssec_managed", return_value=True)
    @patch("nssec.modules.waf.restrict.parse_htaccess_ips", return_value=["127.0.0.1"])
    @patch("nssec.modules.waf.restrict.file_exists", return_value=True)
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    def test_skips_ip_not_in_file(self, mock_isdir, mock_exists, mock_parse, mock_managed):
        """Should skip if IP not found in file."""
        from nssec.modules.waf.restrict import remove_restricted_ip

        results = remove_restricted_ip("core", "10.0.0.1")

        for name, result in results:
            assert result.skipped
            assert "not found" in result.message

    @patch("nssec.modules.waf.restrict.is_nssec_managed", return_value=False)
    @patch("nssec.modules.waf.restrict.file_exists", return_value=True)
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    def test_skips_unmanaged_files(self, mock_isdir, mock_exists, mock_managed):
        """Should skip unmanaged .htaccess files."""
        from nssec.modules.waf.restrict import remove_restricted_ip

        results = remove_restricted_ip("core", "192.168.1.100")

        for name, result in results:
            assert result.skipped
            assert "unmanaged" in result.message.lower()


class TestHtaccessTemplates:
    """Tests for .htaccess Jinja2 templates."""

    def test_dir_template_renders_allow_from(self):
        """Directory template should use Order/Allow from syntax."""
        from nssec.modules.waf.config import HTACCESS_DIR_TEMPLATE, RESTRICT_MANAGED_MARKER

        rendered = Template(HTACCESS_DIR_TEMPLATE).render(
            managed_marker=RESTRICT_MANAGED_MARKER,
            ips=["127.0.0.1", "192.168.1.100"],
        )

        assert RESTRICT_MANAGED_MARKER in rendered
        assert "Order allow,deny" in rendered
        assert "Allow from 127.0.0.1" in rendered
        assert "Allow from 192.168.1.100" in rendered
        # No blank lines between entries
        assert "127.0.0.1\nAllow from 192.168.1.100" in rendered

    def test_file_template_wraps_in_files_directive(self):
        """File template should wrap restrictions in Files directive."""
        from nssec.modules.waf.config import HTACCESS_FILE_TEMPLATE, RESTRICT_MANAGED_MARKER

        rendered = Template(HTACCESS_FILE_TEMPLATE).render(
            managed_marker=RESTRICT_MANAGED_MARKER,
            file_target="adminlogin.php",
            ips=["127.0.0.1", "10.0.0.0/8"],
        )

        assert RESTRICT_MANAGED_MARKER in rendered
        assert '<Files "adminlogin.php">' in rendered
        assert "Order allow,deny" in rendered
        assert "Allow from 127.0.0.1" in rendered
        assert "Allow from 10.0.0.0/8" in rendered
        assert "</Files>" in rendered
        # No blank lines between entries
        assert "127.0.0.1\n    Allow from 10.0.0.0/8" in rendered

    def test_templates_match_netsapiens_doc_format(self):
        """Templates should match the NetSapiens documentation format."""
        from nssec.modules.waf.config import HTACCESS_FILE_TEMPLATE, RESTRICT_MANAGED_MARKER

        rendered = Template(HTACCESS_FILE_TEMPLATE).render(
            managed_marker=RESTRICT_MANAGED_MARKER,
            file_target="adminlogin.php",
            ips=["127.0.0.1"],
        )

        # Should use same syntax as the NS doc
        assert "Order allow,deny" in rendered
        assert "Allow from" in rendered
        # Should NOT use Apache 2.4 Require syntax
        assert "Require" not in rendered


class TestReapplyRestrictions:
    """Tests for reapply_restrictions function."""

    def test_returns_skip_when_no_cache(self):
        """Should skip when no cached IPs exist."""
        from nssec.modules.waf.restrict import reapply_restrictions

        with patch("nssec.modules.waf.restrict.read_file", return_value=None):
            results = reapply_restrictions("core")

        assert len(results) == 1
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
        """Should re-create .htaccess files from cached IPs."""
        from nssec.modules.waf.restrict import reapply_restrictions

        cached = json.dumps({"ips": ["127.0.0.1", "192.168.1.100"]})
        with patch("nssec.modules.waf.restrict.read_file", return_value=cached):
            results = reapply_restrictions("core")

        for name, result in results:
            assert result.success
            assert "Restored" in result.message

        # Verify IPs passed to render include cached IPs
        for call_args in mock_render.call_args_list:
            ips = call_args.kwargs.get("ips", call_args[1].get("ips", []))
            assert "127.0.0.1" in ips
            assert "192.168.1.100" in ips

    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    def test_dry_run_does_not_write(self, mock_isdir):
        """Should not write files in dry run mode."""
        from nssec.modules.waf.restrict import reapply_restrictions

        cached = json.dumps({"ips": ["127.0.0.1", "10.0.0.1"]})
        with patch("nssec.modules.waf.restrict.read_file", return_value=cached), patch(
            "nssec.modules.waf.restrict.file_exists", return_value=False
        ), patch("nssec.modules.waf.restrict.write_file") as mock_write:
            results = reapply_restrictions("core", dry_run=True)

        mock_write.assert_not_called()
        for name, result in results:
            assert result.success
            assert "Would write" in result.message

    @patch("nssec.modules.waf.restrict.write_file", return_value=True)
    @patch("nssec.modules.waf.restrict.backup_file")
    @patch("nssec.modules.waf.restrict.file_exists", return_value=True)
    @patch("nssec.modules.waf.restrict.is_directory", return_value=True)
    @patch("nssec.modules.waf.restrict.render", return_value="rendered")
    def test_backs_up_existing_before_overwrite(
        self, mock_render, mock_isdir, mock_exists, mock_backup, mock_write
    ):
        """Should backup existing files before restoring from cache."""
        from nssec.modules.waf.restrict import reapply_restrictions

        cached = json.dumps({"ips": ["127.0.0.1"]})
        with patch("nssec.modules.waf.restrict.read_file", return_value=cached):
            reapply_restrictions("core")

        mock_backup.assert_called()
