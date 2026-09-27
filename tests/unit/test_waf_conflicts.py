"""Tests for the CRS rule id conflict preflight check."""

from fnmatch import fnmatch
from unittest.mock import MagicMock, patch

import pytest

from nssec.modules.waf.conflicts import (
    describe_conflict,
    expand_config_path,
    extract_rule_ids,
    find_rule_conflicts,
    list_loaded_configs,
    parse_dump_includes,
    parse_include_directives,
    resolve_includes,
)
from nssec.modules.waf.types import RuleConflict

DUMP_OUTPUT = """\
Included configuration files:
  (*) /etc/apache2/apache2.conf
    (146) /etc/apache2/mods-enabled/alias.load
    (147) /etc/apache2/mods-enabled/security2.conf
      (5) /etc/modsecurity/modsecurity.conf
      (9) /etc/modsecurity/rules/custom.conf
    (225) /etc/apache2/sites-enabled/000-default.conf
"""


class TestParseDumpIncludes:
    def test_lists_every_file_in_load_order(self):
        assert parse_dump_includes(DUMP_OUTPUT) == [
            "/etc/apache2/apache2.conf",
            "/etc/apache2/mods-enabled/alias.load",
            "/etc/apache2/mods-enabled/security2.conf",
            "/etc/modsecurity/modsecurity.conf",
            "/etc/modsecurity/rules/custom.conf",
            "/etc/apache2/sites-enabled/000-default.conf",
        ]

    def test_ignores_header_and_status_lines(self):
        assert parse_dump_includes("Included configuration files:\nSyntax OK\n") == []

    def test_empty_output(self):
        assert parse_dump_includes("") == []


class TestParseIncludeDirectives:
    def test_both_directives_any_case(self):
        content = "Include a.conf\n  IncludeOptional /etc/x/*.conf\ninclude b.conf\n"
        assert parse_include_directives(content) == ["a.conf", "/etc/x/*.conf", "b.conf"]

    def test_strips_quotes(self):
        assert parse_include_directives('Include "/etc/x/y.conf"\n') == ["/etc/x/y.conf"]

    def test_ignores_comments(self):
        assert parse_include_directives("# Include /etc/x/y.conf\n") == []


class TestExtractRuleIds:
    def test_ids_from_rule_actions(self):
        content = (
            'SecRule ARGS "@rx foo" "id:901001,phase:1,pass"\n'
            "SecAction \"id:'901100',phase:1,nolog\"\n"
        )
        assert extract_rule_ids(content) == {901001, 901100}

    def test_ignores_commented_rules(self):
        content = '# SecRule ARGS "@rx foo" "id:901001,phase:1"\nSecAction "id:1,pass"\n'
        assert extract_rule_ids(content) == {1}

    def test_follows_continuation_lines(self):
        content = 'SecRule ARGS "@rx foo" \\\n    "phase:1,\\\n    id:942100,\\\n    pass"\n'
        assert extract_rule_ids(content) == {942100}

    def test_commented_rule_with_continuations_is_ignored(self):
        content = '#SecRule ARGS "@rx foo" \\\n    "id:942100,\\\n    pass"\n'
        assert extract_rule_ids(content) == set()

    def test_ignores_id_like_substrings(self):
        content = "SecAction \"id:5,setvar:tx.id:900001,msg:'uuid:900002'\"\n"
        assert extract_rule_ids(content) == {5}


class TestResolveIncludes:
    FILES = {
        "/etc/apache2/apache2.conf": "Include ports.conf\nIncludeOptional mods-enabled/*.conf\n",
        "/etc/apache2/ports.conf": "Listen 80\n",
        "/etc/apache2/mods-enabled/security2.conf": (
            "<IfModule security2_module>\n"
            "  IncludeOptional /etc/modsecurity/*.conf\n"
            "  # Include /etc/modsecurity/disabled/*.conf\n"
            "</IfModule>\n"
        ),
        "/etc/modsecurity/modsecurity.conf": "SecRuleEngine On\n",
        "/etc/modsecurity/loop.conf": "Include /etc/apache2/apache2.conf\n",
    }

    def _expand(self, pattern):
        return sorted(p for p in self.FILES if fnmatch(p, pattern))

    def test_follows_nested_globs_relative_to_server_root(self):
        files = resolve_includes(["/etc/apache2/apache2.conf"], self.FILES.get, self._expand)
        assert files == [
            "/etc/apache2/apache2.conf",
            "/etc/apache2/ports.conf",
            "/etc/apache2/mods-enabled/security2.conf",
            "/etc/modsecurity/loop.conf",
            "/etc/modsecurity/modsecurity.conf",
        ]

    def test_missing_target_is_skipped(self):
        assert resolve_includes(["/etc/none.conf"], self.FILES.get, self._expand) == []


class TestExpandConfigPath:
    def test_glob_uses_find_path_at_glob_depth(self):
        with patch(
            "nssec.modules.waf.conflicts.run_cmd",
            return_value=("/etc/m/b.conf\n/etc/m/a.conf\n", "", 0),
        ) as run:
            assert expand_config_path("/etc/m/*.conf") == ["/etc/m/a.conf", "/etc/m/b.conf"]
        assert run.call_args.args[0] == [
            "find", "-L", "/etc/m", "-mindepth", "1", "-maxdepth", "1",
            "-path", "/etc/m/*.conf", "-type", "f",
        ]  # fmt: skip

    def test_plain_path_is_a_file_or_directory(self):
        with patch("nssec.modules.waf.conflicts.run_cmd", return_value=("", "", 1)) as run:
            assert expand_config_path("/etc/m/rules") == []
        assert run.call_args.args[0] == ["find", "-L", "/etc/m/rules", "-type", "f"]


class TestListLoadedConfigs:
    def test_prefers_dump_includes(self):
        dump = (DUMP_OUTPUT, "", 0)
        with patch("nssec.modules.waf.conflicts.run_cmd", return_value=dump):
            with patch("nssec.modules.waf.conflicts.resolve_includes") as fallback:
                files = list_loaded_configs()
        assert "/etc/modsecurity/rules/custom.conf" in files
        fallback.assert_not_called()

    @pytest.mark.parametrize("dump", [(DUMP_OUTPUT, "config error", 1), ("", "", 0)])
    def test_falls_back_to_following_includes(self, dump):
        with patch("nssec.modules.waf.conflicts.run_cmd", return_value=dump), patch(
            "nssec.modules.waf.conflicts.resolve_includes", return_value=["/a.conf"]
        ) as fallback:
            assert list_loaded_configs() == ["/a.conf"]
        assert fallback.call_args.args[0] == ["/etc/apache2/apache2.conf"]


class TestFindRuleConflicts:
    def test_collides_with_known_crs_ids(self):
        files = {"/x.conf": 'SecAction "id:901001"\nSecAction "id:950000"\n'}
        conflicts = find_rule_conflicts(files, {901001, 901100})
        assert conflicts == [RuleConflict(path="/x.conf", ids=[901001])]

    def test_reserved_range_when_crs_not_on_disk(self):
        files = {"/x.conf": 'SecAction "id:899999"\nSecAction "id:950000"\n'}
        assert find_rule_conflicts(files, None) == [RuleConflict(path="/x.conf", ids=[950000])]

    def test_no_conflict(self):
        assert find_rule_conflicts({"/x.conf": 'SecAction "id:1000001"\n'}, None) == []

    def test_describe_lists_count_and_examples(self):
        text = describe_conflict(RuleConflict(path="/x.conf", ids=[1, 2, 3, 4]))
        assert text.startswith("/x.conf defines 4 rule id(s)")
        assert "e.g. 1, 2, 3, ..." in text


# ---------------------------------------------------------------------------
# Installer preflight, against a fake host
# ---------------------------------------------------------------------------

SEC2_WILDCARD = """\
<IfModule security2_module>
    IncludeOptional /etc/modsecurity/*.conf
    IncludeOptional /usr/share/modsecurity-crs/*.load
    Include /etc/modsecurity/rules/*.conf
</IfModule>
"""

CUSTOM_RULES = """\
# Custom rules
SecAction "id:901001,phase:1,pass,nolog"
SecRule ARGS "@rx foo" \\
    "id:901100,\\
    phase:2,deny"
SecAction "id:10000,phase:1,pass,nolog"
"""

CRS_RULE = 'SecRule ARGS "@rx x" "id:901001,phase:1"\nSecRule ARGS "@rx y" "id:901100,phase:1"\n'


def _base_fs():
    return {
        "/etc/apache2/apache2.conf": "IncludeOptional mods-enabled/*.conf\n",
        "/etc/apache2/mods-available/security2.conf": SEC2_WILDCARD,
        "/etc/apache2/mods-enabled/security2.conf": SEC2_WILDCARD,
        "/etc/modsecurity/modsecurity.conf": "SecRuleEngine DetectionOnly\n",
        "/usr/share/modsecurity-crs/owasp-crs.load": (
            "IncludeOptional /usr/share/modsecurity-crs/rules/*.conf\n"
        ),
        "/usr/share/modsecurity-crs/rules/REQUEST-901-INITIALIZATION.conf": CRS_RULE,
        "/etc/modsecurity/rules/custom.conf": CUSTOM_RULES,
    }


class FakeHost:
    """In-memory host: files plus the few commands the preflight runs."""

    def __init__(self, files, dump_ok=True):
        self.files = files
        self.dump_ok = dump_ok
        self.commands = []

    def read(self, path):
        return self.files.get(path)

    def is_dir(self, path):
        return any(p.startswith(path + "/") for p in self.files)

    def run(self, cmd, timeout=120):
        self.commands.append(cmd)
        if cmd[0] == "apache2ctl":
            if not self.dump_ok:
                return "", "Syntax error", 1
            return self._dump(), "", 0
        if cmd[0] == "find":
            pattern = cmd[cmd.index("-path") + 1] if "-path" in cmd else cmd[2]
            return "\n".join(self.expand(pattern)), "", 0
        if cmd[0] == "cat":
            return "".join(self.files.get(p, "") for p in cmd[1:]), "", 0
        return "", "", 0

    def expand(self, pattern):
        """What the find in expand_config_path returns on a real host."""
        if any(c in pattern for c in "*?["):
            depth = pattern.count("/")
            return sorted(p for p in self.files if fnmatch(p, pattern) and p.count("/") == depth)
        return sorted(p for p in self.files if p == pattern or p.startswith(pattern + "/"))

    def _dump(self):
        files = resolve_includes(["/etc/apache2/apache2.conf"], self.read, self.expand)
        lines = ["Included configuration files:"] + [f"  (1) {p}" for p in files]
        return "\n".join(lines) + "\n"


@pytest.fixture
def fake_host():
    """Patch the installer's host access onto a FakeHost; yields a factory."""
    from contextlib import ExitStack

    stack = ExitStack()
    writes = MagicMock(return_value=True)
    backups = MagicMock(return_value=None)

    def make(files, dump_ok=True):
        host = FakeHost(files, dump_ok)
        host.writes, host.backups = writes, backups
        for target, value in {
            "nssec.modules.waf.is_root": lambda: True,
            "nssec.modules.waf.package_installed": lambda pkg: True,
            "nssec.modules.waf.is_directory": host.is_dir,
            "nssec.modules.waf.file_exists": lambda p: p in host.files,
            "nssec.modules.waf.read_file": host.read,
            "nssec.modules.waf.utils.read_file": host.read,
            "nssec.modules.waf.conflicts.read_file": host.read,
            "nssec.modules.waf.run_cmd": host.run,
            "nssec.modules.waf.conflicts.run_cmd": host.run,
            "nssec.modules.waf.write_file": writes,
            "nssec.modules.waf.backup_file": backups,
        }.items():
            stack.enter_context(patch(target, value))
        return host

    with stack:
        yield make


def _installer():
    from nssec.modules.waf import ModSecurityInstaller

    return ModSecurityInstaller()


class TestPreflightRuleConflicts:
    def test_custom_rules_in_crs_range_block_init(self, fake_host):
        fake_host(_base_fs())
        pf = _installer().preflight(check_rule_conflicts=True)

        # The apt CRS include is commented out by init, so only the custom file clashes.
        assert pf.rule_conflicts == [
            RuleConflict(path="/etc/modsecurity/rules/custom.conf", ids=[901001, 901100])
        ]
        assert not pf.can_proceed
        assert any("custom.conf defines 2 rule id(s)" in e for e in pf.errors)

    def test_compares_against_crs_on_disk_when_v4_present(self, fake_host):
        files = _base_fs()
        files["/etc/modsecurity/crs/VERSION"] = "4.8.0\n"
        files["/etc/modsecurity/crs/rules/REQUEST-901-INITIALIZATION.conf"] = (
            'SecAction "id:901001,phase:1"\n'
        )
        fake_host(files)
        pf = _installer().preflight(check_rule_conflicts=True)

        # 901100 is in the CRS range but not in this CRS release.
        assert [c.ids for c in pf.rule_conflicts] == [[901001]]

    def test_uses_include_fallback_when_dump_fails(self, fake_host):
        host = fake_host(_base_fs(), dump_ok=False)
        pf = _installer().preflight(check_rule_conflicts=True)

        assert [c.path for c in pf.rule_conflicts] == ["/etc/modsecurity/rules/custom.conf"]
        assert any(cmd[0] == "find" for cmd in host.commands)

    def test_no_conflict_leaves_preflight_unchanged(self, fake_host):
        files = _base_fs()
        files["/etc/modsecurity/rules/custom.conf"] = 'SecAction "id:10000,phase:1"\n'
        fake_host(files)
        pf = _installer().preflight(check_rule_conflicts=True)

        assert pf.rule_conflicts == []
        assert pf.errors == []
        assert pf.can_proceed

    def test_same_crs_path_already_included_is_not_a_conflict(self, fake_host):
        sec2 = (
            "<IfModule security2_module>\n"
            "    IncludeOptional /etc/modsecurity/*.conf\n"
            "    IncludeOptional /etc/modsecurity/crs/rules/*.conf\n"
            "</IfModule>\n"
        )
        files = _base_fs()
        del files["/etc/modsecurity/rules/custom.conf"]
        files["/etc/apache2/mods-available/security2.conf"] = sec2
        files["/etc/apache2/mods-enabled/security2.conf"] = sec2
        files["/etc/modsecurity/crs/VERSION"] = "4.8.0\n"
        files["/etc/modsecurity/crs/rules/REQUEST-901-INITIALIZATION.conf"] = CRS_RULE
        fake_host(files)
        pf = _installer().preflight(check_rule_conflicts=True)

        assert pf.rule_conflicts == []
        assert pf.can_proceed

    def test_old_crs_still_loaded_beside_included_v4_is_a_conflict(self, fake_host):
        # security2.conf already names the v4 path, so init leaves it (and the
        # old CRS include) alone: both rule sets would load.
        sec2 = SEC2_WILDCARD.replace(
            "    Include /etc/modsecurity/rules/*.conf\n",
            "    IncludeOptional /etc/modsecurity/crs/rules/*.conf\n",
        )
        files = _base_fs()
        del files["/etc/modsecurity/rules/custom.conf"]
        files["/etc/apache2/mods-available/security2.conf"] = sec2
        files["/etc/apache2/mods-enabled/security2.conf"] = sec2
        files["/etc/modsecurity/crs/VERSION"] = "4.8.0\n"
        files["/etc/modsecurity/crs/rules/REQUEST-901-INITIALIZATION.conf"] = CRS_RULE
        fake_host(files)
        pf = _installer().preflight(check_rule_conflicts=True)

        assert [c.path for c in pf.rule_conflicts] == [
            "/usr/share/modsecurity-crs/rules/REQUEST-901-INITIALIZATION.conf"
        ]

    def test_includes_dropped_by_security2_rewrite_are_not_conflicts(self, fake_host):
        sec2 = "<IfModule security2_module>\n  Include /etc/modsecurity/rules/*.conf\n</IfModule>\n"
        files = _base_fs()
        files["/etc/apache2/mods-available/security2.conf"] = sec2
        files["/etc/apache2/mods-enabled/security2.conf"] = sec2
        fake_host(files)
        pf = _installer().preflight(check_rule_conflicts=True)

        assert not pf.security2_has_wildcard
        assert pf.rule_conflicts == []

    def test_managed_files_are_not_scanned(self, fake_host):
        files = _base_fs()
        del files["/etc/modsecurity/rules/custom.conf"]
        files["/etc/modsecurity/netsapiens-exclusions.conf"] = 'SecAction "id:950000"\n'
        files["/etc/modsecurity/modsecurity.conf"] = 'SecAction "id:950001"\n'
        fake_host(files)
        assert _installer().preflight(check_rule_conflicts=True).rule_conflicts == []

    def test_skipped_unless_asked(self, fake_host):
        host = fake_host(_base_fs())
        pf = _installer().preflight()

        assert pf.rule_conflicts == []
        assert not any(cmd[0] == "apache2ctl" for cmd in host.commands)

    def test_warns_when_configs_cannot_be_listed(self, fake_host):
        fake_host({"/etc/apache2/mods-available/security2.conf": SEC2_WILDCARD}, dump_ok=False)
        pf = _installer().preflight(check_rule_conflicts=True)

        assert pf.rule_conflicts == []
        assert any("conflict check skipped" in w for w in pf.warnings)


class TestRunAbortsOnConflict:
    def test_no_step_runs_and_nothing_is_written(self, fake_host):
        host = fake_host(_base_fs())
        result = _installer().run()

        assert not result.success
        assert result.steps_completed == []
        assert any("custom.conf" in e for e in result.errors)
        host.writes.assert_not_called()
        host.backups.assert_not_called()
        ran = {cmd[0] for cmd in host.commands}
        assert ran <= {"systemctl", "apache2ctl", "find", "cat"}


class TestInitCommandOnConflict:
    def test_refuses_and_shows_conflict_in_plan(self):
        from click.testing import CliRunner

        from nssec.cli.waf_commands import waf
        from nssec.modules.waf.types import PreflightResult

        pf = PreflightResult(is_root=True, apache_installed=True)
        pf.rule_conflicts = [RuleConflict(path="/etc/modsecurity/rules/custom.conf", ids=[901001])]
        pf.errors.append(describe_conflict(pf.rule_conflicts[0]))

        with patch("nssec.modules.waf.ModSecurityInstaller") as cls:
            installer = cls.return_value
            installer.preflight.return_value = pf
            result = CliRunner().invoke(waf, ["init", "-y"])

        assert result.exit_code == 1
        assert "Installation Plan" in result.output
        assert "blocked" in result.output
        assert "custom.conf" in result.output
        assert "No changes were made" in result.output
        installer.preflight.assert_called_once_with(check_rule_conflicts=True)
        installer.run.assert_not_called()
