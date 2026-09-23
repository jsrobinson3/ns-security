"""Tests for API scrape protection (nssec.modules.waf.scrape)."""

import ipaddress
import re
from unittest.mock import patch

import pytest
from jinja2 import Template

from nssec.modules.waf import scrape
from nssec.modules.waf.config import (
    BACKUP_SUFFIX,
    NS_EXCLUSIONS_CONF,
    SCRAPE_CONF,
    SCRAPE_PROFILES,
    SCRAPE_TEMPLATE_HASH,
    SECURITY2_CONF,
    SECURITY2_CONF_TEMPLATE,
)
from nssec.modules.waf.scrape import LOOPBACK_IPS, ScrapeSettings

EXEMPT = ["127.0.0.1", "::1", "203.0.113.10"]


def _render(**overrides):
    return scrape.render_scrape_conf(ScrapeSettings(**overrides), EXEMPT)


def _rules(content):
    """Map rule id -> rule text (indented chained sub-rules included), in load order."""
    rules = {}
    for chunk in re.split(r"\n(?=\S)", content):
        if chunk.startswith("SecRule "):
            rules[int(re.search(r'"id:(\d+)', chunk).group(1))] = chunk
    return rules


class TestScrapeTemplate:
    def test_rule_ids_unique_and_in_scrape_band(self):
        ids = [int(i) for i in re.findall(r'"id:(\d+)', _render(mode="block"))]
        assert len(ids) == len(set(ids))
        assert all(1002000 <= i <= 1002999 for i in ids)

    def test_ids_invisible_to_exclusions_allowlist_parsers(self):
        # status and _parse_allowlist_ips count "id:10001xx" / "id:10002xx" as IPs
        assert re.findall(r'"id:1000[12]\d+', _render(mode="block")) == []

    def test_exemption_is_first_rule_and_removes_whole_tag(self):
        rules = _rules(_render())
        assert list(rules)[0] == 1002001
        exempt = rules[1002001]
        assert '"@ipMatch 127.0.0.1,::1,203.0.113.10"' in exempt
        assert "phase:1" in exempt
        assert "ctl:ruleRemoveByTag=nssec-scrape" in exempt

    def test_every_other_rule_carries_the_exemption_tag(self):
        for rule_id, text in _rules(_render(mode="block")).items():
            if rule_id != 1002001:
                assert "tag:'nssec-scrape'" in text, rule_id

    def test_detect_mode_never_denies(self):
        for text in _rules(_render(mode="detect")).values():
            assert "deny" not in text

    def test_block_mode_denies_over_limit_clients_with_429(self):
        rules = _rules(_render(mode="block"))
        for rule_id in (1002011, 1002022, 1002044):
            assert "deny" in rules[rule_id]
            assert "status:429" in rules[rule_id]

    def test_block_mode_refuses_scraper_user_agents_with_403(self):
        ua_rule = _rules(_render(mode="block"))[1002002]
        assert "deny,status:403" in ua_rule
        assert '"@pm harvest/"' in ua_rule

    def test_enforcement_rule_only_rendered_in_block_mode(self):
        assert 1002011 not in _rules(_render(mode="detect"))

    def test_user_agent_rule_omitted_when_list_empty(self):
        assert 1002002 not in _rules(_render(bad_user_agents=[]))

    def test_counter_increments_do_not_reset_the_window(self):
        """Re-issuing expirevar on each hit would turn the window into an idle timeout."""
        increments = [t for t in _rules(_render()).values() if re.search(r"ip\.\w+=\+1", t)]
        assert len(increments) == 2
        for text in increments:
            assert "expirevar" not in text

    def test_counter_windows_set_only_on_creation(self):
        rules = _rules(_render())
        window = SCRAPE_PROFILES["standard"]["window"]
        for var, rule_id in (("nssec_requests", 1002020), ("nssec_domains", 1002042)):
            assert f'&IP:{var} "@eq 0"' in rules[rule_id]
            assert f"expirevar:ip.{var}={window}" in rules[rule_id]

    def test_limit_rules_log_once_per_flag_period(self):
        rules = _rules(_render())
        for rule_id in (1002022, 1002044):
            assert '&IP:nssec_flagged "@eq 0"' in rules[rule_id]
            assert "setvar:ip.nssec_flagged=1" in rules[rule_id]

    def test_profile_thresholds_rendered(self):
        strict = SCRAPE_PROFILES["strict"]
        rules = _rules(_render(profile="strict"))
        assert f'"@gt {strict["max_requests"]}"' in rules[1002022]
        assert f'"@gt {strict["max_domains"]}"' in rules[1002044]

    def test_overrides_replace_profile_thresholds(self):
        rules = _rules(_render(max_requests=777, max_domains=9))
        assert '"@gt 777"' in rules[1002022]
        assert '"@gt 9"' in rules[1002044]

    def test_domain_taken_from_v1_argument_and_v2_path(self):
        rules = _rules(_render())
        assert "ARGS:domain" in rules[1002030]
        assert "ns-api/v2/domains/" in rules[1002031]

    def test_domain_pattern_accepts_tenants_and_rejects_junk(self):
        pattern = re.search(r'ARGS:domain "@rx (\S+)"', _rules(_render())[1002030]).group(1)
        for good in ("wilkesborohealth", "acme.example", "a_b-c"):
            assert re.match(pattern, good)
        for bad in ("", "../etc", "a b", "x" * 200):
            assert not re.match(pattern, bad)

    def test_only_reads_count_toward_enumeration(self):
        rules = _rules(_render())
        assert "read|count|list" in rules[1002032]
        assert '"@streq GET"' in rules[1002033]
        assert 'TX:nssec_read "@eq 1"' in rules[1002040]

    def test_embeds_template_hash_and_settings(self):
        content = _render(mode="block", max_domains=9)
        assert f"# nssec-scrape-hash: {SCRAPE_TEMPLATE_HASH}" in content
        assert scrape.parse_scrape_settings(content) == ScrapeSettings(mode="block", max_domains=9)


class TestSecurity2Layout:
    def test_template_loads_scrape_conf_after_exclusions(self):
        rendered = Template(SECURITY2_CONF_TEMPLATE).render(
            timestamp="t", crs_path="/etc/modsecurity/crs"
        )
        excl = rendered.index(f"IncludeOptional {NS_EXCLUSIONS_CONF}")
        assert excl < rendered.index(f"IncludeOptional {SCRAPE_CONF}")
        assert scrape.security2_includes_scrape(rendered)

    def test_wildcard_include_sorts_scrape_conf_after_exclusions(self):
        assert sorted([SCRAPE_CONF, NS_EXCLUSIONS_CONF]) == [NS_EXCLUSIONS_CONF, SCRAPE_CONF]


class TestValidateSettings:
    def test_defaults_are_valid(self):
        assert scrape.validate_settings(ScrapeSettings()) == []

    @pytest.mark.parametrize(
        "overrides",
        [
            {"mode": "on"},
            {"profile": "paranoid"},
            {"max_domains": 0},
            {"max_requests": -5},
            {"exempt_ips": ["not-an-ip"]},
            {"exempt_ips": ["fe80::1%eth0"]},
            {"bad_user_agents": ["python requests"]},
            {"bad_user_agents": ['evil"quote']},
        ],
    )
    def test_rejects_invalid(self, overrides):
        assert scrape.validate_settings(ScrapeSettings(**overrides))

    def test_accepts_cidr_and_ipv6(self):
        settings = ScrapeSettings(exempt_ips=["198.51.100.0/24", "2001:db8::1"])
        assert scrape.validate_settings(settings) == []


class TestParseScrapeSettings:
    def test_none_without_header(self):
        assert scrape.parse_scrape_settings("# nothing here\n") is None

    def test_none_on_malformed_json(self):
        assert scrape.parse_scrape_settings("# nssec-scrape-settings: {oops\n") is None

    def test_none_on_wrong_list_type(self):
        content = '# nssec-scrape-settings: {"exempt_ips": "1.2.3.4"}\n'
        assert scrape.parse_scrape_settings(content) is None

    def test_ignores_unknown_keys(self):
        content = '# nssec-scrape-settings: {"mode": "block", "future_knob": 1}\n'
        assert scrape.parse_scrape_settings(content) == ScrapeSettings(mode="block")


class TestGetLocalIps:
    def test_parses_hostname_output(self):
        out = "10.0.0.5 203.0.113.10 2001:db8::5 fe80::1 junk\n"
        with patch("nssec.modules.waf.scrape.run_cmd", return_value=(out, "", 0)):
            assert scrape.get_local_ips() == ["10.0.0.5", "203.0.113.10", "2001:db8::5"]

    def test_empty_on_command_failure(self):
        with patch("nssec.modules.waf.scrape.run_cmd", return_value=("", "boom", 1)):
            assert scrape.get_local_ips() == []


class TestResolveExemptIpsInvariants:
    """Policy-agnostic guarantees the rendered @ipMatch relies on."""

    def _resolve(self, settings=None, admin=(), local=()):
        return scrape.resolve_exempt_ips(settings or ScrapeSettings(), list(admin), list(local))

    def test_always_includes_loopback(self):
        result = self._resolve()
        for ip in LOOPBACK_IPS:
            assert ip in result

    def test_includes_operator_exempt_ips(self):
        result = self._resolve(ScrapeSettings(exempt_ips=["198.51.100.0/24"]))
        assert "198.51.100.0/24" in result

    def test_no_duplicates(self):
        settings = ScrapeSettings(exempt_ips=["127.0.0.1", "203.0.113.10"])
        result = self._resolve(settings, admin=["203.0.113.10"], local=["203.0.113.10"])
        assert len(result) == len(set(result))

    def test_every_entry_is_a_valid_network(self):
        settings = ScrapeSettings(exempt_ips=["198.51.100.7"])
        for entry in self._resolve(settings, admin=["203.0.113.0/24"], local=["10.0.0.5"]):
            ipaddress.ip_network(entry, strict=False)


SEC2 = """\
<IfModule security2_module>
    IncludeOptional /etc/modsecurity/modsecurity.conf
    IncludeOptional /etc/modsecurity/crs/crs-setup.conf
    IncludeOptional /etc/modsecurity/netsapiens-exclusions.conf
    IncludeOptional /etc/modsecurity/crs/rules/*.conf
</IfModule>
"""


@pytest.fixture
def io():
    with patch("nssec.modules.waf.scrape.read_file") as read, patch(
        "nssec.modules.waf.scrape.write_file", return_value=True
    ) as write, patch("nssec.modules.waf.scrape.backup_file") as backup, patch(
        "nssec.modules.waf.scrape.file_exists", return_value=False
    ) as exists, patch(
        "nssec.modules.waf.scrape.remove_file", return_value=True
    ) as remove:
        yield {"read": read, "write": write, "backup": backup, "exists": exists, "remove": remove}


class TestEnsureSecurity2Include:
    def test_inserts_after_exclusions_with_matching_indent(self, io):
        io["read"].return_value = SEC2
        result = scrape.ensure_security2_include()

        assert result.success and not result.skipped
        written = io["write"].call_args[0][1]
        lines = written.splitlines()
        excl = lines.index(f"    IncludeOptional {NS_EXCLUSIONS_CONF}")
        assert lines[excl + 1] == f"    IncludeOptional {SCRAPE_CONF}"
        io["backup"].assert_called_once_with(SECURITY2_CONF)

    def test_skips_when_already_included(self, io):
        io["read"].return_value = SEC2 + f"IncludeOptional {SCRAPE_CONF}\n"
        assert scrape.ensure_security2_include().skipped
        io["write"].assert_not_called()

    def test_skips_on_wildcard_include(self, io):
        io["read"].return_value = "IncludeOptional /etc/modsecurity/*.conf\n"
        assert scrape.ensure_security2_include().skipped

    def test_commented_include_does_not_count(self, io):
        io["read"].return_value = SEC2 + f"# IncludeOptional {SCRAPE_CONF}\n"
        result = scrape.ensure_security2_include()
        assert not result.skipped
        io["write"].assert_called_once()

    def test_errors_when_exclusions_not_included(self, io):
        io["read"].return_value = "IncludeOptional /etc/modsecurity/modsecurity.conf\n"
        result = scrape.ensure_security2_include()
        assert not result.success
        assert "update-exclusions" in result.error
        io["write"].assert_not_called()

    def test_errors_when_security2_missing(self, io):
        io["read"].return_value = None
        assert not scrape.ensure_security2_include().success

    def test_dry_run_does_not_write(self, io):
        io["read"].return_value = SEC2
        assert scrape.ensure_security2_include(dry_run=True).success
        io["write"].assert_not_called()
        io["backup"].assert_not_called()


class TestWriteScrapeConf:
    def test_writes_rendered_rules(self, io):
        result = scrape.write_scrape_conf(ScrapeSettings(), EXEMPT)

        assert result.success
        path, content = io["write"].call_args[0]
        assert path == SCRAPE_CONF
        assert SCRAPE_TEMPLATE_HASH in content

    def test_backs_up_existing_conf(self, io):
        io["exists"].return_value = True
        scrape.write_scrape_conf(ScrapeSettings(), EXEMPT)
        io["backup"].assert_called_once_with(SCRAPE_CONF)

    def test_rejects_invalid_settings_without_writing(self, io):
        result = scrape.write_scrape_conf(ScrapeSettings(mode="yolo"), EXEMPT)
        assert not result.success
        io["write"].assert_not_called()

    def test_rejects_invalid_exempt_entry_without_writing(self, io):
        result = scrape.write_scrape_conf(ScrapeSettings(), EXEMPT + ["bogus"])
        assert not result.success
        assert "bogus" in result.error
        io["write"].assert_not_called()

    def test_dry_run_does_not_write(self, io):
        assert scrape.write_scrape_conf(ScrapeSettings(), EXEMPT, dry_run=True).success
        io["write"].assert_not_called()


class TestRemoveScrapeConf:
    def test_skips_when_not_deployed(self, io):
        assert scrape.remove_scrape_conf().skipped
        io["remove"].assert_not_called()

    def test_backs_up_then_removes(self, io):
        io["exists"].return_value = True
        result = scrape.remove_scrape_conf()
        assert result.success and not result.skipped
        io["backup"].assert_called_once_with(SCRAPE_CONF)
        io["remove"].assert_called_once_with(SCRAPE_CONF)


class TestRollbackScrape:
    @pytest.fixture
    def paths(self, tmp_path):
        conf = tmp_path / "scrape.conf"
        sec2 = tmp_path / "security2.conf"
        with patch.object(scrape, "SCRAPE_CONF", str(conf)), patch.object(
            scrape, "SECURITY2_CONF", str(sec2)
        ):
            yield conf, sec2

    def test_deletes_conf_that_did_not_exist_before(self, paths):
        conf, _ = paths
        conf.write_text("new")
        conf.with_name(conf.name + BACKUP_SUFFIX).write_text("stale backup from an earlier run")

        scrape.rollback_scrape(conf_existed=False, security2_changed=False)

        assert not conf.exists()

    def test_restores_previous_conf(self, paths):
        conf, _ = paths
        conf.write_text("broken")
        conf.with_name(conf.name + BACKUP_SUFFIX).write_text("known good")

        scrape.rollback_scrape(conf_existed=True, security2_changed=False)

        assert conf.read_text() == "known good"

    def test_restores_security2_only_when_changed(self, paths):
        _, sec2 = paths
        sec2.write_text("edited")
        sec2.with_name(sec2.name + BACKUP_SUFFIX).write_text("original")

        scrape.rollback_scrape(conf_existed=False, security2_changed=False)
        assert sec2.read_text() == "edited"

        scrape.rollback_scrape(conf_existed=False, security2_changed=True)
        assert sec2.read_text() == "original"


class TestValidateApacheConfig:
    def test_passes_without_rollback(self):
        with patch("nssec.modules.waf.scrape.run_cmd", return_value=("Syntax OK", "", 0)), patch(
            "nssec.modules.waf.scrape.rollback_scrape"
        ) as rollback:
            assert scrape.validate_apache_config(conf_existed=False, security2_changed=True).success
        rollback.assert_not_called()

    def test_failure_rolls_back_this_runs_changes(self):
        with patch("nssec.modules.waf.scrape.run_cmd", return_value=("", "bad ipMatch", 1)), patch(
            "nssec.modules.waf.scrape.rollback_scrape"
        ) as rollback:
            result = scrape.validate_apache_config(conf_existed=True, security2_changed=False)
        assert not result.success
        assert "bad ipMatch" in result.error
        rollback.assert_called_once_with(conf_existed=True, security2_changed=False)


class TestGetScrapeStatus:
    def _status(self, files):
        with patch("nssec.modules.waf.scrape.read_file", side_effect=files.get):
            return scrape.get_scrape_status()

    def test_not_deployed(self):
        status = self._status({})
        assert not status.deployed
        assert status.settings is None

    def test_deployed_current_and_loaded(self):
        status = self._status(
            {
                SCRAPE_CONF: _render(mode="block"),
                SECURITY2_CONF: f"    IncludeOptional {SCRAPE_CONF}\n",
            }
        )
        assert status.deployed and status.included and status.current
        assert status.settings.mode == "block"

    def test_outdated_when_template_hash_differs(self):
        stale = _render().replace(SCRAPE_TEMPLATE_HASH, "000000000000")
        status = self._status({SCRAPE_CONF: stale})
        assert status.deployed and not status.current and not status.included
