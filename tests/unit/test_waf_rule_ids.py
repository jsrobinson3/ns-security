"""The rendered exclusions file must never define the same rule id twice.

ModSecurity refuses to load a config with duplicate ids, so Apache fails its
configtest and ``nssec waf init`` rolls back. Two exclusions added on separate
branches can each claim the next free id and still merge without a textual
conflict, so the rendered output is checked, not just the template source.
"""

import itertools
import re
from collections import Counter

import pytest

from nssec.modules.waf import render_exclusions
from nssec.modules.waf.cluster import ClusterPeers
from nssec.modules.waf.config import EXCLUSION_TOGGLE_DEFAULTS

_RULE_ID = re.compile(r"(?<![\w.])id:'?(\d+)")

# RFC 5737 documentation addresses
ADMIN_IPS = ["192.0.2.1", "192.0.2.2", "198.51.100.0/24"]
NODEPING_IPS = ["192.0.2.50", "192.0.2.51"]
PEERS = ClusterPeers(
    peers={"203.0.113.10": "core-a.example.test", "203.0.113.11": "core-b.example.test"}
)


def _rule_ids(rendered: str) -> list[str]:
    ids: list[str] = []
    for line in rendered.splitlines():
        if line.lstrip().startswith("#"):
            continue
        ids.extend(_RULE_ID.findall(line))
    return ids


def _toggle_combinations():
    names = sorted(EXCLUSION_TOGGLE_DEFAULTS)
    for values in itertools.product([False, True], repeat=len(names)):
        yield dict(zip(names, values))


def _duplicates(rendered: str) -> dict[str, int]:
    return {rule_id: n for rule_id, n in Counter(_rule_ids(rendered)).items() if n > 1}


@pytest.mark.parametrize(
    "toggles",
    list(_toggle_combinations()),
    ids=lambda t: "".join("1" if v else "0" for v in t.values()),
)
def test_no_duplicate_rule_ids(toggles):
    rendered = render_exclusions(ADMIN_IPS, NODEPING_IPS, toggles, PEERS)
    assert _duplicates(rendered) == {}


def test_no_duplicate_rule_ids_with_no_ips_or_peers():
    rendered = render_exclusions([], [], dict(EXCLUSION_TOGGLE_DEFAULTS), ClusterPeers())
    assert _duplicates(rendered) == {}


def test_rule_ids_are_extracted():
    """Guards the helper: a regex that matched nothing would pass every test above."""
    rendered = render_exclusions(ADMIN_IPS, NODEPING_IPS, dict(EXCLUSION_TOGGLE_DEFAULTS), PEERS)
    assert len(_rule_ids(rendered)) > 40
