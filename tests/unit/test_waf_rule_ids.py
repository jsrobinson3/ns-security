"""Rendered exclusions must never carry the same rule id twice.

Apache refuses to load a ModSecurity config with duplicate ids, so a collision
between two independently-added rules breaks every install and update.
"""

import itertools
import re

import pytest

from nssec.modules.waf import render_exclusions
from nssec.modules.waf.cluster import ClusterPeers
from nssec.modules.waf.config import EXCLUSION_TOGGLE_DEFAULTS

TOGGLE_COMBOS = [
    dict(zip(EXCLUSION_TOGGLE_DEFAULTS, values))
    for values in itertools.product([True, False], repeat=len(EXCLUSION_TOGGLE_DEFAULTS))
]


def _combo_id(toggles):
    return "".join(str(int(v)) for v in toggles.values())


@pytest.mark.parametrize("toggles", TOGGLE_COMBOS, ids=_combo_id)
def test_no_duplicate_rule_ids(toggles):
    content = render_exclusions(
        ["192.0.2.10", "198.51.100.0/24"],
        ["203.0.113.5"],
        toggles,
        ClusterPeers(),
    )
    ids = re.findall(r'"id:(\d+)', content)
    assert ids
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    assert not duplicates, f"duplicate rule ids: {duplicates}"
