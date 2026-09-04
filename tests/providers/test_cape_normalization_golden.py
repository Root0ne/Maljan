"""The CAPE round trip is an identity, and the render is complete without it.

Three properties, one file:
  (a) a CAPE-sourced report renders to *the same object* it came from, so no
      consumer can observe the provider layer at all;
  (b) the extractors agree on the rendered dict and on the raw one;
  (c) with ``raw`` emptied — the path a non-CAPE provider takes — the render
      still carries every key the nine consumers read.
"""

from __future__ import annotations

import pytest

from maljan.extractors.dynamic_extractor import build_dynamic_behavior
from maljan.extractors.network_extractor import build_network_iocs
from maljan.providers.cape_view import to_cape_shaped_dict
from maljan.schemas.sandbox_report import cape_report_to_sandbox_report
from tests.providers.test_extractor_golden import cape_reports, dump

_REPORTS = cape_reports()
_IDS = [n for n, _ in _REPORTS]

# Every path the table in the plan's Task 6 names, as (path, kind). Two
# groups go beyond the brief's own (narrower) CONSUMER_KEYS tuple:
#
# - ``target.file.type`` and ``ttp_tags`` are rows in the brief's own
#   markdown table that its shown test code never turned into an assertion;
#   the render already produces both, so they are added here to close that
#   gap rather than leave it silently untested.
# - The four ``behavior.summary.*`` keys and the top-level ``file_writes``
#   array are the two model additions ruled in during the pre-flight scan —
#   the brief's own consumer-key table names them (persistence_extractor's
#   Linux path rules read all six), but its own render code only reproduced
#   ``behavior.summary`` as a bare ``{"keys": [...]}`` shell, so they are
#   listed here individually rather than folded into one dict-shaped entry.
#
# Not listed: ``network.pcap_local_path`` has its own dedicated test below
# (it is only ever present conditionally, never an empty placeholder), and
# ``behavior.notable_apis`` / ``dynamic.notable_apis`` is a known, accepted
# gap — out of scope for this task's two ruled additions — see the task
# report's concerns section.
CONSUMER_KEYS: tuple[tuple[str, str], ...] = (
    ("target.sha256", "scalar"),
    ("target.md5", "scalar"),
    ("target.name", "scalar"),
    ("target.file.type", "scalar"),
    ("behavior.processes", "list"),
    ("behavior.calls", "list"),
    ("behavior.apistats", "dict"),
    ("behavior.generic", "list"),
    ("behavior.summary", "dict"),
    ("behavior.summary.files", "list"),
    ("behavior.summary.write_files", "list"),
    ("behavior.summary.modified_files", "list"),
    ("behavior.summary.wrote_files", "list"),
    ("file_writes", "list"),
    ("signatures", "list"),
    ("network.dns", "list"),
    ("network.http", "list"),
    ("network.tcp", "list"),
    ("network.udp", "list"),
    ("network.hosts", "list"),
    ("network.domains", "list"),
    ("network.tls", "list"),
    ("cti", "dict"),
    ("ttp_tags", "list"),
)


def _at(d, path):
    cursor = d
    for part in path.split("."):
        assert isinstance(cursor, dict), path
        assert part in cursor, f"missing {path}"
        cursor = cursor[part]
    return cursor


@pytest.mark.parametrize("name,raw", _REPORTS, ids=_IDS)
def test_cape_render_is_the_same_object(name, raw):
    report = cape_report_to_sandbox_report(raw, provider="cape2")
    assert to_cape_shaped_dict(report) is raw


@pytest.mark.parametrize("name,raw", _REPORTS, ids=_IDS)
def test_extractors_agree_on_rendered_and_raw(name, raw):
    rendered = to_cape_shaped_dict(cape_report_to_sandbox_report(raw, provider="cape2"))
    assert dump(build_dynamic_behavior(rendered)) == dump(build_dynamic_behavior(raw))
    assert dump(build_network_iocs(rendered)) == dump(build_network_iocs(raw))


@pytest.mark.parametrize("name,raw", _REPORTS[:5], ids=_IDS[:5])
def test_the_render_reproduces_every_consumer_key_without_the_short_circuit(name, raw):
    report = cape_report_to_sandbox_report(raw, provider="cape2").model_copy(update={"raw": {}})
    rendered = to_cape_shaped_dict(report)
    assert rendered is not raw
    for path, kind in CONSUMER_KEYS:
        value = _at(rendered, path)
        assert isinstance(
            value, {"list": list, "dict": dict}.get(kind, (str, int, float, type(None)))
        )


@pytest.mark.parametrize("name,raw", _REPORTS[:5], ids=_IDS[:5])
def test_the_rendered_extractors_still_find_what_the_raw_ones_found(name, raw):
    """The rendered dict is not merely shaped right; it carries the same evidence."""
    report = cape_report_to_sandbox_report(raw, provider="cape2").model_copy(update={"raw": {}})
    rendered = to_cape_shaped_dict(report)
    raw_dyn, new_dyn = build_dynamic_behavior(raw), build_dynamic_behavior(rendered)
    if raw_dyn is None:
        assert new_dyn is None
    else:
        assert new_dyn is not None
        assert len(new_dyn.process_tree) == len(raw_dyn.process_tree)
        assert [s.name for s in new_dyn.sandbox_signatures] == [
            s.name for s in raw_dyn.sandbox_signatures
        ]
    raw_net, new_net = build_network_iocs(raw), build_network_iocs(rendered)
    if raw_net is None:
        assert new_net is None
    else:
        assert new_net is not None
        assert {d.fqdn for d in new_net.domains} == {d.fqdn for d in raw_net.domains}
        assert {i.address for i in new_net.ips} == {i.address for i in raw_net.ips}


def test_pcap_path_and_unavailable_survive_the_render():
    report = cape_report_to_sandbox_report(
        {"target": {"sha256": "a" * 64}, "network": {"pcap_local_path": "/tmp/x.pcap"}},
        provider="triage",
        source_format="triage",
    ).model_copy(update={"unavailable": ["apistats", "calls"]})
    rendered = to_cape_shaped_dict(report)
    assert rendered["network"]["pcap_local_path"] == "/tmp/x.pcap"
    assert rendered["unavailable"] == ["apistats", "calls"]
