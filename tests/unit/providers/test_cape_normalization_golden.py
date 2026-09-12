"""The CAPE round trip is an identity, and the render is complete without it.

Three properties, one file:
  (a) a CAPE-sourced report renders to *the same object* it came from, so no
      consumer can observe the provider layer at all;
  (b) the sandbox tools answer the same on the rendered dict and on the raw one;
  (c) with ``raw`` emptied — the path a non-CAPE provider takes — the render
      still carries every key the nine consumers read.
"""

from __future__ import annotations

import pytest

from maljan.providers.cape_view import to_cape_shaped_dict
from maljan.schemas.sandbox_report import cape_report_to_sandbox_report
from tests.unit._ledger_helpers import sandbox_view
from tests.unit.providers.test_sandbox_tools_golden import cape_reports

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
#   the brief's own consumer-key table names them (an agent hunting Linux
#   persistence reads all six), but its own render code only reproduced
#   ``behavior.summary`` as a bare ``{"keys": [...]}`` shell, so they are
#   listed here individually rather than folded into one dict-shaped entry.
#
# Not listed: ``network.pcap_local_path`` has its own dedicated test below
# (it is only ever present conditionally, never an empty placeholder), and
# ``behavior.notable_apis`` / ``dynamic.notable_apis`` stays unmodeled here —
# Task 7 resolved that carried finding by showing neither provider it built
# ever takes this full-render path with a real report (see
# tests/unit/providers/sandbox/test_cape2_provider.py and the task report), so
# this file's own scope — the render used when ``raw`` is empty — is
# unchanged by that resolution.
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
def test_the_tools_answer_the_same_on_rendered_and_raw(name, raw):
    rendered = to_cape_shaped_dict(cape_report_to_sandbox_report(raw, provider="cape2"))
    assert sandbox_view(rendered) == sandbox_view(raw)


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
def test_the_rendered_report_still_answers_what_the_raw_one_answered(name, raw):
    """The rendered dict is not merely shaped right; it carries the same evidence."""
    report = cape_report_to_sandbox_report(raw, provider="cape2").model_copy(update={"raw": {}})
    rendered = to_cape_shaped_dict(report)
    raw_view, new_view = sandbox_view(raw), sandbox_view(rendered)
    assert len(new_view["sandbox_processes"]["processes"]) == len(
        raw_view["sandbox_processes"]["processes"]
    )
    assert [s["name"] for s in new_view["sandbox_signatures"]["signatures"]] == [
        s["name"] for s in raw_view["sandbox_signatures"]["signatures"]
    ]
    # Empty kinds are dropped before the comparison: the render carries a
    # ``tls`` placeholder the raw report does not and omits an ``icmp`` one it
    # does, and neither absence is evidence about the sample.
    assert _nonempty(new_view["sandbox_network"]) == _nonempty(raw_view["sandbox_network"])


def _nonempty(view: dict) -> dict:
    """One tool answer with the kinds it found nothing for left out."""
    return {key: value for key, value in view.items() if value}


def test_pcap_path_and_unavailable_survive_the_render():
    report = cape_report_to_sandbox_report(
        {"target": {"sha256": "a" * 64}, "network": {"pcap_local_path": "/tmp/x.pcap"}},
        provider="triage",
        source_format="triage",
    ).model_copy(update={"unavailable": ["apistats", "calls"]})
    rendered = to_cape_shaped_dict(report)
    assert rendered["network"]["pcap_local_path"] == "/tmp/x.pcap"
    assert rendered["unavailable"] == ["apistats", "calls"]


def test_file_writes_survives_the_render_as_the_flat_list_it_is():
    """Carried finding: ``file_writes``/``registry`` were filtered with ``_rows``
    (dict entries only), but the real shape is a flat list of path strings, so
    the dict-only filter silently dropped every real entry on the
    non-short-circuit render path. The agent that reads this section asks for
    it by name, so the assertion is on what that call returns.
    """
    raw = {
        "target": {"sha256": "a" * 64},
        "file_writes": ["/etc/rc.local", "/etc/ld.so.preload"],
    }
    report = cape_report_to_sandbox_report(raw, provider="cape2").model_copy(update={"raw": {}})
    rendered = to_cape_shaped_dict(report)
    assert rendered is not raw
    assert rendered["file_writes"] == ["/etc/rc.local", "/etc/ld.so.preload"]

    from maljan.providers.sandbox_tools import sandbox_report_section

    raw_section = sandbox_report_section(raw, "file_writes")
    rendered_section = sandbox_report_section(rendered, "file_writes")
    assert raw_section["rows"] == ["/etc/rc.local", "/etc/ld.so.preload"]
    assert rendered_section == raw_section
