"""A dotted name written as a Windows kernel object's name is no host, unless the evidence holds it.

A mutex named ``Global\\mtx.app`` printed as ``Global\\mtx[.]app`` in the
report's identifier table: the string sweep (the IOC reader) and the prose
host reader both took the name after the namespace for a host under ``.app``.
No resolver reads a kernel object namespace (``Global\\``, ``Local\\``,
``Session\\<n>\\``, ``BaseNamedObjects\\``), so both readers now leave such a
name out. The run's network evidence still decides: a value it holds is
defanged by the run's own pass wherever it stands, and a check that can ask
the IOC table reads the name and drops it only when no row holds it.
"""

from __future__ import annotations

from maljan.pipeline.validation import (
    needs_network_evidence,
    network_values_in,
    unpublished_value_violations,
)
from maljan.reporting.defang import ProseDefanger
from maljan.reporting.renderers.markdown import _defanged_text
from maljan.tools.strings import iocs_from_text

NAMES = (
    "Global\\mtx.app",
    "Local\\sync.top",
    "Session\\1\\x1.example.com",
    "\\BaseNamedObjects\\mtx.app",
    "GLOBAL\\MTX.APP",
    "Global\\dl.delivery.mp.microsoft.com",
    "Global\\x.icu",
)


def _domains(text: str) -> list[str]:
    return [row["value"] for row in iocs_from_text(text, ["domain"])["iocs"]]


class TestBothReadersAgree:
    def test_the_sweep_reads_no_host_in_an_object_name(self) -> None:
        for name in NAMES:
            assert _domains(f"mutex {name} created") == [], name

    def test_the_host_reader_reads_none_either(self) -> None:
        for name in NAMES:
            assert network_values_in(f"It creates the mutex {name}.") == [], name

    def test_the_report_prints_the_name_as_written(self) -> None:
        for name in NAMES:
            assert _defanged_text(f"It creates the mutex {name}.") == (
                f"It creates the mutex {name}."
            ), name


class TestEverythingElseStaysAHost:
    def test_a_unc_host_a_path_s_last_name_and_a_bare_mention(self) -> None:
        assert _domains("\\\\fileserver.example.com\\share") == ["fileserver.example.com"]
        assert _domains("C:\\Users\\a\\evil.com") == ["evil.com"]
        assert _domains("MyGlobal\\mtx.app") == ["mtx.app"]
        assert network_values_in("Global\\mtx.app, then it resolves mtx.app.") == [
            ("domain", "mtx.app")
        ]

    def test_a_link_form_is_defanged_whatever_comes_before_it(self) -> None:
        assert _defanged_text("Global\\http://mtx.app/x") == "Global\\hxxp://mtx[.]app/x"


class TestTheNetworkEvidenceDecides:
    def test_a_value_the_run_recorded_is_defanged_in_an_object_name(self) -> None:
        run_values = ProseDefanger([("mtx.app", "domain")])

        assert _defanged_text(run_values("the mutex Global\\mtx.app")) == (
            "the mutex Global\\mtx[.]app"
        )

    def test_a_check_that_asks_the_table_reads_it_with_the_evidence(self) -> None:
        sentence = "It creates Global\\mtx.app on start."

        assert network_values_in(sentence, packages=True) == [("domain", "mtx.app")]
        assert needs_network_evidence(sentence, "mtx.app")
        assert not needs_network_evidence("It resolves mtx.app.", "mtx.app")

        held = {("domain", "mtx.app"): "no: the sandbox report does not say which process"}
        (found,) = unpublished_value_violations(
            {"body": sentence, "evidence_refs": []},
            lambda kind, value: held.get((kind, value), ""),
        )
        assert "mtx.app" in found.message

    def test_with_no_row_the_object_name_is_not_asked_about(self) -> None:
        payload = {"body": "It creates Global\\mtx.app on start.", "evidence_refs": []}

        assert unpublished_value_violations(payload, lambda kind, value: "") == []
