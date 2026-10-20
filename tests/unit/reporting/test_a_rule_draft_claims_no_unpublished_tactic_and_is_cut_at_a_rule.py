"""Sigma tags come from published cells; a Suricata draft is cut between rules (RC-21)."""

from __future__ import annotations

from maljan.reporting import detection_signatures as ds
from maljan.reporting.models import CapabilityCell, FileHashes, MalwareReport, SampleIdentity


def _cell(tactic_name: str, technique: str, not_published: str = "") -> CapabilityCell:
    return CapabilityCell(
        tactic="TA0003",
        tactic_name=tactic_name,
        technique_id=technique,
        technique_name="n",
        not_published=not_published,
    )


def test_an_unpublished_cell_gives_no_tactic_tag() -> None:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        capability_matrix=[
            _cell("Persistence", "T1547"),
            _cell("Impact", "T9999", "the catalogue has no such id"),
        ],
    )
    assert ds._sigma_tags(report) == ["attack.persistence"]


def test_a_long_draft_keeps_every_rule_it_holds_whole(monkeypatch: object) -> None:
    monkeypatch.setattr(ds, "_SURICATA_MAX_BODY_BYTES", 400)  # type: ignore[attr-defined]
    lines = []
    for n in range(10):
        lines.append(f"# why {n}")
        lines.append(f'alert dns any any -> any any (msg:"rule {n}"; sid:{n};)')
    body = ds._suricata_body_within(lines)
    kept = body.splitlines()
    assert all(line.endswith(";)") for line in kept if line.startswith("alert"))
    assert len(body.encode("utf-8")) < 400 + 200
    assert kept[-1].startswith("# (cut at the draft's size:")
    rules = [line for line in kept if line.startswith("alert")]
    assert f"{10 - len(rules):,} more indicators" in kept[-1]


def test_a_short_draft_is_unchanged() -> None:
    lines = ["# a", 'alert ip any any -> any any (msg:"x"; sid:1;)']
    assert ds._suricata_body_within(lines) == "\n".join(lines)


def test_the_header_lines_survive_a_cut_and_the_capped_are_counted(monkeypatch: object) -> None:
    monkeypatch.setattr(ds, "_SURICATA_MAX_BODY_BYTES", 120)  # type: ignore[attr-defined]
    header = ["# one", "# two", "# three"]
    lines = [*header, "# why", 'alert dns any any -> any any (msg:"' + "x" * 200 + '"; sid:1;)']
    kept = ds._suricata_body_within(lines, header=3, capped=4).splitlines()
    assert kept[:3] == header
    assert "5 more indicators" in kept[-1]
