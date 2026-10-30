"""Each credited benchmark item says whether the run's own analysis or a lookup found it.

The stored run beside a key score (its ledger, report and published
techniques) is written by the test. An entry is classed by the kind its tool
declares, never by its name; the tag changes no verdict and no gate outcome.
The intel-off arm is derived from settings built here and never run.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from scripts.benchmark import provenance as prov
from scripts.benchmark.gate import arm, gate, render, render_arm, score_arm
from scripts.benchmark.intel_off import ArmError, intel_off
from scripts.benchmark.provenance import (
    ANALYSIS,
    LOOKUP,
    NO_ANSWER,
    NOT_IN_LEDGER,
    UNDECLARED,
    closes_sentence,
    entry_class,
    fragments,
    tag_of,
)
from scripts.benchmark.run import main
from scripts.benchmark.scores import ScoredRun, read_key_score


def _entry(number: int, tool: str, source: str, kind: str | None, ok: bool = True) -> dict:
    """A ledger row whose tool's facts were stored under ``source`` (``kind`` None: none)."""
    row: dict[str, Any] = {"entry_id": f"ev_{number:04d}", "tool": tool, "source": source}
    if kind is not None:
        row["facts"] = {"v": 1, "kind": kind}
    return {**row, "ok": ok}


# One recorded source and its facts per class: the tool names say nothing.
LEDGER: list[dict[str, Any]] = [
    _entry(1, "listing", "mcp:a", "decompile"),
    _entry(2, "ask_about", "mcp:b", "reputation"),
    _entry(3, "who_knows", "mcp:b", "indicator_report"),
    _entry(4, "mystery", "mcp:c", None),
    _entry(5, "listing", "mcp:a", "decompile", ok=False),
    _entry(6, "get_file_report", "mcp:a", "strings"),
    _entry(7, "rules", "pack", "signature_rules"),
]

REPORT = """# Report

Family: Example (moderate confidence) [ev_0002, ev_0007]
The routine at 0x3868 returns -1 when the debugger flag is set. (assessed) [ev_0001]
It decodes the C2 list with a rolling XOR key. Its labels come from engines [ev_0003].
| name | `Custom_update` | the static analyst | ev_0006 |
Category: loader with no citation on this line.
"""

TECHNIQUES = {
    "techniques": [{"technique_id": "T1027", "description": "Encoded (ev_0001, ev_0005)."}]
}

ROWS = [
    # (label, verdict, report cell)
    ("K1.1a family", "found", '"Family: Example (moderate confidence)" (l.3)'),
    ("K2.2 abort on failed check", "found", '"returns -1 when the debugger flag is set"'),
    ("K6.3 RC4 then base64", "partly", '"decodes the C2 list with a rolling XOR key"'),
    ("K1.2 IcedID link", "found", '"Its labels come from engines"'),
    ("K9 Custom_update", "found", '"the static analyst"'),
    ("K1.1b loader", "found", '"Category: loader with no citation"'),
    ("K10 T1027", "found", "published"),
    ("K2.3 mutex", "found", "named by ev_0004 only"),
    ("K2.4 install", "found", "ev_0005 and ev_0099 only"),
    ("K7 17 uninstall", "missed", '"Its labels come from engines"'),
]


def _score_md(rows: list[tuple[str, str, str]]) -> str:
    lines = [
        "# Key score: arm X",
        "",
        "## 3. Item by item",
        "",
        "| # | arm X | arm X report (quoted or condensed), where |",
        "|---|---|---|",
        *(f"| {label} | {verdict} | {cell} |" for label, verdict, cell in rows),
        "",
    ]
    return "\n".join(lines)


def _stored_run(root: Path, rows: list[tuple[str, str, str]] = ROWS, **files: Any) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "score.md").write_text(_score_md(rows), encoding="utf-8")
    ledger = files.get("ledger", {"total": len(LEDGER), "items": LEDGER})
    if ledger is not None:
        (root / "evidence.json").write_text(json.dumps(ledger), encoding="utf-8")
    (root / "report.md").write_text(files.get("report", REPORT), encoding="utf-8")
    (root / "mitre.json").write_text(json.dumps(TECHNIQUES), encoding="utf-8")
    return root / "score.md"


def test_an_entry_is_classed_by_its_declared_kind_never_its_name() -> None:
    by_id = {e["entry_id"]: e for e in LEDGER}
    assert entry_class(by_id["ev_0001"]) == ANALYSIS
    assert entry_class(by_id["ev_0002"]) == LOOKUP
    assert entry_class(by_id["ev_0003"]) == LOOKUP
    # A recorded source that declared nothing is undeclared, never analysis.
    assert entry_class(by_id["ev_0004"]) == UNDECLARED
    assert entry_class(by_id["ev_0005"]) == NO_ANSWER
    # A built-in lookup's name on a tool that declares another kind is that kind.
    assert entry_class(by_id["ev_0006"]) == ANALYSIS
    # An entry written before sources were recorded reads by the shipped declaration.
    assert entry_class({"entry_id": "x", "tool": "get_file_report", "ok": True}) == LOOKUP
    assert entry_class({"entry_id": "x", "tool": "decompile_function", "ok": True}) == ANALYSIS
    assert prov.LOOKUP_KINDS >= {"reputation", "indicator_report", "indicator_reputation"}


@pytest.mark.parametrize(
    ("classes", "tag"),
    [
        ({ANALYSIS}, prov.OWN),
        ({ANALYSIS, LOOKUP}, prov.BOTH),
        ({ANALYSIS, LOOKUP, UNDECLARED}, prov.BOTH),
        ({LOOKUP}, prov.LOOKUP_ONLY),
        ({LOOKUP, UNDECLARED}, prov.UNTOLD),
        ({UNDECLARED}, prov.UNTOLD),
        ({NO_ANSWER, NOT_IN_LEDGER}, prov.NO_ENTRY),
        (set(), prov.NO_ENTRY),
    ],
)
def test_the_tag_says_both_when_both_credited_it(classes: set[str], tag: str) -> None:
    assert tag_of(classes) == tag


def test_a_fragment_is_cited_by_its_own_sentence_only() -> None:
    assert fragments('x "short" and "a longer fragment … second half here"') == [
        "a longer fragment",
        "second half here",
    ]
    assert closes_sentence(" key") and closes_sentence(". ") and closes_sentence(". (assessed) ")
    assert not closes_sentence(" key. Its labels come from engines ")


# The same report in the analyst layout: each citation a numbered note, read back
# through the evidence bundle's notes beside it.
def _note(number: int) -> str:
    return f"[[{number}]](evidence-bundle.html#cite-{number})"


ANALYST_REPORT = "\n".join(
    [
        "# Report",
        "",
        f"**Family:** Example (moderate confidence){_note(1)}",
        "The routine at 0x3868 returns -1 when the debugger flag is set. _(assessed)_" + _note(2),
        "It decodes the C2 list with a rolling XOR key. Its labels come from engines"
        + _note(3)
        + ".",
        f"| name | `Custom_update` | the static analyst{_note(4)} |",
        "Category: loader with no citation on this line.",
        "",
    ]
)
BUNDLE_NOTES = {
    "notes": [
        {"number": 1, "evidence_ids": ["ev_0002", "ev_0007"]},
        {"number": 2, "evidence_ids": ["ev_0001"]},
        {"number": 3, "evidence_ids": ["ev_0003"]},
        {"number": 4, "evidence_ids": ["ev_0006"]},
    ]
}


def test_a_citation_note_is_read_back_through_the_bundle(tmp_path: Path) -> None:
    path = _stored_run(tmp_path / "run9", report=ANALYST_REPORT)
    (path.parent / prov.BUNDLE_FILE).write_text(json.dumps(BUNDLE_NOTES), encoding="utf-8")
    analyst = read_key_score(path)
    single = read_key_score(_stored_run(tmp_path / "single"))

    assert "evidence-bundle.json" in analyst.provenance_note
    for key in ("K1.1a", "K2.2", "K6.3", "K1.2", "K9 custom_update", "K1.1b"):
        assert analyst.provenance[key].tag == single.provenance[key].tag, key
        assert analyst.provenance[key].entries == single.provenance[key].entries, key


def test_without_the_bundle_a_note_credits_nothing_and_says_so(tmp_path: Path) -> None:
    run = read_key_score(_stored_run(tmp_path / "run9", report=ANALYST_REPORT))

    assert "credit nothing: no evidence-bundle.json" in run.provenance_note
    assert run.provenance["K2.2"].tag == prov.NO_ENTRY


def test_each_credited_item_names_the_entries_that_credited_it(tmp_path: Path) -> None:
    run = read_key_score(_stored_run(tmp_path / "run9"))
    assert run.provenance_note == "read from evidence.json, report.md, mitre.json beside the score"
    tags = {key: held.tag for key, held in run.provenance.items()}
    assert tags == {
        "K1.1a": prov.BOTH,
        "K2.2": prov.OWN,
        # The next sentence's citation is not this fragment's.
        "K6.3": prov.NO_ENTRY,
        "K1.2": prov.LOOKUP_ONLY,
        # Every id of a table row; a lookup's name on that tool says nothing.
        "K9 custom_update": prov.OWN,
        "K1.1b": prov.NO_ENTRY,
        "K10 T1027": prov.OWN,
        "K2.3": prov.UNTOLD,
        "K2.4": prov.NO_ENTRY,
        "K7 17": prov.LOOKUP_ONLY,
    }
    assert run.provenance["K1.1a"].entries == {"ev_0002": LOOKUP, "ev_0007": ANALYSIS}
    assert run.provenance["K10 T1027"].entries == {"ev_0001": ANALYSIS, "ev_0005": NO_ANSWER}
    assert run.provenance["K2.4"].entries == {"ev_0005": NO_ANSWER, "ev_0099": NOT_IN_LEDGER}
    assert (run.provenance["K6.3"].fragments, run.provenance["K6.3"].located) == (1, 1)


def test_the_score_counts_credited_items_both_ways_and_keeps_every_verdict(
    tmp_path: Path,
) -> None:
    path = _stored_run(tmp_path / "run9")
    run = read_key_score(path)
    result = score_arm(arm([run]))
    held = result["provenance"]
    # The missed item is not counted: nine credited items.
    assert held["credited"] == result["totals"]["credited"] == 9
    assert held["by_tag"][prov.OWN] == 3 and held["by_tag"][prov.BOTH] == 1
    assert (held["by_analysis"], held["only_by_lookup"]) == (4, 1)
    assert held["items"][prov.LOOKUP_ONLY] == ["K1.2"]
    assert held["by_item"]["K7 17"] is None
    text = render_arm(result)
    assert (
        "run9 provenance of 9 credited items: 3 own analysis / 1 own analysis + lookup / "
        "1 lookup only / 1 undeclared tool / 3 no cited entry; found by analysis 4, "
        "found only by lookup 1"
    ) in text
    assert "  own analysis + lookup: K1.1a family" in text
    # The same score with no stored run beside it reads the same verdicts.
    bare = tmp_path / "bare" / "score.md"
    bare.parent.mkdir()
    bare.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    alone = read_key_score(bare)
    assert alone.verdicts == run.verdicts
    assert alone.provenance_note == "not read: no evidence.json beside the score"
    assert score_arm(arm([alone]))["totals"] == result["totals"]
    assert score_arm(arm([alone]))["provenance"]["by_tag"][prov.NOT_READ] == 9


def test_an_unreadable_ledger_is_said_and_scores_nothing_by_it(tmp_path: Path) -> None:
    run = read_key_score(_stored_run(tmp_path / "empty", ledger={"items": []}))
    assert run.provenance_note.startswith("not read: evidence.json holds no entries")
    assert {held.tag for held in run.provenance.values()} == {prov.NOT_READ}


def _tagged(name: str, verdicts: dict[str, str], tags: dict[str, str]) -> ScoredRun:
    return ScoredRun(
        name=name,
        source=name,
        verdicts={k: ("key", v) for k, v in verdicts.items()},
        labels={k: k for k in verdicts},
        provenance={k: prov.ItemProvenance(t) for k, t in tags.items()},
    )


def test_an_arm_s_tag_is_the_one_m_of_its_runs_share() -> None:
    found = {"K1.1": "found", "K2.1": "found", "K3.1": "found"}
    runs = [
        _tagged("a", found, {"K1.1": prov.OWN, "K2.1": prov.OWN, "K3.1": prov.OWN}),
        _tagged("b", found, {"K1.1": prov.OWN, "K2.1": prov.BOTH, "K3.1": prov.LOOKUP_ONLY}),
        _tagged("c", found, {"K1.1": prov.BOTH, "K2.1": prov.LOOKUP_ONLY, "K3.1": prov.NO_ENTRY}),
    ]
    items = score_arm(arm(runs))["provenance"]["by_item"]
    assert items["K1.1"]["tag"] == prov.OWN
    assert items["K1.1"]["runs"] == {"a": prov.OWN, "b": prov.OWN, "c": prov.BOTH}
    # Two runs found it by analysis, one alone and one beside a lookup.
    assert items["K2.1"]["tag"] == prov.BOTH
    assert items["K3.1"]["tag"] == prov.MIXED


def test_the_gate_names_a_changed_tag_and_does_not_gate_on_it() -> None:
    baseline = _tagged(
        "base", {"K1.1": "found", "K2.1": "found"}, {"K1.1": prov.LOOKUP_ONLY, "K2.1": prov.OWN}
    )
    candidate = _tagged(
        "intel_off", {"K1.1": "found", "K2.1": "found"}, {"K1.1": prov.OWN, "K2.1": prov.OWN}
    )
    result = gate(arm([baseline]), arm([candidate]))
    assert result["passed"] is True
    assert result["provenance"]["changed"] == ["K1.1"]
    assert result["provenance"]["baseline"]["only_by_lookup"] == 1
    assert result["provenance"]["candidate"]["by_analysis"] == 2
    row = next(r for r in result["items"] if r["item"] == "K1.1")
    assert row["baseline"]["provenance"]["tag"] == prov.LOOKUP_ONLY
    text = render(result)
    assert "provenance changed (reported, not gated): 1 of the items both arms credit" in text
    assert "  K1.1: baseline lookup only; candidate own analysis" in text
    assert "candidate provenance of 2 credited items: 2 own analysis" in text


def test_the_intel_off_arm_withholds_every_server_declaring_a_lookup() -> None:
    derived = intel_off(
        {
            "mcp.servers": {
                "oracle": {
                    "command": "x",
                    "tool_facts": {
                        "ask": {"kind": "indicator_report"},
                        "peek": {"kind": "strings"},
                    },
                },
                # A built-in lookup's name on a tool declared as another kind.
                "plain": {"command": "y", "tool_facts": {"get_file_report": {"kind": "strings"}}},
            }
        }
    )
    assert derived["profile"] == "default_intel_off"
    assert derived["base_profile"] == "default"
    assert derived["withheld"]["oracle"] == ["ask"]
    assert {"threatintel", "virustotal"} <= set(derived["withheld"])
    assert "plain" not in derived["withheld"]
    assert derived["withheld_with_them"]["oracle"] == ["peek"]
    assert derived["definition"]["exclude_servers"] == sorted(derived["withheld"])
    # A benchmark arm starts without an earlier run's memory, as every benchmark run does.
    assert derived["job_config"] == {"profile": "default_intel_off", "ignore_earlier_runs": True}
    assert derived["settings_key"] == "agents.profiles.default_intel_off"
    assert derived["not_withheld"] == []
    # A profile that already withholds every server withholds the lookups too.
    measured = intel_off({}, "measurement")
    assert measured["withheld"] == {} and {"threatintel", "virustotal"} <= set(
        measured["already_withheld"]
    )
    assert measured["definition"]["exclude_servers"] == ["*"]
    with pytest.raises(ArmError, match="no profile 'nobody'"):
        intel_off({}, "nobody")


def test_the_command_line_scores_with_provenance_and_writes_the_arm(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _stored_run(tmp_path / "run9")
    out = tmp_path / "score.json"
    assert main(["score", str(path), "--json", str(out)]) == 0
    assert "found only by lookup 1" in capsys.readouterr().out
    item = json.loads(out.read_text())["runs"][0]["provenance"]["by_item"]["K1.1a"]
    assert item["entries"] == {"run9": {"ev_0002": LOOKUP, "ev_0007": ANALYSIS}}
    assert main(["gate", "--baseline", str(path), "--candidate", str(path)]) == 0
    assert "provenance changed (reported, not gated): 0" in capsys.readouterr().out
    arm_file = tmp_path / "arm.json"
    assert main(["intel-off", "--profile", "default", "--json", str(arm_file)]) == 0
    assert "intel-off arm: profile 'default_intel_off'" in capsys.readouterr().out
    assert json.loads(arm_file.read_text())["profile"] == "default_intel_off"
    settings = tmp_path / "settings.json"
    settings.write_text("[1]", encoding="utf-8")
    assert main(["intel-off", "--settings", str(settings)]) == 2
    assert "not an object of settings by dotted key" in capsys.readouterr().err
    assert main(["intel-off", "--profile", "nobody"]) == 2
