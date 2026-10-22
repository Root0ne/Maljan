"""The known-answer gate: an item the baseline found in m of n runs may not drop.

Every scored run here is written by the test: key scores in the layout the
benchmark's score files use (an "Item by item" table whose first verdict column
is the scored run's, a second table and a numbered list under other headings
that are not read), a blind score sheet with its sealed map, and calibration
scores in the scorer's own shape.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from scripts.benchmark import gate as gating
from scripts.benchmark.gate import GateError, arm, gate, majority, mth_largest, score_arm
from scripts.benchmark.run import main
from scripts.benchmark.scores import (
    CLAIM,
    FACT,
    KEY,
    ScoredRun,
    ScoreFileError,
    item_key,
    key_verdict,
    read_blind,
    read_calibration,
    read_key_score,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "benchmark"
LABELS = (
    "K1.1a family",
    "K2.3 mutex",
    "K3.2 process count 75 / 50",
    "K7 17 uninstall",
    "K9 mutex `runnung`",
    "K10 T1055",
)


def _score_md(
    verdicts: dict[str, str],
    *,
    beyond: int | None = 2,
    stated_beyond: int | None = None,
    totals: str | None = None,
    numbering: list[int] | None = None,
) -> str:
    words = [key_verdict(v) for v in verdicts.values()]
    found, missed, wrong = words.count("found"), words.count("missed"), words.count("wrong")
    body, dump = words.count("partly (body)"), words.count("partly (dump)")
    if totals is None:
        totals = (
            f"**Totals: {found} found / {body + dump} partly ({body} body + {dump} dump) / "
            f"{missed} missed / {wrong} wrong.** Found + partly = {found + body + dump}."
        )
    lines = [
        "# Key score: arm X",
        "",
        "## 1. Totals",
        "",
        totals,
        "",
        "## 3. Item by item (arm X against arm Y)",
        "",
        "| # | Human analyst (key) | arm X | arm X report (quoted) | arm Y |",
        "|---|---|---|---|---|",
    ]
    for label, verdict in verdicts.items():
        lines.append(f'| {label} | B, E | {verdict} | "quoted \\| text" | found |')
    lines += [
        "",
        "### Gains and losses",
        "",
        "| # | arm X | arm Y | cause |",
        "|---|---|---|---|",
        "| K2.3 mutex | wrong | found | not the scored table |",
        "",
    ]
    if beyond is not None:
        lines += ["## 4. Beyond the human reports", ""]
        for number in numbering or list(range(1, beyond + 1)):
            lines += [f"{number}. A fact proven by ev_{number:04d}.", "   - a detail line"]
        stated = beyond if stated_beyond is None else stated_beyond
        lines += ["", f"**{stated} facts more than the human analyst.** (arm Y: 1.)", ""]
    lines += [
        "## 7. What would go beyond the human reports (prioritised)",
        "",
        "1. Not a beyond fact.",
        "2. Nor this.",
        "",
    ]
    return "\n".join(lines) + "\n"


def _write(path: Path, verdicts: dict[str, str], **kwargs: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_score_md(verdicts, **kwargs), encoding="utf-8")
    return path


def _run(name: str, verdicts: dict[str, str | None], beyond: int | None = None) -> ScoredRun:
    return ScoredRun(
        name=name,
        source=name,
        verdicts={item_key(k): (KEY, v) for k, v in verdicts.items()},
        labels={item_key(k): k for k in verdicts},
        beyond=beyond,
    )


def test_a_key_score_is_read_as_its_own_totals_say(tmp_path: Path) -> None:
    verdicts = dict(
        zip(
            LABELS,
            ["found", "**partly**", "partly (dump)", "missed", "wrong", "found"],
            strict=True,
        )
    )
    run = read_key_score(_write(tmp_path / "haiku9" / "score.md", verdicts, beyond=3))
    assert run.name == "haiku9"
    assert run.column == "arm X"
    assert [v for _, v in run.verdicts.values()] == [
        "found",
        "partly (body)",
        "partly (dump)",
        "missed",
        "wrong",
        "found",
    ]
    # The numbered list of the beyond section only: not the plan's list, not a detail line.
    assert run.beyond == 3
    assert run.beyond_note == "3 listed, as stated"
    assert run.totals_note == "Totals line checked against the table"
    result = score_arm(arm([run]))
    assert result["totals"]["by_scale"][KEY] == {
        "wrong": 1,
        "missed": 1,
        "partly (dump)": 1,
        "partly (body)": 1,
        "found": 2,
    }
    assert (result["totals"]["credited"], result["totals"]["credit_items"]) == (4, 6)
    assert result["beyond"]["count"] == 3


def test_a_score_with_no_beyond_section_has_no_count(tmp_path: Path) -> None:
    run = read_key_score(_write(tmp_path / "score.md", {"K1.1a family": "found"}, beyond=None))
    assert run.beyond is None
    assert "no section headed 'Beyond the human reports'" in run.beyond_note


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {"totals": "**Totals: 9 found / 0 partly (0 body + 0 dump) / 0 missed / 0 wrong.**"},
            "found 9 stated, 1 in the table",
        ),
        ({"beyond": 2, "stated_beyond": 5}, "5 beyond-human facts stated, 2 listed"),
        ({"beyond": 2, "numbering": [1, 3]}, "not numbered 1 to 2 in order"),
    ],
)
def test_a_score_that_disagrees_with_itself_is_refused(
    tmp_path: Path, kwargs: dict[str, Any], message: str
) -> None:
    path = _write(tmp_path / "score.md", {"K1.1a family": "found"}, **kwargs)
    with pytest.raises(ScoreFileError, match=message):
        read_key_score(path)


def test_an_item_scored_twice_or_a_table_with_no_verdict_column_is_refused(tmp_path: Path) -> None:
    twice = _write(
        tmp_path / "a" / "score.md", {"K3.2 count 75/50": "found", "K3.2 count 75 / 50": "missed"}
    )
    with pytest.raises(ScoreFileError, match="item K3.2 is scored twice"):
        read_key_score(twice)
    # One cell of the scored column is not a verdict: refused, never read from
    # the next run's column, which is a verdict in every row.
    odd = _write(
        tmp_path / "b" / "score.md",
        {"K1.1a family": "found (it. 6 partly)", "K2.3 mutex": "missed"},
    )
    with pytest.raises(ScoreFileError, match="column 'arm X' is not a verdict for 'K1.1a family'"):
        read_key_score(odd)
    none = tmp_path / "c.md"
    none.write_text("# Notes\n\nNo table.\n", encoding="utf-8")
    with pytest.raises(ScoreFileError, match="no section headed 'Item by item'"):
        read_key_score(none)


def test_one_item_spelt_two_ways_is_one_item() -> None:
    assert item_key("K3.2 process count 75 / 50") == item_key("**K3.2** process count 75/50")
    assert item_key("K7 17 uninstall") == item_key("K7 17 uninstall / terminate") == "K7 17"
    assert item_key("K10 T1053.005") == "K10 T1053.005"
    assert item_key("K9 mutex `runnung`") == item_key("K9  mutex runnung")
    assert item_key("K9 own hashes") != item_key("K9 UA")
    # Without a code only runs of spaces and the spaces around a slash fold.
    assert item_key("K9 a / b") == item_key("K9 a/b") == "K9 a/b"
    assert item_key("K9 task  Updater") == item_key("K9 task Updater") == "K9 task updater"
    assert item_key("K9 task Updater") != item_key("K9 taskUpdater")
    assert item_key("K9 a-b") != item_key("K9 a b")


def test_a_totals_line_that_cannot_be_read_is_refused(tmp_path: Path) -> None:
    line = "**Totals: 1 found / 0 missed**"
    path = _write(tmp_path / "score.md", {"K1.1a family": "found"}, totals=line)
    with pytest.raises(ScoreFileError, match=re.escape(f"Totals line cannot be read: {line!r}")):
        read_key_score(path)


def test_a_score_with_no_totals_line_says_its_totals_were_unchecked(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _write(tmp_path / "run3" / "score.md", {"K1.1a family": "found"}, totals="")
    run = read_key_score(path)
    assert run.totals_note == "no Totals line: totals unchecked"
    assert score_arm(arm([run]))["unchecked_totals"] == {"run3": run.totals_note}
    assert main(["gate", "--baseline", str(path), "--candidate", str(path)]) == 0
    assert "run3: no Totals line: totals unchecked" in capsys.readouterr().out
    assert main(["score", str(path)]) == 0
    assert "run3: no Totals line: totals unchecked" in capsys.readouterr().out


def test_a_stated_beyond_count_with_no_list_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "score.md"
    path.write_text(
        "## Item by item\n\n| item | r |\n|---|---|\n| K1.1a family | found |\n\n"
        "**5 facts more than the human analyst.**\n",
        encoding="utf-8",
    )
    with pytest.raises(ScoreFileError, match="5 beyond-human facts stated, and no section"):
        read_key_score(path)


def test_the_stored_haiku3_to_haiku4_drop_is_t1055_alone() -> None:
    """Labels, verdicts and counts copied from the two stored scores (no quote, no indicator)."""
    haiku3 = read_key_score(FIXTURES / "haiku3-score.md")
    haiku4 = read_key_score(FIXTURES / "haiku4-score.md")
    totals = score_arm(arm([haiku4]))
    assert totals["totals"]["by_scale"][KEY] == {
        "wrong": 0,
        "missed": 6,
        "partly (dump)": 1,
        "partly (body)": 15,
        "found": 35,
    }
    assert (totals["totals"]["credited"], totals["totals"]["credit_items"]) == (51, 57)
    assert totals["beyond"]["count"] == 33
    # haiku3 spells two labels without the spaces around "/": the same items.
    assert set(haiku3.verdicts) == set(haiku4.verdicts)
    result = gate(arm([haiku3]), arm([haiku4]))
    assert result["dropped"] == ["K10 T1055"]
    assert len(result["improved"]) == 26
    assert result["beyond"]["outcome"] == gating.IMPROVED
    assert result["passed"] is False


def test_an_item_is_found_in_m_of_n() -> None:
    runs = [
        _run("r1", {"K1.1a": "found", "K2.3": "found", "K3.2": "found"}),
        _run("r2", {"K1.1a": "found", "K2.3": "partly (body)", "K3.2": None}),
        _run("r3", {"K1.1a": "missed", "K2.3": "missed"}),
    ]
    two_of_three = score_arm(arm(runs))["items"]
    assert two_of_three["K1.1a"] == {
        "scale": KEY,
        "verdict": "found",
        "runs_at_or_above": 2,
        "n": 3,
        "m": 2,
        "unknown": 0,
    }
    assert two_of_three["K2.3"]["verdict"] == "partly (body)"
    assert two_of_three["K2.3"]["runs_at_or_above"] == 2
    # One run scored it and two did not: no verdict reaches 2 of 3.
    assert two_of_three["K3.2"]["verdict"] is None
    assert two_of_three["K3.2"]["unknown"] == 2
    all_three = score_arm(arm(runs, 3))["items"]
    assert all_three["K1.1a"]["verdict"] == "missed"
    assert all_three["K1.1a"]["runs_at_or_above"] == 3
    assert [majority(n) for n in (1, 2, 3, 4, 5)] == [1, 2, 2, 3, 3]
    with pytest.raises(GateError, match="between 1 and the arm's 3 runs, not 4"):
        arm(runs, 4)
    with pytest.raises(GateError, match="given twice in one arm: r1"):
        arm([runs[0], runs[0]])
    with pytest.raises(GateError, match="at least one scored run"):
        arm([])


def test_the_gate_fails_a_dropped_item_and_passes_otherwise() -> None:
    baseline = arm(
        [
            _run(
                "b1",
                {"K1.1a": "found", "K2.3": "partly (body)", "K3.2": "missed", "K9 UA": "found"},
                5,
            ),
            _run("b2", {"K1.1a": "found", "K2.3": "missed", "K3.2": "missed", "K9 UA": None}, 7),
            _run(
                "b3",
                {"K1.1a": "found", "K2.3": "partly (body)", "K3.2": "missed", "K9 UA": None},
                6,
            ),
        ]
    )
    candidate = arm(
        [
            _run("c1", {"K1.1a": "found", "K2.3": "found", "K3.2": "missed", "K7 2": "found"}, 6),
            _run("c2", {"K1.1a": "partly (body)", "K2.3": "found", "K3.2": "missed"}, 9),
            _run("c3", {"K1.1a": "missed", "K2.3": "partly (body)", "K3.2": "partly (body)"}, 4),
        ]
    )
    result = gate(baseline, candidate)
    rows = {r["item"]: r for r in result["items"]}
    # Found in 3 of 3, then in 1 of 3: dropped to partly, which 2 of 3 reach.
    assert rows["K1.1a"]["outcome"] == gating.DROPPED
    assert rows["K1.1a"]["candidate"]["verdict"] == "partly (body)"
    assert rows["K1.1a"]["candidate"]["runs_at_baseline_verdict"] == 1
    assert rows["K2.3"]["outcome"] == gating.IMPROVED
    assert rows["K3.2"]["outcome"] == gating.HELD
    # Scored by one baseline run of three: not gated, and named.
    assert rows[item_key("K9 UA")]["outcome"] == gating.NOT_GATED
    assert result["new_items"] == ["K7 2"]
    # Beyond: the baseline's 2nd largest is 6, the candidate's is 6.
    assert result["beyond"]["baseline"]["count"] == 6
    assert result["beyond"]["candidate"]["count"] == 6
    assert result["beyond"]["outcome"] == gating.HELD
    assert result["dropped"] == ["K1.1a"]
    assert result["passed"] is False
    text = gating.render(result)
    assert text.startswith("known-answer gate: FAIL (1 dropped)")
    assert "K1.1a: baseline found (3 of 3 at or above, m 2)" in text
    assert "1 of 3 candidate runs at the baseline's" in text
    # With m 1 of 3 the candidate holds K1.1a, and the gate passes.
    assert gate(baseline, arm(candidate.runs, 1))["passed"] is True


def test_an_item_the_candidate_did_not_score_is_a_drop() -> None:
    baseline = arm([_run("b", {"K1.1a": "wrong", "K2.3": "found"})])
    candidate = arm([_run("c", {"K2.3": "found"})])
    result = gate(baseline, candidate)
    assert result["dropped"] == ["K1.1a"]
    assert result["items"][0]["candidate"]["verdict"] is None


def test_the_beyond_count_is_gated_on_the_mth_largest() -> None:
    assert mth_largest([5, 7, 6], 2) == 6
    assert mth_largest([3, 3, 3, 1], 3) == 3
    assert mth_largest([4], 1) == 4
    assert mth_largest([9, 1], 3) is None
    items = {"K1.1a": "found"}
    lower = gate(arm([_run("b", items, 33)]), arm([_run("c", items, 30)]))
    assert lower["beyond"]["outcome"] == gating.DROPPED
    assert lower["passed"] is False
    assert gating.render(lower).startswith("known-answer gate: FAIL (1 dropped)")
    unknown = gate(arm([_run("b", items, 33)]), arm([_run("c", items, None)]))
    assert unknown["beyond"]["outcome"] == gating.DROPPED
    no_baseline = gate(arm([_run("b", items, None)]), arm([_run("c", items, 1)]))
    assert no_baseline["beyond"]["outcome"] == gating.NOT_GATED
    assert no_baseline["passed"] is True


def test_items_on_different_scales_are_not_compared() -> None:
    base = ScoredRun("b", "b", {"x": (FACT, "found")})
    cand = ScoredRun("c", "c", {"x": (KEY, "found")})
    with pytest.raises(GateError, match="item x is on the fact scale in the baseline"):
        gate(arm([base]), arm([cand]))
    with pytest.raises(GateError, match="on the fact scale in one run and the key scale in c"):
        score_arm(arm([base, cand]))


def test_a_baseline_that_scores_no_item_gates_nothing() -> None:
    empty = ScoredRun("e", "e", {})
    with pytest.raises(GateError, match="the baseline scores no item"):
        gate(arm([empty]), arm([_run("c", {"K1.1a": "found"})]))


def _calibration(case: str, facts: list[str], traps: list[str]) -> dict[str, Any]:
    return {
        "case": case,
        "split": "heldout",
        "run": f"run-{case}",
        "facts": [{"id": f"F{i}", "kind": "import", "status": s} for i, s in enumerate(facts, 1)],
        "traps": [
            {"id": f"T{i}", "kind": "dead_import", "status": s} for i, s in enumerate(traps, 1)
        ],
        "absent": [],
        "beyond": {"techniques": 2, "indicators": 0},
        "totals": {"beyond": 2},
    }


def test_calibration_scores_are_gated_on_facts_and_traps(tmp_path: Path) -> None:
    base_path = tmp_path / "base.json"
    base_path.write_text(json.dumps(_calibration("cal-1", ["found", "partial"], ["clear"])))
    cand_path = tmp_path / "cand.json"
    cand_path.write_text(
        json.dumps(
            {
                "split": "heldout",
                "scores": [
                    _calibration("cal-1", ["found", "mentioned"], ["false"]),
                    _calibration("cal-2", ["missed"], ["not recorded"]),
                ],
            }
        )
    )
    base, cand = read_calibration(base_path), read_calibration(cand_path)
    assert base.name == "run-cal-1" and cand.name == "cand"
    assert base.verdicts == {
        "cal-1/F1": (FACT, "found"),
        "cal-1/F2": (FACT, "partial"),
        "cal-1/T1": (CLAIM, "not claimed"),
    }
    assert cand.verdicts["cal-2/T1"] == (CLAIM, None)
    # A count of publications no manifest names is not a beyond-human count.
    assert base.beyond is None and "not proven facts" in base.beyond_note
    result = gate(arm([base]), arm([cand]))
    assert result["dropped"] == ["cal-1/F2", "cal-1/T1"]
    assert result["new_items"] == ["cal-2/F1", "cal-2/T1"]
    assert result["beyond"]["outcome"] == gating.NOT_GATED
    totals = result["totals"]["baseline"]
    assert (totals["credited"], totals["credit_items"]) == (2, 2)
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(_calibration("cal-1", ["found-ish"], [])))
    with pytest.raises(ScoreFileError, match="cal-1/F1 has the status 'found-ish'"):
        read_calibration(bad)
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"case": "cal-9", "facts": []}))
    with pytest.raises(ScoreFileError, match="cal-9 has no fact, trap or absent entry"):
        read_calibration(empty)


def _blind(tmp_path: Path) -> tuple[Path, Path]:
    sealed = tmp_path / "sealed-map.json"
    sealed.write_text(
        json.dumps(
            {
                "items": ["K1.1a", "K2.3"],
                "arms": {"A": {"name": "haiku9"}, "B": {"name": "run9"}},
            }
        )
    )
    sheet = tmp_path / "scores.csv"
    sheet.write_text(
        "item,A,B\nK1.1a,found,found\nK2.3,missed,partly (body)\nbeyond_human,4,3\n",
        encoding="utf-8",
    )
    return sheet, sealed


def test_a_blind_sheet_gives_one_run_per_arm(tmp_path: Path) -> None:
    sheet, sealed = _blind(tmp_path)
    runs = {r.name: r for r in read_blind(sheet, sealed)}
    assert runs["run9"].verdicts == {"K1.1a": (KEY, "found"), "K2.3": (KEY, "partly (body)")}
    assert (runs["haiku9"].beyond, runs["run9"].beyond) == (4, 3)
    result = gate(arm([runs["haiku9"]]), arm([runs["run9"]]))
    assert result["improved"] == ["K2.3"]
    assert result["beyond"]["outcome"] == gating.DROPPED


def test_the_command_line_exits_by_the_gate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    base = _write(tmp_path / "base" / "score.md", {"K1.1a family": "found", "K2.3 mutex": "missed"})
    same = _write(tmp_path / "same" / "score.md", {"K1.1a family": "found", "K2.3 mutex": "found"})
    worse = _write(
        tmp_path / "worse" / "score.md", {"K1.1a family": "partly", "K2.3 mutex": "found"}
    )
    out = tmp_path / "gate.json"
    assert (
        main(["gate", "--baseline", str(base), "--candidate", str(same), "--json", str(out)]) == 0
    )
    assert json.loads(out.read_text())["passed"] is True
    assert main(["gate", "--baseline", str(base), "--candidate", str(worse)]) == 1
    assert "K1.1a family: baseline found" in capsys.readouterr().out
    assert (
        main(
            [
                "gate",
                "--baseline",
                str(base),
                "--candidate",
                str(base),
                str(same),
                "--candidate-m",
                "3",
            ]
        )
        == 2
    )
    assert "not 3" in capsys.readouterr().err
    assert main(["gate", "--baseline", str(base), "--candidate", "blind:run9"]) == 2
    assert "needs --sheet and --map" in capsys.readouterr().err
    sheet, sealed = _blind(tmp_path)
    assert (
        main(
            [
                "gate",
                "--baseline",
                "blind:haiku9",
                "--candidate",
                "blind:nobody",
                "--sheet",
                str(sheet),
                "--map",
                str(sealed),
            ]
        )
        == 2
    )
    assert "names no arm 'nobody'" in capsys.readouterr().err
    scored = tmp_path / "score.json"
    assert main(["score", str(base), str(same), "--json", str(scored)]) == 0
    printed = capsys.readouterr().out
    assert "base (m 1 of 1): 1 found / 0 partly (body) / 0 partly (dump) / 1 missed" in printed
    assert "as one arm:" in printed
    assert json.loads(scored.read_text())["arm"]["totals"]["n"] == 2
    assert main(["score", str(tmp_path / "notes.txt")]) == 2


def test_the_gate_is_linear_in_items_and_runs() -> None:
    from tests.linear_cost import TIME_RATIO_LIMIT, calls, cpu_seconds

    words = ("found", "partly (body)", "missed", "partly (dump)", "wrong")

    def build(items: int) -> Callable[[], Any]:
        def runs(prefix: str, shift: int) -> list[ScoredRun]:
            return [
                ScoredRun(
                    f"{prefix}{r}",
                    f"{prefix}{r}",
                    {f"K{i}.1": (KEY, words[(i + r + shift) % 5]) for i in range(items)},
                    beyond=items + r,
                )
                for r in range(5)
            ]

        baseline, candidate = arm(runs("b", 0)), arm(runs("c", 1))
        return lambda: gate(baseline, candidate)

    build(50)()  # one-time costs (lazy imports) are not the gate's
    small, large = build(500), build(2000)
    # Four times the items must take under eight times the CPU time; a
    # quadratic gate takes sixteen. The calls made are held to the same ratio.
    assert cpu_seconds(large) < cpu_seconds(small) * TIME_RATIO_LIMIT
    assert calls(large) <= calls(small) * 4 * 1.2 + 100
