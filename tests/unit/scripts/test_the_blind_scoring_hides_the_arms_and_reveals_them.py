"""Blind A/B scoring: the copies name no arm, the shuffle is repeatable, the reveal maps back.

Two small stored runs are built by hand, each with a model, a job id, a
report number and dates that must not survive in what a scorer reads.
"""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pytest
from scripts.blind import prepare as prepare_module
from scripts.blind.identity import leaks
from scripts.blind.prepare import BEYOND_ROW, BlindError, prepare, read_items, self_check
from scripts.blind.reveal import render, reveal
from scripts.blind.run import main
from scripts.replay.stored import StoredRunChanged

ARMS = {
    "alpha-run": ("zephyrmodel-large", "11111111-1111-4111-8111-111111111111", "2026-01-02"),
    "beta-run": ("quasarmodel-small", "22222222-2222-4222-8222-222222222222", "2026-03-04"),
}
ITEMS = ["K1.1a", "K1.2", "K2.1"]


def _run(root: Path, name: str) -> Path:
    model, job, day = ARMS[name]
    run = root / name
    run.mkdir()
    (run / "report.md").write_text(
        f"# Loader analysis\n\nRun {name} on {model}, job {job},"
        f" report MJN{day.replace('-', '')}-6091f2,"
        f" written {day}T10:11:12Z. Settings at /srv/{name}/settings.json.\n",
        encoding="utf-8",
    )
    (run / "report.html").write_text(f"<p>{model.upper()} {day}</p>", encoding="utf-8")
    (run / "stix-bundle.json").write_text(
        json.dumps(
            {"type": "bundle", "objects": [{"created": f"{day}T01:02:03.000Z", "note": model}]}
        ),
        encoding="utf-8",
    )
    (run / "iocs.json").write_text(
        json.dumps({"iocs": [{"value": "198.51.100.7"}]}), encoding="utf-8"
    )
    (run / "meta.json").write_text(json.dumps({"model": f"{model} (thinking on)", "job_id": job}))
    (run / "job.json").write_text(json.dumps({"id": job, "config": {"profile": f"{name}-team"}}))
    (run / "run-summary.json").write_text(
        json.dumps({"settings_snapshot": {"llm": {"provider": f"{name}-cloud", "model": model}}})
    )
    (run / "score.md").write_text(f"{name} scored found everything", encoding="utf-8")
    return run


@pytest.fixture
def runs(tmp_path: Path) -> list[Path]:
    base = tmp_path / "stored"
    base.mkdir()
    return [_run(base, name) for name in ARMS]


def _tree(directory: Path) -> dict[str, bytes]:
    return {
        p.relative_to(directory).as_posix(): p.read_bytes()
        for p in sorted(directory.rglob("*"))
        if p.is_file()
    }


def _hashes(paths: list[Path]) -> dict[str, str]:
    return {
        str(p): hashlib.sha256(p.read_bytes()).hexdigest()
        for root in paths
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def test_a_seed_gives_the_same_copies_and_map_every_time(runs: list[Path], tmp_path: Path) -> None:
    first = prepare(runs, tmp_path / "one", ITEMS, seed=7)
    second = prepare(runs, tmp_path / "two", ITEMS, seed=7)
    assert _tree(first.scorer_dir) == _tree(second.scorer_dir)
    assert first.sealed.read_text() == second.sealed.read_text()
    assert first.ids == ["A", "B"]


def test_the_shuffle_can_put_either_arm_first(runs: list[Path], tmp_path: Path) -> None:
    seen = set()
    for seed in range(12):
        done = prepare(runs, tmp_path / f"s{seed}", ITEMS, seed=seed)
        arms = json.loads(done.sealed.read_text())["arms"]
        seen.add(arms["A"]["name"])
    assert seen == set(ARMS)


def test_without_a_seed_the_order_is_drawn_and_the_copies_are_still_clean(
    runs: list[Path], tmp_path: Path
) -> None:
    done = prepare(runs, tmp_path / "out", ITEMS)
    sealed = json.loads(done.sealed.read_text())
    assert sealed["seed"] is None
    assert {arm["name"] for arm in sealed["arms"].values()} == set(ARMS)


def test_nothing_that_names_an_arm_is_left_in_the_copies(runs: list[Path], tmp_path: Path) -> None:
    done = prepare(runs, tmp_path / "out", ITEMS, seed=1)
    text = "\n".join(p.read_text() for p in done.scorer_dir.rglob("*") if p.is_file()).lower()
    for name, (model, job, day) in ARMS.items():
        for needle in (
            name,
            model,
            job,
            day,
            day.replace("-", ""),
            f"{name}-team",
            f"{name}-cloud",
        ):
            assert needle.lower() not in text, needle
    assert "198.51.100.7" in text  # the evidence the scorer reads is kept
    assert "score.md" not in {p.name for p in done.scorer_dir.rglob("*")}
    # redaction leaves the STIX copy readable JSON
    for anon in done.ids:
        json.loads((done.scorer_dir / anon / "stix-bundle.json").read_text())


def test_the_sealed_map_lives_outside_the_scorer_directory(
    runs: list[Path], tmp_path: Path
) -> None:
    done = prepare(runs, tmp_path / "out", ITEMS, seed=3)
    assert done.scorer_dir not in done.sealed.parents
    assert not any("sealed" in p.name or "map" in p.name for p in done.scorer_dir.rglob("*"))


def test_the_self_check_fails_on_a_string_that_survived(tmp_path: Path) -> None:
    scorer = tmp_path / "scorer"
    (scorer / "A").mkdir(parents=True)
    (scorer / "A" / "report.md").write_text("made by Zephyrmodel on 2026-01-02")
    (scorer / "scores.csv").write_text("item,A\n")
    problems = self_check(scorer, {"zephyrmodel"}, ["A"])
    assert problems and "zephyrmodel" in problems[0] and "a date" in problems[0]
    assert leaks("clean", {"zephyrmodel"}) == []


def test_an_extra_identifying_string_is_removed_too(runs: list[Path], tmp_path: Path) -> None:
    (runs[0] / "report.md").write_text("Reviewed by the Falcon desk.")
    done = prepare(runs, tmp_path / "out", ITEMS, seed=1, identify=("falcon desk",))
    assert "falcon" not in "".join(
        p.read_text().lower() for p in done.scorer_dir.rglob("report.md")
    )


def _fill(template: Path, verdicts: dict[str, dict[str, str]], beyond: dict[str, int]) -> None:
    with template.open(newline="") as handle:
        rows = list(csv.reader(handle))
    header = rows[0]
    for row in rows[1:]:
        for column, anon in enumerate(header[1:], start=1):
            row[column] = str(beyond[anon]) if row[0] == BEYOND_ROW else verdicts[anon][row[0]]
    with template.open("w", newline="") as handle:
        csv.writer(handle).writerows(rows)


def test_the_reveal_maps_scores_back_to_the_arms(runs: list[Path], tmp_path: Path) -> None:
    done = prepare(runs, tmp_path / "out", ITEMS, seed=5)
    arms = json.loads(done.sealed.read_text())["arms"]
    winner = next(anon for anon, arm in arms.items() if arm["name"] == "alpha-run")
    loser = next(anon for anon in arms if anon != winner)
    _fill(
        done.template,
        {
            winner: {"K1.1a": "found", "K1.2": "found", "K2.1": "partly (body)"},
            loser: {"K1.1a": "found", "K1.2": "missed", "K2.1": "wrong"},
        },
        {winner: 4, loser: 1},
    )
    result = reveal(done.template, done.sealed)
    assert result.totals["alpha-run"]["found"] == 2
    assert result.totals["beta-run"]["missed"] == 1
    assert result.beyond == {"alpha-run": 4, "beta-run": 1}
    assert set(result.differences) == {"K1.2", "K2.1"}
    assert result.differences["K1.2"] == {"alpha-run": "found", "beta-run": "missed"}
    text = render(result)
    assert "K1.2: alpha-run found; beta-run missed" in text


def test_the_reveal_reads_json_scores_too(runs: list[Path], tmp_path: Path) -> None:
    done = prepare(runs, tmp_path / "out", ITEMS, seed=5)
    sheet = {anon: {**{item: "found" for item in ITEMS}, BEYOND_ROW: 0} for anon in done.ids}
    path = tmp_path / "scores.json"
    path.write_text(json.dumps({"scores": sheet}))
    assert reveal(path, done.sealed).differences == {}


def test_a_partial_score_is_refused_and_names_the_item(runs: list[Path], tmp_path: Path) -> None:
    done = prepare(runs, tmp_path / "out", ITEMS, seed=5)
    fill = {anon: {item: "found" for item in ITEMS} for anon in done.ids}
    fill["B"]["K1.2"] = ""
    _fill(done.template, fill, {"A": 0, "B": 0})
    with pytest.raises(BlindError, match=r"item K1\.2 is not scored for B"):
        reveal(done.template, done.sealed)
    assert main(["reveal", str(done.template), "--map", str(done.sealed)]) == 2


def test_an_unscored_beyond_row_and_a_bad_verdict_are_refused(
    runs: list[Path], tmp_path: Path
) -> None:
    done = prepare(runs, tmp_path / "out", ITEMS, seed=5)
    fill = {anon: {item: "found" for item in ITEMS} for anon in done.ids}
    no_count = tmp_path / "no-count.json"
    no_count.write_text(json.dumps(fill))
    with pytest.raises(BlindError, match=BEYOND_ROW):
        reveal(no_count, done.sealed)
    fill["A"]["K2.1"] = "great"
    _fill(done.template, fill, {"A": 0, "B": 0})
    with pytest.raises(BlindError, match=r"K2\.1"):
        reveal(done.template, done.sealed)


def test_the_stored_runs_are_untouched(runs: list[Path], tmp_path: Path) -> None:
    before = _hashes(runs)
    prepare(runs, tmp_path / "out", ITEMS, seed=2)
    assert _hashes(runs) == before


def test_a_run_that_changes_during_the_preparation_fails_it(
    runs: list[Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = prepare_module.identifiers

    def touching(root: Path, name: str, extra: tuple[str, ...] = ()) -> set[str]:
        with (root / "report.md").open("a") as handle:
            handle.write("tampered")
        return real(root, name, extra)

    monkeypatch.setattr(prepare_module, "identifiers", touching)
    with pytest.raises(StoredRunChanged):
        prepare(runs, tmp_path / "out", ITEMS, seed=2)


def test_the_arms_must_hold_the_same_files_and_the_output_must_be_empty(
    runs: list[Path], tmp_path: Path
) -> None:
    (runs[1] / "iocs.json").unlink()
    with pytest.raises(BlindError, match="same scorer-facing files"):
        prepare(runs, tmp_path / "out", ITEMS)
    (runs[1] / "iocs.json").write_text("{}")
    full = tmp_path / "full"
    full.mkdir()
    (full / "x").write_text("x")
    with pytest.raises(BlindError, match="not empty"):
        prepare(runs, full, ITEMS)
    with pytest.raises(BlindError, match="at least two"):
        prepare(runs[:1], tmp_path / "solo", ITEMS)


def test_the_command_prepares_without_printing_the_map(
    runs: list[Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    items = tmp_path / "items.txt"
    items.write_text("# the list\n" + "\n".join(ITEMS) + "\n")
    code = main(
        [
            "prepare",
            *map(str, runs),
            "--out",
            str(tmp_path / "out"),
            "--items",
            str(items),
            "--seed",
            "4",
        ]
    )
    shown = capsys.readouterr().out
    assert code == 0 and "self-check passed" in shown
    assert not any(name in shown for name in ARMS)
    assert read_items(items) == ITEMS
