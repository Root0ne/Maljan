"""A value the sandbox observed is linked to the static places that hold it, by exact match only.

The links read the normalised sandbox report through its sections, whichever
provider produced it, and the pack's own static answers (the printable runs,
the recovered strings, the decoded blobs, the function index). The match is
exact after the platform's normalisation for each kind; a value held nowhere
is "observed only"; a missing function index is said; every value printed is
quoted by the pack's escaping and, in the report, written as a code span.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from maljan.analysis import behaviour_code as bc
from maljan.pipeline.triage_pack import PACK_SOURCE, PIPELINE, behaviour_inputs, render_pack
from maljan.reporting.ledger_report import BEHAVIOUR_CODE_SECTION, build_sections
from maljan.reporting.renderers.markdown import _evidence_rows
from maljan.schemas.evidence import build_entry, format_entry_id
from maljan.utils.written_forms import pack_escaped

MUTEX = "Global\\QxRun_7781"
DOMAIN = "gate.observed-only.example"


def _report(**summary: Any) -> dict[str, Any]:
    return {
        "behavior": {
            "processes": [{"pid": 84, "ppid": 56, "process_name": "a.exe"}],
            "summary": {"mutexes": [MUTEX], **summary},
        },
        "network": {"dns": [{"request": DOMAIN, "type": "A", "sample_process_tree": True}]},
    }


def _blobs(text: str = MUTEX, function: str | None = "0x1180") -> dict[str, Any]:
    return {
        "tool": "decode_string_blobs",
        "results": [
            {
                "offset": "0x3010",
                "rva": "0x4010",
                "section": ".data",
                "scheme": "xor8",
                "parameters": {"key": "0x9c"},
                "text": text,
                "encoding": "ascii",
                "references": [{"at": "0x1204", "section": ".text", "function": function}],
            }
        ],
        "total": 1,
    }


def _index(text: str, function: str = "0x2000") -> dict[str, Any]:
    return {
        "tool": "function_index",
        "image_base": "0x400000",
        "rows": [
            {
                "function": hex(0x400000 + int(function, 16)),
                "offset": function,
                "plain_strings": [{"text": text, "sources": ["this entry"]}],
                "decoded_strings": [],
            }
        ],
    }


def _strings(*rows: dict[str, Any], total: int | None = None) -> dict[str, Any]:
    return {"strings": list(rows), "total": total or len(rows), "total_matched": total or len(rows)}


def _entry(tool: str, payload: Any, seq: int) -> Any:
    return build_entry(
        entry_id=format_entry_id(seq),
        seq=seq,
        agent=PIPELINE,
        tool=tool,
        args={},
        server=PIPELINE,
        output=json.dumps(payload),
        ok=True,
        stage="triage_pack",
        source=PACK_SOURCE,
    )


def _link(answer: dict[str, Any], value: str) -> dict[str, Any]:
    return next(row for row in answer["links"] if row["value"] == value)


class TestTheLinks:
    def test_a_mutex_held_in_a_decoded_blob_names_its_place_and_function(self) -> None:
        inputs = bc.StaticInputs(blobs=("ev_0007", "decode_string_blobs", _blobs()))
        answer = bc.link_behaviour_to_code(_report(), None, inputs)
        link = _link(answer, MUTEX)
        assert link["kind"] == "mutex"
        assert link["items"] == ["mutex:1"]
        (held,) = link["held"]
        assert held["source"] == bc.BLOB
        assert (held["entry"], held["offset"], held["section"]) == ("ev_0007", "0x3010", ".data")
        assert held["functions"] == ["0x1180"]
        assert answer["held"] == 1

    def test_a_blob_with_no_function_of_its_own_takes_the_index_s(self) -> None:
        inputs = bc.StaticInputs(
            blobs=("ev_0007", "decode_string_blobs", _blobs(function=None)),
            index=("ev_0009", "function_index", _index(MUTEX, "0x2000")),
        )
        link = _link(bc.link_behaviour_to_code(_report(), None, inputs), MUTEX)
        assert [h["functions"] for h in link["held"]] == [["0x2000"]]

    def test_a_registry_key_differing_only_in_case_is_held(self) -> None:
        key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
        report = _report(keys=[key])
        row = {"offset": 0x2210, "enc": "ascii", "text": key.lower()}
        inputs = bc.StaticInputs(
            strings=[("ev_0004", "strings", _strings(row))],
            sections=[{"name": ".rdata", "raw_offset": 0x2000, "raw_size": 0x1000}],
        )
        link = _link(bc.link_behaviour_to_code(report, None, inputs), key)
        assert link["kind"] == "registry key"
        (held,) = link["held"]
        assert (held["offset"], held["section"], held["text"]) == ("0x2210", ".rdata", key.lower())

    def test_a_mutex_differing_in_case_is_not_held(self) -> None:
        row = {"offset": 0x10, "enc": "ascii", "text": MUTEX.lower()}
        inputs = bc.StaticInputs(strings=[("ev_0004", "strings", _strings(row))])
        link = _link(bc.link_behaviour_to_code(_report(), None, inputs), MUTEX)
        assert link["held"] == []

    def test_a_utf16_path_is_held_with_its_encoding(self) -> None:
        path = "C:\\Users\\Public\\Libraries\\svc.dat"
        report = _report(files=[path])
        row = {"offset": 0x5000, "enc": "utf16le", "text": "c:\\users\\public\\libraries\\SVC.DAT"}
        inputs = bc.StaticInputs(strings=[("ev_0004", "strings", _strings(row))])
        link = _link(bc.link_behaviour_to_code(report, None, inputs), path)
        assert link["kind"] == "path"
        assert link["held"][0]["encoding"] == "utf16le"

    def test_a_named_pipe_is_named_so(self) -> None:
        pipe = "\\\\.\\pipe\\msagent_81"
        answer = bc.link_behaviour_to_code(_report(files=[pipe]), None, bc.StaticInputs())
        assert _link(answer, pipe)["kind"] == "named pipe"

    def test_a_substring_is_not_a_match(self) -> None:
        row = {"offset": 0x10, "enc": "ascii", "text": f"admin@{DOMAIN} said so"}
        inputs = bc.StaticInputs(strings=[("ev_0004", "strings", _strings(row))])
        link = _link(bc.link_behaviour_to_code(_report(), None, inputs), DOMAIN)
        assert link["held"] == []

    def test_a_domain_that_is_the_host_of_a_held_url_is_held_so(self) -> None:
        url = f"https://{DOMAIN.upper()}:8443/gate.php?id=1"
        row = {"offset": 0x40, "enc": "utf16le", "text": url}
        inputs = bc.StaticInputs(strings=[("ev_0004", "strings", _strings(row))])
        answer = bc.link_behaviour_to_code(_report(), None, inputs)
        (held,) = _link(answer, DOMAIN)["held"]
        assert (held["matched"], held["text"]) == (bc.URL_HOST, url)
        line = render_pack([_entry(bc.TOOL, answer, 8)], 0)
        assert f'as {bc.URL_HOST} "{url}"' in line
        table = next(
            s
            for s in build_sections([_entry(bc.TOOL, answer, 8)])
            if s.key == BEHAVIOUR_CODE_SECTION
        )
        assert [r[4] for r in table.rows if r[1] == DOMAIN] == [bc.URL_HOST]

    def test_an_address_that_is_the_host_of_a_held_url_is_held_so(self) -> None:
        report = _report()
        report["network"]["hosts"] = ["192.0.2.10"]
        row = {"offset": 0x40, "enc": "ascii", "text": "http://192.0.2.10/x.bin"}
        inputs = bc.StaticInputs(strings=[("ev_0004", "strings", _strings(row))])
        (held,) = _link(bc.link_behaviour_to_code(report, None, inputs), "192.0.2.10")["held"]
        assert held["matched"] == bc.URL_HOST

    def test_a_url_whose_host_only_contains_the_domain_is_not_held(self) -> None:
        row = {"offset": 0x40, "enc": "ascii", "text": f"https://cdn.{DOMAIN}/x"}
        inputs = bc.StaticInputs(strings=[("ev_0004", "strings", _strings(row))])
        assert _link(bc.link_behaviour_to_code(_report(), None, inputs), DOMAIN)["held"] == []

    @pytest.mark.parametrize("hive", ["HKEY_CURRENT_USER", "HKCU", "\\REGISTRY\\USER\\S-1-5-21-1"])
    def test_a_registry_key_held_without_its_hive_is_held_so(self, hive: str) -> None:
        key = f"{hive}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
        held_text = "software\\microsoft\\windows\\currentversion\\run\\Updater"
        row = {"offset": 0x80, "enc": "ascii", "text": held_text}
        inputs = bc.StaticInputs(strings=[("ev_0004", "strings", _strings(row))])
        answer = bc.link_behaviour_to_code(_report(keys=[key]), None, inputs)
        (held,) = _link(answer, key)["held"]
        assert (held["matched"], held["text"]) == (bc.WITHOUT_HIVE, held_text)

    def test_a_held_key_under_another_path_or_one_word_is_not_held(self) -> None:
        key = "HKLM\\Software\\Updater"
        rows = [
            {"offset": 1, "enc": "ascii", "text": "Software\\Other\\Updater"},
            {"offset": 2, "enc": "ascii", "text": "Updater"},
        ]
        inputs = bc.StaticInputs(strings=[("ev_0004", "strings", _strings(*rows))])
        answer = bc.link_behaviour_to_code(_report(keys=[key]), None, inputs)
        assert _link(answer, key)["held"] == []

    def test_an_exact_holding_is_labelled_exact(self) -> None:
        inputs = bc.StaticInputs(blobs=("ev_0007", "decode_string_blobs", _blobs()))
        link = _link(bc.link_behaviour_to_code(_report(), None, inputs), MUTEX)
        assert [h["matched"] for h in link["held"]] == [bc.EXACT]

    def test_a_domain_held_nowhere_is_observed_only_and_listed_after_the_held(self) -> None:
        inputs = bc.StaticInputs(blobs=("ev_0007", "decode_string_blobs", _blobs()))
        answer = bc.link_behaviour_to_code(_report(), None, inputs)
        assert [row["value"] for row in answer["links"]] == [MUTEX, DOMAIN]
        assert _link(answer, DOMAIN) == {
            "kind": "domain",
            "value": DOMAIN,
            "items": ["net:1"],
            "held": [],
            "attribution": bc.SAMPLE_TREE,
        }
        assert answer["observed_only"] == 1

    def test_a_static_text_never_observed_is_not_listed(self) -> None:
        row = {"offset": 0x10, "enc": "ascii", "text": "never.observed.example"}
        inputs = bc.StaticInputs(strings=[("ev_0004", "strings", _strings(row))])
        answer = bc.link_behaviour_to_code(_report(), None, inputs)
        assert {row["value"] for row in answer["links"]} == {MUTEX, DOMAIN}

    def test_a_page_of_strings_is_said_to_be_one(self) -> None:
        row = {"offset": 0x10, "enc": "ascii", "text": "x" * 8}
        inputs = bc.StaticInputs(strings=[("ev_0004", "strings", _strings(row, total=900))])
        (compared,) = bc.link_behaviour_to_code(_report(), None, inputs)["compared"]
        assert (compared["texts"], compared["of"]) == (1, 900)

    def test_a_missing_section_is_named_with_its_no(self) -> None:
        answer = bc.link_behaviour_to_code(_report(), None, bc.StaticInputs())
        assert answer["absent"]["sandbox commands"].startswith("no:")

    def test_any_provider_s_report_is_read_through_its_sections(self) -> None:
        from tests.unit.analysis.test_a_sandbox_report_reads_as_sections_of_items import _triage

        observed = bc.observed_values(_triage()).values
        assert observed
        assert all(one.items for one in observed)


class TestNoFunctionData:
    def test_no_function_index_is_said_in_the_answer_the_line_and_the_report(self) -> None:
        row = {"offset": 0x10, "enc": "ascii", "text": MUTEX}
        entries = [_entry("strings", _strings(row), 4)]
        inputs, joined = behaviour_inputs(entries)
        assert inputs.index is None
        assert inputs.absent["function_index"] == bc.NO_INDEX
        answer = bc.link_behaviour_to_code(_report(), None, inputs)
        assert answer["functions"] == bc.NO_INDEX
        held = _link(answer, MUTEX)["held"][0]
        assert bc.function_words(held, answer["functions"]) == (
            f"function {bc.NO_FUNCTION} ({bc.NO_INDEX})"
        )
        line = render_pack([*entries, _entry(bc.TOOL, answer, 5)], 0).splitlines()[-1]
        assert f"functions: {bc.NO_INDEX}" in line
        sections = build_sections([*entries, _entry(bc.TOOL, answer, 5)])
        table = next(s for s in sections if s.key == BEHAVIOUR_CODE_SECTION)
        assert bc.NO_INDEX in table.text
        assert joined == [("ev_0004", "strings")]


class TestThePackLine:
    def test_the_line_says_observed_held_at_in_function(self) -> None:
        inputs = bc.StaticInputs(blobs=("ev_0007", "decode_string_blobs", _blobs()))
        answer = bc.link_behaviour_to_code(_report(), None, inputs)
        line = render_pack([_entry(bc.TOOL, answer, 8)], 0)
        assert (
            f'mutex "{pack_escaped(MUTEX)}" (mutex:1) held at [ev_0007] decoded blob file 0x3010 '
            '(".data", xor8, ascii) in function 0x1180'
        ) in line
        assert f'domain "{DOMAIN}" (net:1) observed only' in line

    def test_the_line_takes_only_the_room_it_is_given(self) -> None:
        many = [f"Global\\m{i}" for i in range(400)]
        report = _report()
        report["behavior"]["summary"]["mutexes"] = many
        answer = bc.link_behaviour_to_code(report, None, bc.StaticInputs())
        entry = _entry(bc.TOOL, answer, 8)
        whole = render_pack([entry], 0)
        assert "all 401 shown" in whole
        fitted = render_pack([entry], 4000)
        assert len(fitted) <= 4000
        assert "the rest are in this entry's full output" in fitted


HOSTILE = 'x`` | [a](https://evil.example/)\n```\n# h "q"\\'


class TestAHostileValue:
    def _answer(self) -> dict[str, Any]:
        row = {"offset": 0x10, "enc": "ascii", "text": HOSTILE}
        inputs = bc.StaticInputs(
            strings=[("ev_0004", "strings", _strings(row))],
            sections=[{"name": "`.t|x\n", "raw_offset": 0, "raw_size": 0x100}],
        )
        report = _report()
        report["behavior"]["summary"]["mutexes"] = [HOSTILE]
        return bc.link_behaviour_to_code(report, None, inputs)

    def test_the_pack_line_quotes_it_with_the_pack_s_escaping(self) -> None:
        line = render_pack([_entry(bc.TOOL, self._answer(), 8)], 0)
        section = pack_escaped("`.t|x\n")
        assert "\n" not in line
        assert f'"{pack_escaped(HOSTILE)}"' in line
        assert f'"{section}"' in line

    def test_the_report_writes_it_as_one_code_span(self) -> None:
        sections = build_sections([_entry(bc.TOOL, self._answer(), 8)])
        table = next(s for s in sections if s.key == BEHAVIOUR_CODE_SECTION)
        rows = _evidence_rows(table)
        assert len(rows) == 4
        assert rows[3].endswith("| net:1 | observed only |  |  |")
        value_cell = rows[2].split(" | ")[1]
        assert value_cell.startswith("```` ") and value_cell.endswith(" ````")
        assert "\n" not in rows[2]
        assert "](https://" in value_cell
        assert "\\|" in value_cell


class TestLinearTime:
    @pytest.mark.parametrize("n", [500, 2000])
    def test_normalisations_grow_with_the_inputs_not_their_product(
        self, n: int, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = 0
        real = bc.indicator_fingerprint

        def counted(kind: Any, value: Any) -> tuple[str, str]:
            nonlocal calls
            calls += 1
            return real(kind, value)

        monkeypatch.setattr(bc, "indicator_fingerprint", counted)
        report = _report()
        report["behavior"]["summary"]["mutexes"] = [f"m{i}" for i in range(n)]
        rows = [{"offset": i, "enc": "ascii", "text": f"m{i}"} for i in range(n)]
        inputs = bc.StaticInputs(strings=[("ev_0004", "strings", _strings(*rows))])
        answer = bc.link_behaviour_to_code(report, None, inputs)
        assert answer["held"] == n
        kinds = len({bc.FINGERPRINT_KIND[row["kind"]] for row in answer["links"]})
        # Each observed value twice (read, indexed), each static text once per kind.
        assert calls <= 2 * (n + 1) + n * kinds


def _pack(tmp_path: Any, report: dict[str, Any] | None) -> Any:
    from maljan.agents.evidence_recorder import EvidenceCounter, EvidenceRecorder
    from maljan.pipeline.triage_pack import CapaSettings, PackInputs, _Pack

    inputs = PackInputs(
        sample_path=str(tmp_path / "s"),
        sha256="a" * 64,
        file_type="pe",
        strings_head=10,
        capa=CapaSettings(rules_dir="", signatures_dir="", timeout_s=1),
        sandbox_report=report,
        budget_s=1.0,
    )
    recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
    return _Pack(recorder, inputs, reputation=None, function_matches=None)


class TestThePackStep:
    def test_the_step_reads_the_pack_s_answers_and_is_the_last_step(self, tmp_path: Any) -> None:
        from maljan.core.pack_steps import default_steps, shipped_step

        assert default_steps()[-1].id == bc.TOOL
        pack = _pack(tmp_path, _report())
        pack.record("decode_string_blobs", {}, lambda: _blobs(function=None))
        pack.record("function_index", {}, lambda: _index(MUTEX, "0x2000"))
        pack._behaviour_code_links(shipped_step(bc.TOOL))
        entry = pack.recorder.entries[-1]
        assert (entry.tool, entry.ok) == (bc.TOOL, True)
        assert entry.args == {"joined": ["ev_0001 decode_string_blobs", "ev_0002 function_index"]}
        link = _link(entry.structured, MUTEX)
        assert [(h["source"], h["functions"]) for h in link["held"]] == [(bc.BLOB, ["0x2000"])]
        assert entry.structured["functions"] == {"entry": "ev_0002", "tool": "function_index"}
        lines = render_pack(pack.recorder.entries, 0).splitlines()
        (line,) = [one for one in lines if one.startswith(f"[{entry.id}] ")]
        assert line.startswith(f"[{entry.id}] behaviour to code: 2 values the sandbox observed")
        assert "in function 0x2000" in line

    def test_no_sandbox_report_records_nothing(self, tmp_path: Any) -> None:
        from maljan.core.pack_steps import shipped_step

        pack = _pack(tmp_path, None)
        pack._behaviour_code_links(shipped_step(bc.TOOL))
        assert pack.recorder.entries == []


def _repeated(n: int) -> tuple[dict[str, Any], bc.StaticInputs]:
    """One mutex observed ``n`` times, in a blob referred to ``n`` times from one function,
    and placed in one function by ``n`` index rows of the same start."""
    report = _report()
    report["behavior"]["summary"]["mutexes"] = [MUTEX] * n
    blobs = _blobs()
    blobs["results"][0]["references"] = [
        {"at": hex(0x1000 + i), "section": ".text", "function": "0x1180"} for i in range(n)
    ]
    index = _index(MUTEX, "0x2000")
    index["rows"] = index["rows"] * n
    return report, bc.StaticInputs(
        blobs=("ev_0007", "decode_string_blobs", blobs),
        index=("ev_0009", "function_index", index),
    )


class TestRepeatsStayLinear:
    def test_repeated_ids_are_kept_once_each_in_order(self) -> None:
        report, inputs = _repeated(50)
        link = _link(bc.link_behaviour_to_code(report, None, inputs), MUTEX)
        assert link["items"] == [f"mutex:{i}" for i in range(1, 51)]
        assert [h["functions"] for h in link["held"]] == [["0x1180"]]
        assert bc._index_functions(inputs.index[2] if inputs.index else None) == {MUTEX: ["0x2000"]}

    def test_many_repeats_grow_linearly(self) -> None:
        import time

        def spent(n: int) -> float:
            report, inputs = _repeated(n)
            best = float("inf")
            for _ in range(3):
                started = time.perf_counter()
                bc.link_behaviour_to_code(report, None, inputs)
                best = min(best, time.perf_counter() - started)
            return best

        small, large = spent(2_000), spent(16_000)
        # Eight times the repeats: linear is about 8x, a list scan per repeat about 64x.
        assert large < small * 24, (small, large)
