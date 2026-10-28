"""A behaviour-to-code link is never a wrong one, a slow one or a silent one.

The adversarial cases: a sample string of a million hive prefixes, a key name
ending in a parenthesis, a request path with no host, hosts written with a
port, brackets, a trailing dot or IDN, the guest's own traffic, a static side
read in part, two keys that differ only by hive, a copy of a text in another
place, overlapping section ranges, and items whose value is under a field the
reading does not know.
"""

from __future__ import annotations

from typing import Any

from tests.linear_cost import assert_scales
from tests.unit.analysis.test_observed_behaviour_is_linked_to_code import (
    MUTEX,
    _blobs,
    _entry,
    _link,
    _report,
    _strings,
)

from maljan.analysis import behaviour_code as bc
from maljan.reporting.detection_signatures import hiveless_key
from maljan.reporting.ledger_report import BEHAVIOUR_CODE_SECTION, build_sections


def _strings_of(*texts: str, total: int | None = None) -> bc.StaticInputs:
    rows = [{"offset": 0x10 * (i + 1), "enc": "ascii", "text": t} for i, t in enumerate(texts)]
    return bc.StaticInputs(strings=[("ev_0004", "strings", _strings(*rows, total=total))])


def _network(**kinds: Any) -> dict[str, Any]:
    report = _report()
    report["network"] = kinds
    return report


class TestHivePrefixesCostTheirLength:
    def test_a_megabyte_of_hive_prefixes_is_stripped_in_bounded_time(self) -> None:
        assert hiveless_key("HKCU\\" * 200_000 + "Software") == "Software"
        assert_scales(lambda count: "HKCU\\" * count + "Software", 25_000, hiveless_key)

    def test_a_megabyte_of_hive_prefixes_in_the_strings_head_links_in_bounded_time(self) -> None:
        report = _report(keys=["HKCU\\Software\\X"])
        inputs = _strings_of("HKCU\\" * 200_000)
        answer = bc.link_behaviour_to_code(report, None, inputs)
        assert_scales(
            lambda count: _strings_of("HKCU\\" * count),
            25_000,
            lambda held: bc.link_behaviour_to_code(report, None, held),
        )
        assert _link(answer, "HKCU\\Software\\X")["held"] == []

    def test_long_and_short_prefixes_together_are_still_one_key(self) -> None:
        assert hiveless_key("HKCU\\HKEY_CURRENT_USER\\Software\\X") == "Software\\X"

    def test_the_pack_s_deadline_stops_the_comparison_with_a_partial_answer(self) -> None:
        ticks = iter(range(100))
        inputs = _strings_of(*(f"text {i}" for i in range(10)))
        answer = bc.link_behaviour_to_code(
            _report(), None, inputs, deadline=3.0, clock=lambda: float(next(ticks))
        )
        assert answer["partial"] == bc.CUT_BY_BUDGET.format(done=4)
        assert answer["observed_only_label"] == bc.PARTLY_READ


class TestAKeyNameEndingInAParenthesis:
    KEY = "HKLM\\SOFTWARE\\Microsoft\\Vendor App (x86)"

    def test_it_is_not_held_by_its_sibling(self) -> None:
        answer = bc.link_behaviour_to_code(
            _report(keys=[self.KEY]), None, _strings_of("SOFTWARE\\Microsoft\\Vendor App")
        )
        assert _link(answer, self.KEY)["held"] == []

    def test_it_is_held_by_its_own_text(self) -> None:
        answer = bc.link_behaviour_to_code(
            _report(keys=[self.KEY]), None, _strings_of("SOFTWARE\\Microsoft\\Vendor App (x86)")
        )
        (held,) = _link(answer, self.KEY)["held"]
        assert held["matched"] == bc.WITHOUT_HIVE

    def test_the_ioc_table_s_suffix_is_still_stripped_where_it_is_one(self) -> None:
        assert hiveless_key("HKCU\\Software\\Run (Updater)") == "Software\\Run"
        assert hiveless_key("HKCU\\Software\\Run (Updater)", value_suffix=False) == (
            "Software\\Run (Updater)"
        )


class TestARequestPath:
    def test_a_triage_row_s_path_is_joined_with_its_host_and_scheme(self) -> None:
        row = {"host": "evil.example", "uri": "/gate.php", "port": None, "encrypted": False}
        answer = bc.link_behaviour_to_code(
            _network(http=[row]), None, _strings_of("http://evil.example/gate.php")
        )
        (held,) = _link(answer, "http://evil.example/gate.php")["held"]
        assert held["matched"] == bc.EXACT

    def test_a_non_default_port_and_https_are_written_in_the_url(self) -> None:
        row = {"host": "evil.example", "uri": "/a", "port": 8443, "encrypted": True}
        observed = bc.observed_values(_network(http=[row])).values
        assert ("url", "https://evil.example:8443/a") in {(o.kind, o.value) for o in observed}

    def test_a_path_with_no_host_or_scheme_is_a_path_never_a_url(self) -> None:
        for row in ({"uri": "/gate.php"}, {"host": "evil.example", "uri": "/gate.php"}):
            observed = bc.observed_values(_network(http=[row])).values
            kinds = {o.value: o.kind for o in observed}
            assert kinds["/gate.php"] == "url path"
            assert "url" not in kinds.values()


class TestHostsReadOneWay:
    def test_a_port_is_not_part_of_the_host(self) -> None:
        answer = bc.link_behaviour_to_code(
            _network(http=[{"host": "evil.com:8080"}]), None, _strings_of("evil.com")
        )
        assert [h["matched"] for h in _link(answer, "evil.com:8080")["held"]] == [bc.EXACT]

    def test_a_bracketed_address_is_the_host_of_a_url_in_another_spelling(self) -> None:
        answer = bc.link_behaviour_to_code(
            _network(hosts=["[2001:db8::1]"]), None, _strings_of("http://[2001:DB8:0::1]/a")
        )
        assert [h["matched"] for h in _link(answer, "[2001:db8::1]")["held"]] == [bc.URL_HOST]

    def test_a_trailing_dot_and_idn_are_one_host(self) -> None:
        report = _network(dns=[{"request": "evil.com."}, {"request": "xn--bcher-kva.de"}])
        answer = bc.link_behaviour_to_code(
            report, None, _strings_of("http://evil.com/a", "bücher.de")
        )
        assert [h["matched"] for h in _link(answer, "evil.com.")["held"]] == [bc.URL_HOST]
        assert [h["matched"] for h in _link(answer, "xn--bcher-kva.de")["held"]] == [bc.EXACT]


class TestTheGuestsOwnTraffic:
    def test_a_value_only_another_process_made_is_not_linked_and_is_counted(self) -> None:
        report = _network(tcp=[{"dst": "192.0.2.7", "sample_process_tree": False}])
        answer = bc.link_behaviour_to_code(report, None, _strings_of("192.0.2.7"))
        assert all(row["value"] != "192.0.2.7" for row in answer["links"])
        assert answer["not_linked"] == {"other processes": 1}
        assert any("outside the sample's tree" in s for s in bc.unread_words(answer))

    def test_a_value_the_sample_s_tree_made_is_linked_unmarked(self) -> None:
        report = _network(
            tcp=[
                {"dst": "192.0.2.7", "sample_process_tree": False},
                {"dst": "192.0.2.7", "sample_process_tree": True},
            ]
        )
        link = _link(bc.link_behaviour_to_code(report, None, _strings_of("192.0.2.7")), "192.0.2.7")
        assert link["attribution"] == bc.SAMPLE_TREE

    def test_a_value_no_row_attributes_is_marked_in_the_line_and_the_table(self) -> None:
        from maljan.pipeline.triage_pack import render_pack

        report = _network(tcp=[{"dst": "192.0.2.7"}])
        answer = bc.link_behaviour_to_code(report, None, _strings_of("192.0.2.7"))
        assert _link(answer, "192.0.2.7")["attribution"] == bc.NOT_ATTRIBUTED
        entry = _entry(bc.TOOL, answer, 8)
        assert f"(net:1; {bc.NOT_ATTRIBUTED})" in render_pack([entry], 0)
        table = next(s for s in build_sections([entry]) if s.key == BEHAVIOUR_CODE_SECTION)
        assert f"net:1 ({bc.NOT_ATTRIBUTED})" in [r[2] for r in table.rows]


class TestAPartlyReadStaticSide:
    def test_a_page_of_recovered_strings_is_counted_and_labels_observed_only(self) -> None:
        inputs = bc.StaticInputs(
            recovered=[("ev_0005", "floss", [{"string": "x", "kind": "stack"}])],
            recovered_of={"ev_0005": 4000},
        )
        answer = bc.link_behaviour_to_code(_report(), None, inputs)
        (row,) = answer["compared"]
        assert bc.compared_words(row) == "[ev_0005] recovered string (1 of 4,000 texts, a page)"
        assert answer["observed_only_label"] == bc.PARTLY_READ

    def test_decodings_no_code_refers_to_are_said_not_compared(self) -> None:
        blobs = {**_blobs(text="other"), "unreferenced": 3}
        answer = bc.link_behaviour_to_code(
            _report(), None, bc.StaticInputs(blobs=("ev_0007", "decode_string_blobs", blobs))
        )
        (row,) = answer["compared"]
        assert "3 decodings no code refers to were not compared" in bc.compared_words(row)
        assert answer["observed_only_label"] == bc.PARTLY_READ
        table = next(
            s
            for s in build_sections([_entry(bc.TOOL, answer, 8)])
            if s.key == BEHAVIOUR_CODE_SECTION
        )
        assert [r[3] for r in table.rows if r[1] == MUTEX] == [bc.PARTLY_READ]

    def test_an_unread_static_answer_labels_observed_only(self) -> None:
        inputs = bc.StaticInputs(unread=["strings"], absent={"strings": "no: [ev_0004] failed"})
        answer = bc.link_behaviour_to_code(_report(), None, inputs)
        assert answer["observed_only_label"] == bc.PARTLY_READ

    def test_a_whole_static_side_says_observed_only(self) -> None:
        answer = bc.link_behaviour_to_code(_report(), None, _strings_of("x" * 8))
        assert answer["observed_only_label"] == bc.OBSERVED_ONLY


class TestKeysThatDifferOnlyByHive:
    def test_both_are_held_by_the_one_hiveless_text(self) -> None:
        keys = ["HKLM\\Software\\Foo\\Bar", "HKCU\\Software\\Foo\\Bar"]
        answer = bc.link_behaviour_to_code(
            _report(keys=keys), None, _strings_of("Software\\Foo\\Bar")
        )
        for key in keys:
            assert [h["matched"] for h in _link(answer, key)["held"]] == [bc.WITHOUT_HIVE]


class TestAFunctionByText:
    def test_a_strings_row_placed_by_the_index_s_text_says_so(self) -> None:
        from tests.unit.analysis.test_observed_behaviour_is_linked_to_code import _index

        inputs = _strings_of(MUTEX)
        inputs.index = ("ev_0009", "function_index", _index(MUTEX, "0x2000"))
        answer = bc.link_behaviour_to_code(_report(), None, inputs)
        (held,) = _link(answer, MUTEX)["held"]
        assert bc.function_words(held, answer["functions"]) == f"{bc.SAME_TEXT} 0x2000"

    def test_a_blob_s_own_reference_is_its_function(self) -> None:
        inputs = bc.StaticInputs(blobs=("ev_0007", "decode_string_blobs", _blobs()))
        answer = bc.link_behaviour_to_code(_report(), None, inputs)
        (held,) = _link(answer, MUTEX)["held"]
        assert bc.function_words(held, answer["functions"]) == "function 0x1180"


class TestOverlappingSections:
    def _section(self, sections: list[dict[str, Any]]) -> Any:
        inputs = _strings_of(MUTEX)
        rows = inputs.strings[0][2]["strings"]
        rows[0]["offset"] = 0x900
        inputs.sections = sections
        answer = bc.link_behaviour_to_code(_report(), None, inputs)
        return _link(answer, MUTEX)["held"][0]["section"]

    def test_the_innermost_section_is_named(self) -> None:
        sections = [
            {"name": ".text", "raw_offset": 0x400, "raw_size": 0x2000},
            {"name": ".x", "raw_offset": 0x600, "raw_size": 0x200},
        ]
        assert self._section(sections) == ".text"
        sections.append({"name": ".in", "raw_offset": 0x800, "raw_size": 0x200})
        assert self._section(sections) == ".in"

    def test_two_of_equal_size_are_both_named(self) -> None:
        sections = [
            {"name": ".a", "raw_offset": 0x800, "raw_size": 0x200},
            {"name": ".b", "raw_offset": 0x800, "raw_size": 0x200},
        ]
        assert self._section(sections) == ".a / .b"


class TestNothingSkippedSilently:
    def test_items_with_no_value_under_the_fields_read_are_counted(self) -> None:
        report = _report()
        report["behavior"]["summary"]["files"] = [{"filepath": "C:\\x.exe"}, "C:\\y.exe"]
        answer = bc.link_behaviour_to_code(report, None, bc.StaticInputs())
        # The process row names no command line, so it is counted too.
        assert answer["no_value"] == {"files": 1, "processes": 1}
        assert "items with no value under the fields read: files 1, processes 1" in (
            bc.unread_words(answer)
        )

    def test_a_registry_row_s_value_name_and_data_are_both_read(self) -> None:
        report = _report()
        report["behavior"]["summary"]["keys"] = [
            {"key": "HKCU\\Software\\Run", "value": "Updater", "data": "C:\\u\\upd.exe"}
        ]
        observed = bc.observed_values(report).values
        assert {(o.kind, o.value) for o in observed} >= {
            ("registry key", "HKCU\\Software\\Run"),
            ("registry value name", "Updater"),
            ("registry value data", "C:\\u\\upd.exe"),
        }


def test_a_step_begun_after_the_pack_s_budget_is_a_not_run_entry(tmp_path: Any) -> None:
    from tests.unit.analysis.test_observed_behaviour_is_linked_to_code import _pack

    from maljan.core.pack_steps import shipped_step

    pack = _pack(tmp_path, _report())
    # One step has run, as the pack's earlier steps always have by now.
    pack.steps_run = 1
    pack.started -= 100
    pack._behaviour_code_links(shipped_step(bc.TOOL))
    (entry,) = pack.recorder.entries
    assert (entry.tool, entry.ok) == (bc.TOOL, False)
    assert "budget" in str(entry.error)
