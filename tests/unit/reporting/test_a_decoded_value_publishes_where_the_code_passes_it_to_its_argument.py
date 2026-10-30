"""A decoded value publishes only where the code passes it whole to an API argument of its role.

A decoded mutex name, file path or user agent used to stay a candidate on
every surface, because its shape alone is no source: a run decodes user
agents the code never hands to anything. Now a decoded text is bound when the
run's own answers state the whole chain: the decoder's reference passes the
encoded bytes to the program's own routine, the frame slot that routine was
given is the argument of a call to an API (directly, or inside the function
that call reaches), the API is the import the file's table names or the slot a
function index entry names, and the argument-role table says that argument of
that API takes a value of a role, in the text's encoding. The bound value is a
row of the IOC table under the ``call_argument`` source, and its chain is the
reason §9, ``/iocs``, the STIX indicator and the MISP attribute each print.
Every value here is invented.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from app.services.report_service import ioc_feed_rows
from maljan.reporting.builder import build_consolidated_iocs
from maljan.reporting.call_bindings import (
    BOUND_SOURCE,
    BROWSER_LIKE,
    argument_roles,
    binding_words,
    bound_values_from_ledger,
    reads_as_a_browser_user_agent,
)
from maljan.reporting.misp import build_misp_attributes
from maljan.reporting.models import FileHashes, JudgeIndicator, MalwareReport, SampleIdentity
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.reporting.renderers.stix_renderer import (
    NOT_BOUND,
    ExtendedSTIXRenderer,
    indicator_pattern,
    pattern_values,
    publish_answer,
)
from maljan.schemas.evidence import LedgerEntry

ROOT = Path(__file__).resolve().parents[3]
MUTEX = "Global\\relay-lock-7"
AGENT = "ExampleAgent/2.1 (unit)"
SPARE = "OtherAgent/9.9"
BASE = 0x140000000
MUTEX_SLOT = 0x9C60
AGENT_SLOT = 0x9E00


def _hop(slot: str, call_at: str, argument: int, **more: Any) -> dict[str, Any]:
    return {
        "callee": {"slot": slot},
        "call_at": call_at,
        "argument": argument,
        "register": {1: "rcx", 2: "rdx", 3: "r8", 4: "r9"}[argument],
        "followed": "the frame slot [rsp+0x40], given to that call as argument 2,",
        "fall_through": False,
        "contents_unchanged": True,
        **more,
    }


def _row(text: str, encoding: str, then: dict[str, Any] | None, *, offset: str) -> dict:
    passed: dict[str, Any] = {
        "callee": {"function": "0x7e78"},
        "call_at": "0x3939",
        "argument": 1,
        "register": "rcx",
        "address_of": "blob",
    }
    if then is not None:
        passed["output_passed_to"] = then
    return {
        "text": text,
        "encoding": encoding,
        "offset": offset,
        "references": [{"at": "0x3935", "function": "0x3868", "passed_to": passed}],
    }


def _decoder(*rows: dict, entry: str = "ev_0021", **args: Any) -> LedgerEntry:
    return LedgerEntry(
        id=entry,
        agent="pipeline",
        tool="decode_string_blobs",
        args={"path": "sample.exe", **args},
        structured={"tool": "decode_string_blobs", "total": len(rows), "results": list(rows)},
    )


def _index(
    slots: dict[int, str], *, entry: str = "ev_0025", ambiguous: dict[int, list[str]] | None = None
) -> LedgerEntry:
    return LedgerEntry(
        id=entry,
        agent="pipeline",
        tool="function_index",
        args={"path": "sample.exe"},
        structured={
            "rows": [],
            "image_base": hex(BASE),
            "resolved_slots": {hex(BASE + slot): name for slot, name in slots.items()},
            "ambiguous_slots": {
                hex(BASE + slot): names for slot, names in (ambiguous or {}).items()
            },
        },
    )


def _mutex_row(**over: Any) -> dict:
    then = _hop(hex(MUTEX_SLOT), "0x3962", 3, **over)
    return _row(MUTEX, "utf-16le", then, offset="0xd800")


def _agent_row() -> dict:
    # The decoder's output goes to a routine of the file, which hands its
    # argument 1 to the session-opening API through a slot.
    then = {
        "callee": {"function": "0x4c70"},
        "call_at": "0x4ded",
        "argument": 1,
        "register": "rcx",
        "followed": "the frame slot [rsp+0x80], given to that call as argument 2,",
        "fall_through": True,
        "contents_unchanged": True,
        "inside": {
            "function": "0x4c70",
            "call_at": "0x4cb0",
            "callee": {"slot": hex(AGENT_SLOT)},
            "argument": 1,
            "register": "rcx",
            "fall_through": False,
            "contents_unchanged": True,
        },
    }
    return _row(AGENT, "utf-16le", then, offset="0xd9e0")


def _ledger() -> list[LedgerEntry]:
    return [
        _decoder(
            _mutex_row(),
            _agent_row(),
            # Decoded and never handed to anything: no chain, no binding.
            {
                "text": SPARE,
                "encoding": "utf-16le",
                "offset": "0xd9c0",
                "references": [{"at": "0x1b9e", "function": "0x1a08"}],
            },
        ),
        _index({MUTEX_SLOT: "CreateMutexW", AGENT_SLOT: "InternetOpenW"}),
    ]


def _report(**over: Any) -> MalwareReport:
    over.setdefault("bound_values", bound_values_from_ledger(_ledger()))
    over.setdefault("verdict", "Malware")
    over.setdefault("overall_confidence", 0.8)
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        malware_category="loader",
        **over,
    )


class TestTheBinding:
    def test_a_mutex_name_and_a_user_agent_bind_and_an_unused_text_does_not(self) -> None:
        bound = bound_values_from_ledger(_ledger())

        assert [(b.kind, b.value, b.api, b.argument, b.parameter) for b in bound] == [
            ("mutex", MUTEX, "CreateMutexW", 3, "lpName"),
            ("user_agent", AGENT, "InternetOpenW", 1, "lpszAgent"),
        ]
        mutex, agent = bound
        assert (mutex.entry, mutex.named_by, mutex.slot, mutex.call_at) == (
            "ev_0021",
            "ev_0025",
            hex(MUTEX_SLOT),
            "0x3962",
        )
        assert (agent.inside, agent.reaches, agent.reaches_argument, agent.call_at) == (
            "0x4c70",
            "0x4ded",
            1,
            "0x4cb0",
        )
        assert agent.fall_through is True

    def test_the_words_state_every_link_of_the_chain(self) -> None:
        mutex, agent = bound_values_from_ledger(_ledger())

        assert binding_words(mutex) == (
            "the code passes it to CreateMutexW as argument 3 (lpName, the name of the mutex "
            "the call creates or opens): decode_string_blobs decoded it in ev_0021 (blob at "
            "file offset 0xd800), loaded at 0x3935 in the function at 0x3868 and given to the "
            "routine called at 0x3939; the frame slot that routine was given is argument 3 of "
            f"the call at 0x3962, through the slot {hex(MUTEX_SLOT)} that ev_0025 names"
        )
        said = binding_words(agent)
        assert (
            "is argument 1 of the call at 0x4ded to the function at 0x4c70, and inside that "
            f"function argument 1 of the call at 0x4cb0, through the slot {hex(AGENT_SLOT)} that "
            "ev_0025 names, on the path where every conditional jump falls through"
        ) in said

    @pytest.mark.parametrize(
        "followed",
        ["that call's return value in rax", "the call's return value in rax", "", "rax"],
    )
    def test_only_a_followed_frame_slot_binds(self, followed: str) -> None:
        row = _mutex_row(followed=followed)

        assert bound_values_from_ledger([_decoder(row), _index({MUTEX_SLOT: "CreateMutexW"})]) == []

    @pytest.mark.parametrize("flag", [False, None], ids=["changed", "not-stated"])
    def test_a_slot_the_decoder_does_not_state_unchanged_binds_nothing(
        self, flag: bool | None
    ) -> None:
        row = _mutex_row()
        then = row["references"][0]["passed_to"]["output_passed_to"]
        if flag is None:
            then.pop("contents_unchanged")
        else:
            then["contents_unchanged"] = flag

        assert bound_values_from_ledger([_decoder(row), _index({MUTEX_SLOT: "CreateMutexW"})]) == []

    def test_an_argument_changed_inside_binds_nothing(self) -> None:
        row = _agent_row()
        row["references"][0]["passed_to"]["output_passed_to"]["inside"]["contents_unchanged"] = (
            False
        )

        assert (
            bound_values_from_ledger([_decoder(row), _index({AGENT_SLOT: "InternetOpenW"})]) == []
        )

    def test_a_direct_binding_on_the_fall_through_path_says_so(self) -> None:
        row = _mutex_row(fall_through=True)

        (bound,) = bound_values_from_ledger([_decoder(row), _index({MUTEX_SLOT: "CreateMutexW"})])

        assert bound.fall_through is True
        assert binding_words(bound).endswith(
            "names, on the path where every conditional jump falls through"
        )

    def test_a_binding_inside_on_the_fall_through_path_says_so(self) -> None:
        row = _agent_row()
        then = row["references"][0]["passed_to"]["output_passed_to"]
        then["fall_through"] = False
        then["inside"]["fall_through"] = True

        (bound,) = bound_values_from_ledger([_decoder(row), _index({AGENT_SLOT: "InternetOpenW"})])

        assert (bound.inside, bound.fall_through) == ("0x4c70", True)

    def test_the_ex_form_names_its_mutex_in_argument_2(self) -> None:
        row = _mutex_row()
        row["references"][0]["passed_to"]["output_passed_to"]["argument"] = 2

        (bound,) = bound_values_from_ledger([_decoder(row), _index({MUTEX_SLOT: "CreateMutexExW"})])
        wrong = bound_values_from_ledger([_decoder(row), _index({MUTEX_SLOT: "CreateMutexW"})])

        assert (bound.api, bound.argument, bound.parameter) == ("CreateMutexExW", 2, "lpName")
        assert wrong == []

    @pytest.mark.parametrize(
        ("constants", "binds"),
        [({"5": "0x2"}, True), ({"5": "0x1"}, True), ({"5": "0x3"}, False), (None, False)],
        ids=["create-always", "create-new", "open-existing", "not-read"],
    )
    def test_create_file_binds_only_when_it_creates_the_file(
        self, constants: dict[str, str] | None, binds: bool
    ) -> None:
        then = _hop(hex(MUTEX_SLOT), "0x3962", 1)
        if constants is not None:
            then["constants"] = constants
        row = _row("C:\\Users\\Public\\cache.bin", "utf-16le", then, offset="0xe000")

        bound = bound_values_from_ledger([_decoder(row), _index({MUTEX_SLOT: "CreateFileW"})])

        assert [(b.kind, b.api) for b in bound] == ([("path", "CreateFileW")] if binds else [])

    @pytest.mark.parametrize(
        ("api", "argument", "binds"),
        [
            ("CopyFileW", 1, False),
            ("CopyFileW", 2, True),
            ("MoveFileExW", 2, True),
            ("DeleteFileW", 1, True),
            ("SetFileAttributesW", 1, False),
        ],
    )
    def test_a_file_path_binds_where_the_call_makes_or_removes_the_file(
        self, api: str, argument: int, binds: bool
    ) -> None:
        then = _hop(hex(MUTEX_SLOT), "0x3962", argument)
        row = _row("C:\\Users\\Public\\cache.bin", "utf-16le", then, offset="0xe000")

        bound = bound_values_from_ledger([_decoder(row), _index({MUTEX_SLOT: api})])

        assert bool(bound) is binds

    def test_encoded_bytes_handed_straight_to_an_api_bind_nothing(self) -> None:
        row = _mutex_row()
        passed = row["references"][0]["passed_to"]
        passed["callee"] = {"import": "KERNEL32.dll!CreateMutexW", "slot": "0x9000"}
        passed["argument"] = 3

        assert bound_values_from_ledger([_decoder(row), _index({MUTEX_SLOT: "CreateMutexW"})]) == []

    def test_a_text_in_another_encoding_than_the_api_reads_binds_nothing(self) -> None:
        row = _mutex_row()
        row["encoding"] = "ascii"

        assert bound_values_from_ledger([_decoder(row), _index({MUTEX_SLOT: "CreateMutexW"})]) == []

    def test_an_import_the_file_s_table_names_binds_without_an_index(self) -> None:
        row = _mutex_row()
        row["references"][0]["passed_to"]["output_passed_to"]["callee"] = {
            "import": "KERNEL32.dll!CreateMutexW",
            "slot": "0x9000",
        }

        (bound,) = bound_values_from_ledger([_decoder(row)])

        assert (bound.api, bound.imported_as, bound.named_by) == (
            "CreateMutexW",
            "KERNEL32.dll!CreateMutexW",
            "",
        )
        assert "through the import KERNEL32.dll!CreateMutexW" in binding_words(bound)

    @pytest.mark.parametrize(
        "index",
        [
            [
                _index({MUTEX_SLOT: "CreateMutexW"}),
                _index({MUTEX_SLOT: "OpenEventW"}, entry="ev_9"),
            ],
            [_index({}, ambiguous={MUTEX_SLOT: ["CreateMutexW", "OpenEventW"]})],
            [],
        ],
        ids=["two-entries-disagree", "ambiguous", "no-index"],
    )
    def test_a_slot_no_entry_names_alone_binds_nothing(self, index: list[LedgerEntry]) -> None:
        assert bound_values_from_ledger([_decoder(_mutex_row()), *index]) == []

    def test_a_carved_file_s_text_is_not_bound_by_the_sample_s_index(self) -> None:
        carved = _decoder(_mutex_row(), carved_path="layer-1.bin")

        assert bound_values_from_ledger([carved, _index({MUTEX_SLOT: "CreateMutexW"})]) == []

    def test_a_decoder_of_another_name_is_read_by_its_declared_kind(self) -> None:
        entry = _decoder(_mutex_row()).model_copy(
            update={
                "tool": "unwrap_blobs",
                "source": "mcp:blob_reader",
                "facts": {"v": 1, "kind": "decoded_strings", "rows": "/results/*"},
            }
        )

        (bound,) = bound_values_from_ledger([entry, _index({MUTEX_SLOT: "CreateMutexW"})])

        assert bound.value == MUTEX

    def test_one_binding_per_value_the_first_in_ledger_order(self) -> None:
        ledger = [*_ledger(), _decoder(_mutex_row(), entry="ev_0040")]

        mutexes = [b for b in bound_values_from_ledger(ledger) if b.kind == "mutex"]

        assert [b.entry for b in mutexes] == ["ev_0021"]


class TestTheArgumentRoleTable:
    def test_every_argument_names_a_role_with_a_kind_and_an_encoding(self) -> None:
        document = json.loads((ROOT / "data" / "api_argument_roles_v1.json").read_text())
        roles = document["roles"]

        assert document["source"]
        for api, spec in document["apis"].items():
            assert spec["text"] in ("ascii", "utf-16le"), api
            for position, argument in spec["arguments"].items():
                assert int(position) >= 1, api
                assert argument["name"] and argument["role"] in roles, api
        assert all(role["kind"] and role["words"] for role in roles.values())

    def test_the_table_is_read_by_position(self) -> None:
        table = argument_roles()

        assert (table["CreateMutexW"][3].role, table["CreateMutexW"][3].text) == (
            "mutex_name",
            "utf-16le",
        )
        assert table["InternetOpenA"][1].kind == "user_agent"
        assert 2 not in table["CreateMutexW"]
        assert table["CreateFileW"][1].when == (5, "dwCreationDisposition", frozenset({1, 2}))

    def test_only_paths_a_call_makes_or_removes_are_listed(self) -> None:
        table = argument_roles()

        assert 1 not in table["CopyFileW"] and 1 not in table["MoveFileW"]
        assert "SetFileAttributesW" not in table
        assert all(
            role.when is not None
            for api in ("CreateFileA", "CreateFileW")
            for role in table[api].values()
        )

    def test_the_browser_prefixes_are_listed_with_their_source(self) -> None:
        document = json.loads((ROOT / "data" / "api_argument_roles_v1.json").read_text())
        listed = document["browser_user_agents"]

        assert listed["source"] and listed["prefixes"]
        assert reads_as_a_browser_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        assert not reads_as_a_browser_user_agent(AGENT)


class TestEverySurface:
    def test_the_ioc_table_publishes_each_bound_value_with_its_chain(self) -> None:
        rows = {row.value: row for row in build_consolidated_iocs(_report())}

        mutex, agent = rows[MUTEX], rows[AGENT]
        assert (mutex.type, mutex.kind, mutex.source, mutex.is_network) == (
            "Mutex",
            "mutex",
            BOUND_SOURCE,
            False,
        )
        assert mutex.context == "argument 3 (lpName) of CreateMutexW at 0x3962"
        assert mutex.published == f"yes: {binding_words(_report().bound_values[0])}"
        assert (agent.type, agent.kind, agent.is_network) == ("User-Agent", "user_agent", True)
        assert agent.published is not None and agent.published.startswith(
            "yes: the code passes it to InternetOpenW as argument 1 (lpszAgent"
        )
        assert SPARE not in rows

    def test_section_9_prints_each_row_with_its_chain(self) -> None:
        markdown = MarkdownRenderer().render(_report())

        line = next(ln for ln in markdown.splitlines() if "argument 3 (lpName)" in ln)
        assert "| call_argument | yes: the code passes it to CreateMutexW" in line
        agent = next(ln for ln in markdown.splitlines() if "argument 1 (lpszAgent)" in ln)
        assert "| call_argument | yes: the code passes it to InternetOpenW" in agent

    def test_the_feed_serves_each_row_published_with_its_chain(self) -> None:
        fed = {
            row["value"]: row
            for row in ioc_feed_rows(_report().model_dump(mode="json"))
            if row["source"] == BOUND_SOURCE
        }

        assert set(fed) == {MUTEX, AGENT}
        assert all(row["published"] for row in fed.values())
        assert fed[MUTEX]["publish_answer"].startswith("yes: the code passes it to CreateMutexW")

    def test_the_export_carries_an_indicator_for_each_with_the_chain(self) -> None:
        bundle = ExtendedSTIXRenderer().render(_report()).model_dump(mode="json")
        indicators = {
            obj["pattern"]: obj for obj in bundle["objects"] if obj.get("type") == "indicator"
        }

        mutex = indicators[str(indicator_pattern("mutex", MUTEX))]
        agent = indicators[
            "[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = "
            f"'{AGENT}']"
        ]
        assert "Published because: the code passes it to CreateMutexW" in mutex["description"]
        assert "through the slot" in agent["description"]

    def test_misp_types_each_and_says_why(self) -> None:
        report = _report()
        attributes = {
            a["value"]: a
            for a in build_misp_attributes(report, build_consolidated_iocs(report), owner="unit")
        }

        assert (attributes[MUTEX]["type"], attributes[MUTEX]["to_ids"]) == ("mutex", True)
        assert attributes[AGENT]["type"] == "user-agent"
        assert (
            "published because the code passes it to InternetOpenW" in attributes[AGENT]["comment"]
        )

    def test_the_judge_s_value_for_a_bound_value_is_asked_as_the_binding(self) -> None:
        report = _report(judge_indicators=[JudgeIndicator(kind="mutex", value=MUTEX)])
        bundle = {
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--0f1e2d3c-4b5a-4968-8776-655443332211",
                    "pattern": str(indicator_pattern("mutex", MUTEX)),
                    "pattern_type": "stix",
                    "indicator_types": ["malicious-activity"],
                }
            ]
        }
        from maljan.schemas.stix_models import Bundle

        rows = [r for r in build_consolidated_iocs(report) if r.value == MUTEX]
        exported = ExtendedSTIXRenderer().render(report, Bundle.model_validate(bundle))

        assert [r.source for r in rows] == [BOUND_SOURCE]
        named = [
            obj
            for obj in exported.model_dump(mode="json")["objects"]
            if obj.get("type") == "indicator"
            and ("mutex", MUTEX) in [(v.kind, v.value) for v in pattern_values(obj["pattern"])]
        ]
        assert len(named) == 1


def _bound_report(mutex: str, agent: str, **over: Any) -> MalwareReport:
    """A report binding ``mutex`` and ``agent`` as the default ledger binds its own."""
    mutex_row = _mutex_row()
    mutex_row["text"] = mutex
    agent_row = _agent_row()
    agent_row["text"] = agent
    ledger = [
        _decoder(mutex_row, agent_row),
        _index({MUTEX_SLOT: "CreateMutexW", AGENT_SLOT: "InternetOpenW"}),
    ]
    return _report(bound_values=bound_values_from_ledger(ledger), **over)


class TestTheVerdict:
    @pytest.mark.parametrize(
        ("over", "why"),
        [
            ({"verdict": "Benign"}, "but the verdict is Benign"),
            ({"overall_confidence": None}, "but the judge stated no verdict with a confidence"),
        ],
        ids=["benign", "unstated"],
    )
    def test_a_bound_value_is_refused_under_a_verdict_that_publishes_nothing(
        self, over: dict[str, Any], why: str
    ) -> None:
        report = _report(**over)
        rows = {row.value: row for row in build_consolidated_iocs(report)}

        for value in (MUTEX, AGENT):
            assert rows[value].published == (
                "no: the code passes it whole to an API argument of its role, "
                + why
                + (", which publishes no malicious indicator" if "Benign" in why else "")
            )
        exported = ExtendedSTIXRenderer().render(report).model_dump(mode="json")
        assert not [
            obj
            for obj in exported["objects"]
            if obj.get("type") == "indicator" and "mutex:name" in str(obj.get("pattern"))
        ]


class TestABrowserUserAgent:
    BROWSER = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )

    def test_its_row_keeps_the_chain_and_is_refused_with_why(self) -> None:
        report = _bound_report(MUTEX, self.BROWSER)
        (row,) = [r for r in build_consolidated_iocs(report) if r.value == self.BROWSER]
        (bound,) = [b for b in report.bound_values if b.value == self.BROWSER]

        assert row.source == BOUND_SOURCE
        assert row.published == f"no: {binding_words(bound)}; {BROWSER_LIKE}"

    def test_no_surface_publishes_it(self) -> None:
        report = _bound_report(MUTEX, self.BROWSER)
        bundle = ExtendedSTIXRenderer().render(report).model_dump(mode="json")
        attributes = {
            a["value"]: a
            for a in build_misp_attributes(report, build_consolidated_iocs(report), owner="unit")
        }
        fed = {row["value"]: row for row in ioc_feed_rows(report.model_dump(mode="json"))}

        assert not [
            obj
            for obj in bundle["objects"]
            if obj.get("type") == "indicator" and "User-Agent" in str(obj.get("pattern"))
        ]
        assert self.BROWSER not in attributes
        assert fed[self.BROWSER]["published"] is False
        assert fed[self.BROWSER]["publish_answer"].endswith(BROWSER_LIKE)
        assert fed[MUTEX]["published"] is True and attributes[MUTEX]["to_ids"] is True


class TestABrowserShapedUserAgentWithATokenOfItsOwn:
    # Browser-shaped, with a comment token no browser sends.
    AGENT = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Quill 2.4)"

    def test_its_row_is_published_naming_the_token(self) -> None:
        report = _bound_report(MUTEX, self.AGENT)
        (row,) = [r for r in build_consolidated_iocs(report) if r.value == self.AGENT]
        (bound,) = [b for b in report.bound_values if b.value == self.AGENT]

        assert row.source == BOUND_SOURCE
        assert row.published == (
            f"yes: {binding_words(bound)}; it begins as the common browsers' user agents do, "
            "but carries 'Quill 2.4', a token their own user agents do not send"
        )

    def test_every_surface_publishes_it(self) -> None:
        report = _bound_report(MUTEX, self.AGENT)
        bundle = ExtendedSTIXRenderer().render(report).model_dump(mode="json")
        attributes = {
            a["value"]: a
            for a in build_misp_attributes(report, build_consolidated_iocs(report), owner="unit")
        }
        fed = {row["value"]: row for row in ioc_feed_rows(report.model_dump(mode="json"))}

        assert [
            obj
            for obj in bundle["objects"]
            if obj.get("type") == "indicator"
            and ("user_agent", self.AGENT)
            in [(v.kind, v.value) for v in pattern_values(obj["pattern"])]
        ]
        assert attributes[self.AGENT]["to_ids"] is True
        assert fed[self.AGENT]["published"] is True
        assert "'Quill 2.4'" in fed[self.AGENT]["publish_answer"]

    def test_under_a_benign_verdict_it_is_still_refused(self) -> None:
        report = _bound_report(MUTEX, self.AGENT, verdict="Benign")
        (row,) = [r for r in build_consolidated_iocs(report) if r.value == self.AGENT]

        assert row.published is not None and row.published.startswith("no: ")


def test_a_quote_and_a_backslash_reach_stix_and_misp_whole() -> None:
    mutex = "Local\\it's-held"
    agent = "Tool\\Agent 'x'/1.0"
    report = _bound_report(mutex, agent)

    bundle = ExtendedSTIXRenderer().render(report).model_dump(mode="json")
    exported = {
        (value.kind, value.value): obj
        for obj in bundle["objects"]
        if obj.get("type") == "indicator"
        for value in pattern_values(obj["pattern"])
    }
    attributes = {
        a["value"]: a
        for a in build_misp_attributes(report, build_consolidated_iocs(report), owner="unit")
    }

    assert "the code passes it to CreateMutexW" in exported[("mutex", mutex)]["description"]
    assert "the code passes it to InternetOpenW" in exported[("user_agent", agent)]["description"]
    assert exported[("mutex", mutex)]["pattern"] == "[mutex:name = 'Local\\\\it\\'s-held']"
    assert (attributes[mutex]["type"], attributes[agent]["type"]) == ("mutex", "user-agent")
    assert attributes[agent]["to_ids"] is True


class TestTheUserAgentPattern:
    def test_the_pattern_reads_back_as_the_value(self) -> None:
        pattern = str(indicator_pattern("user_agent", AGENT))

        assert [(v.kind, v.value) for v in pattern_values(pattern)] == [("user_agent", AGENT)]

    def test_an_unbound_user_agent_is_refused_with_why(self) -> None:
        assert publish_answer("user_agent", SPARE, "strings") == f"no: {NOT_BOUND}"

    def test_a_captured_user_agent_is_still_refused_as_unattributed(self) -> None:
        said = publish_answer("user_agent", AGENT, "sandbox", unattributed="no process is named")

        assert said == "no: no process is named"


def test_a_report_with_no_binding_dumps_as_before() -> None:
    dumped = _report(bound_values=[]).model_dump(mode="json")

    assert "bound_values" not in dumped
