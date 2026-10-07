"""A claim about a function is checked against that function's own facts.

The claim cites the listing of a function the analyst decompiled. The Windows
function names and the quoted strings its sentence names are looked for in the
listing, in the function's row of the pack's function index, in the rows of its
direct callees, and where the run's hash resolution and blob decoder place a
value inside it. A value none of them holds is stated to the analyst once; where
a fact is not whole the check states nothing and the record says why.

Every address, name, string and sentence here is made up for the test.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

from maljan.agents.function_map import INDEX_NOT_KEPT, function_artefacts
from maljan.pipeline import function_claims as fc
from maljan.pipeline.function_claims import (
    FUNCTION_CLAIM_UNHELD_CODE,
    check_function_claims,
    function_facts,
    listed_functions,
    named_values,
)
from maljan.pipeline.validation import FUNCTION_QUESTION_ASK
from maljan.schemas.evidence import LedgerEntry, not_shown_record
from maljan.schemas.isr_models import ClaimEvidence
from maljan.tools.artefact_index import SELF, row_line

BASE = 0x140000000
MAIN = 0x2340
HELPER = 0x2A10
FAR = 0x3B80
OTHER = 0x4C00
INDEX_ID = "ev_0002"
LISTING_ID = "ev_0007"


def _cells(key: str, values: Any) -> list[dict[str, Any]]:
    return [{key: value, "sources": [SELF]} for value in values]


def _row(
    offset: int,
    *,
    imports: Any = (),
    resolved: Any = (),
    decoded: Any = (),
    plain: Any = (),
    capa: Any = (),
    callers: Any = (),
    callees: Any = (),
) -> dict[str, Any]:
    return {
        "function": hex(BASE + offset),
        "offset": hex(offset),
        "direct": len(imports) + len(resolved) + len(decoded) + len(plain) + len(capa),
        "imports": _cells("name", imports),
        "resolved": _cells("name", resolved),
        "decoded_strings": _cells("text", decoded),
        "plain_strings": _cells("text", plain),
        "capa": _cells("rule", capa),
        "callers": [hex(BASE + c) for c in callers],
        "callees": [hex(BASE + c) for c in callees],
        "indirect": {"artefacts": 0, "through": 0},
    }


def _index(
    rows: list[dict[str, Any]],
    *,
    unnamed: Any = None,
    undecoded: Any = None,
    others: Any = (),
) -> LedgerEntry:
    data: dict[str, Any] = {
        "tool": "function_index",
        "image_base": hex(BASE),
        "functions_known": 8,
        "undecoded_functions": len(undecoded or []),
        "undecoded": [hex(BASE + o) for o in (undecoded or [])],
        "calls_unnamed": {hex(BASE + o): n for o, n in (unnamed or {}).items()},
        "rows": rows,
    }
    if unnamed is False:
        del data["calls_unnamed"]
    if others is not None:
        data["other_callees"] = {
            hex(BASE + start): [hex(BASE + c) for c in callees]
            for start, callees in dict(others).items()
        }
    return LedgerEntry(
        id=INDEX_ID,
        agent="pipeline",
        tool="function_index",
        output=json.dumps(data),
        structured=data,
    )


def _listing(body: str = "  FUN_140002a10();\n  return 0;", entry: str = LISTING_ID) -> LedgerEntry:
    return LedgerEntry(
        id=entry,
        agent="reverser",
        tool="decompile_function",
        args={"address": f"{BASE + MAIN:x}"},
        output=f"\nundefined8 FUN_{BASE + MAIN:x}(void)\n\n{{\n{body}\n}}\n",
    )


HELPER_LISTING_ID = "ev_0008"
HELPER_VA = f"0x{BASE + HELPER:x}"


def _helper_listing() -> LedgerEntry:
    return LedgerEntry(
        id=HELPER_LISTING_ID,
        agent="reverser",
        tool="decompile_function",
        args={"address": f"{BASE + HELPER:x}"},
        output=f"\nundefined8 FUN_{BASE + HELPER:x}(void)\n\n{{\n  return 0;\n}}\n",
    )


ROWS = [
    _row(MAIN, imports=["CreateMutexW"], decoded=["update-channel"], callees=[HELPER]),
    _row(HELPER, imports=["GetTickCount"], plain=["helper banner"], callers=[MAIN], callees=[FAR]),
    _row(FAR, imports=["WriteFile"], callers=[HELPER]),
    _row(OTHER, decoded=["settings.ini path"], callers=[]),
]


def _check(
    sentence: str,
    *,
    index: LedgerEntry | None = None,
    pack: list[LedgerEntry] | None = None,
    own: list[LedgerEntry] | None = None,
    evidence: str = f"[{LISTING_ID}]",
    block: str = "",
    extra: list[ClaimEvidence] | None = None,
) -> fc.FunctionClaimCheck:
    pack_entries = [*(pack or []), *([index] if index is not None else [_index(ROWS)])]
    mine = own if own is not None else [_listing()]
    facts = function_facts(
        mine,
        function_artefacts(pack_entries),
        pack_entries=pack_entries,
        facts_block=block,
        bases=(BASE,),
    )
    claims = [ClaimEvidence(claim=sentence, evidence_ref=evidence, confidence=0.8), *(extra or [])]
    return check_function_claims(
        SimpleNamespace(claims=claims), listed_functions(mine), facts, (BASE,)
    )


MAIN_VA = f"0x{BASE + MAIN:x}"


class TestTheQuestion:
    def test_an_api_the_function_s_facts_hold_nowhere_is_asked_once(self) -> None:
        found = _check(f"{MAIN_VA} sleeps with SleepEx before it writes the marker.")

        (violation,) = found.violations
        assert violation.code == FUNCTION_CLAIM_UNHELD_CODE
        assert violation.path == "claims[0]"
        assert found.flagged == [0] and found.asked == 1 and found.checked == 1
        message = violation.message
        assert message.startswith("claim 1 (")
        assert f'names "SleepEx" for function {MAIN_VA} [{LISTING_ID}]' in message
        assert (
            f'neither its listing nor its index row [{INDEX_ID}] holds "SleepEx", and no '
            f"function reachable from {MAIN_VA} through its call edges holds it (2 functions "
            f"reachable); {fc.NOT_FOLLOWED}" in message
        )
        assert f'{MAIN_VA}\'s row holds: calls "CreateMutexW" ({INDEX_ID})' in message
        assert "refers to 1 decoded string" in message
        assert message.endswith(FUNCTION_QUESTION_ASK)

    def test_every_unheld_value_of_a_claim_is_named_in_its_one_question(self) -> None:
        found = _check(f'{MAIN_VA} calls SleepEx and VirtualAlloc and reads "settings.ini path".')

        (violation,) = found.violations
        assert '"SleepEx", "VirtualAlloc" and "settings.ini path"' in violation.message
        assert 'holds "SleepEx" or "VirtualAlloc" or "settings.ini path"' in violation.message
        assert "holds any of them (2 functions reachable)" in violation.message

    def test_one_claim_written_under_several_techniques_is_asked_once(self) -> None:
        sentence = f"{MAIN_VA} sleeps with SleepEx."
        claims = [
            ClaimEvidence(
                claim=sentence, evidence_ref=f"[{LISTING_ID}]", confidence=0.8, technique_id=tid
            )
            for tid in ("T1497", "T1027")
        ]
        for claim in claims:
            claim.note_block(0)
        own = [_listing()]
        pack = [_index(ROWS)]
        facts = function_facts(own, function_artefacts(pack), pack_entries=pack, bases=(BASE,))
        found = check_function_claims(
            SimpleNamespace(claims=claims), listed_functions(own), facts, (BASE,)
        )
        assert len(found.violations) == 1 and found.flagged == [0]

    def test_a_long_row_is_counted_instead_of_listed(self) -> None:
        names = [f"RtlUserRoutine{n:02d}" for n in range(40)]
        index = _index([_row(MAIN, resolved=names), *ROWS[1:]])
        (violation,) = _check(f"{MAIN_VA} sleeps with SleepEx.", index=index).violations
        assert f"{MAIN_VA}'s row holds: 40 resolved names ({INDEX_ID}); called by 0" in (
            violation.message
        )
        assert "RtlUserRoutine00" not in violation.message


class TestWhereAValueHolds:
    def test_the_function_s_own_import_holds_in_either_spelling_and_with_its_module(self) -> None:
        assert not _check(f"{MAIN_VA} creates the guard with CreateMutexW.").violations
        assert not _check(f"{MAIN_VA} creates the guard with CreateMutexA.").violations
        assert not _check(f"{MAIN_VA} calls `kernel32.dll!CreateMutexW`.").violations

    def test_the_listing_s_own_text_holds(self) -> None:
        own = [_listing("  SleepEx(1000, 0);\n  return 0;")]
        assert not _check(f"{MAIN_VA} calls SleepEx.", own=own).violations

    def test_a_direct_callee_s_row_holds(self) -> None:
        assert not _check(f"{MAIN_VA} reads the clock with GetTickCount.").violations
        assert not _check(f'{MAIN_VA} prints "helper banner".').violations

    def test_a_function_two_calls_away_holds_too(self) -> None:
        # MAIN calls HELPER, which calls FAR: FAR's WriteFile is reachable.
        found = _check(f"{MAIN_VA} writes the file with WriteFile.")
        assert found.violations == [] and found.checked == 1

    def test_a_listed_callee_s_reach_read_first_is_part_of_its_caller_s(self) -> None:
        own = [_listing(), _helper_listing()]
        found = _check(f"{MAIN_VA} writes the file with WriteFile.", own=own)
        assert found.violations == [] and found.checked == 1

    def test_a_claim_naming_two_listed_functions_holds_what_either_reaches(self) -> None:
        own = [_listing(), _helper_listing()]
        evidence = f"[{LISTING_ID}] [{HELPER_LISTING_ID}]"
        held = _check(
            f"{MAIN_VA} and {HELPER_VA} guard with CreateMutexW and write with WriteFile.",
            own=own,
            evidence=evidence,
        )
        assert held.violations == [] and held.checked == 1
        asked = _check(f"{MAIN_VA} and {HELPER_VA} sleep with SleepEx.", own=own, evidence=evidence)
        (violation,) = asked.violations
        # MAIN reaches HELPER and FAR, HELPER reaches FAR: one function beside the two.
        assert "(1 function reachable)" in violation.message

    def test_a_function_reachable_through_one_with_no_row_holds(self) -> None:
        index = _index(
            [
                _row(MAIN, imports=["CreateMutexW"], callees=[HELPER]),
                _row(FAR, imports=["WriteFile"], callers=[HELPER]),
            ],
            others={HELPER: [FAR]},
        )
        assert not _check(f"{MAIN_VA} writes the file with WriteFile.", index=index).violations

    def test_with_no_callees_listed_for_functions_without_rows_api_names_are_not_checked(
        self,
    ) -> None:
        index = _index(
            [
                _row(MAIN, imports=["CreateMutexW"], callees=[HELPER]),
                _row(FAR, imports=["WriteFile"]),
            ],
            others=None,
        )
        found = _check(f"{MAIN_VA} sleeps with SleepEx.", index=index)
        assert found.violations == []
        assert found.not_checked == [
            f"claim 1: {fc.CALLEES_UNKNOWN.format(entry=INDEX_ID, address=MAIN_VA)}"
        ]

    def test_a_name_the_hash_resolution_places_inside_the_function_holds(self) -> None:
        hashes = LedgerEntry(
            id="ev_0003",
            agent="pipeline",
            tool="resolve_api_hashes",
            output="{}",
            structured={
                "image_base": hex(BASE),
                "hits": [
                    {
                        "readings": [{"name": "VirtualAlloc", "set": "exports"}],
                        "occurrences": [{"function": hex(MAIN), "rva": hex(MAIN + 0x10)}],
                    }
                ],
            },
        )
        assert not _check(f"{MAIN_VA} allocates with VirtualAlloc.", pack=[hashes]).violations

    def test_a_string_the_blob_decoder_places_inside_the_function_holds(self) -> None:
        blobs = LedgerEntry(
            id="ev_0004",
            agent="pipeline",
            tool="decode_string_blobs",
            output="{}",
            structured={
                "results": [{"text": "settings.ini path", "references": [{"function": hex(MAIN)}]}]
            },
        )
        assert not _check(f'{MAIN_VA} opens "settings.ini path".', pack=[blobs]).violations

    def test_a_value_another_cited_entry_holds_is_still_asked(self) -> None:
        listing = LedgerEntry(
            id="ev_0005",
            agent="pipeline",
            tool="resolve_api_hashes",
            output='{"hits": [{"readings": [{"name": "VirtualAlloc"}]}]}',
        )
        found = _check(
            f"{MAIN_VA} allocates its buffer with VirtualAlloc.",
            pack=[listing],
            evidence=f"[{LISTING_ID}], [ev_0005]",
        )
        (violation,) = found.violations
        assert '"VirtualAlloc"' in violation.message

    def test_citing_the_index_itself_excuses_nothing(self) -> None:
        found = _check(f"{MAIN_VA} injects with CreateRemoteThread [{INDEX_ID}].")
        assert len(found.violations) == 1

    def test_a_value_given_to_a_function_no_callee_edge_reaches_is_recorded(self) -> None:
        found = _check(
            f'{MAIN_VA} hands over to 0x{BASE + OTHER:x}, which reads "settings.ini path".'
        )
        assert found.violations == []
        assert found.not_checked == [
            "claim 1: "
            + fc.GIVEN_ELSEWHERE.format(value="settings.ini path", address=hex(BASE + OTHER))
        ]

    def test_a_value_given_to_a_function_the_cited_one_reaches_is_checked(self) -> None:
        held = _check(f"{MAIN_VA} hands over to 0x{BASE + FAR:x}, which calls WriteFile.")
        assert held.violations == [] and held.not_checked == []
        asked = _check(f"{MAIN_VA} hands over to 0x{BASE + FAR:x}, which calls SleepEx.")
        assert len(asked.violations) == 1

    def test_a_value_in_a_sentence_that_names_no_cited_function_is_recorded(self) -> None:
        found = _check(f"{MAIN_VA} creates the guard. The sample also resolves SleepEx.")
        assert found.violations == []
        assert found.not_checked == [
            "claim 1: " + fc.UNATTRIBUTED.format(value="SleepEx", where=fc.NO_NAME_IN_ITS_SENTENCE)
        ]

    def test_a_value_before_every_function_its_sentence_names_is_recorded(self) -> None:
        found = _check(f"CreateRemoteThread is called by {MAIN_VA} to inject.")
        assert found.violations == []
        assert found.not_checked == [
            "claim 1: "
            + fc.UNATTRIBUTED.format(value="CreateRemoteThread", where=fc.BEFORE_ANY_NAME)
        ]

    def test_a_pronoun_s_sentence_after_another_function_is_no_cited_function_s(self) -> None:
        index = _index([*ROWS[:3], _row(OTHER, imports=["InternetOpenW"])])
        found = _check(
            f'0x{BASE + OTHER:x} is the reader passed to CreateThread. It opens "a stack text".',
            index=index,
        )
        assert found.asked == 0
        assert any("is given to no function the claim names" in n for n in found.not_checked)

    def test_an_abbreviation_s_dot_ends_no_sentence(self) -> None:
        index = _index([*ROWS[:3], _row(OTHER, decoded=["settings.ini path"])])
        found = _check(
            f'0x{BASE + OTHER:x} reads its settings, e.g. it opens "settings.ini path".',
            index=index,
        )
        assert found.asked == 0
        assert found.not_checked == [
            "claim 1: "
            + fc.GIVEN_ELSEWHERE.format(value="settings.ini path", address=hex(BASE + OTHER))
        ]

    def test_a_slash_list_s_items_are_read_exactly_as_written(self) -> None:
        apis, _strings = named_values("It calls NtCreateFile/WriteFile in turn.")
        assert apis == ["NtCreateFile", "WriteFile"]
        apis, _strings = named_values("It calls InternetOpenW/ConnectA in turn.")
        assert apis == ["InternetOpenW"]

    def test_a_slash_list_s_names_held_as_written_ask_nothing(self) -> None:
        index = _index(
            [_row(MAIN, imports=["NtCreateFile", "WriteFile"], callees=[HELPER]), *ROWS[1:3]]
        )
        found = _check(f"{MAIN_VA} fills the file with NtCreateFile/WriteFile.", index=index)
        assert found.violations == []

    def test_a_name_repeated_many_times_reads_in_well_under_a_second(self) -> None:
        import time

        body = " ".join(f"{MAIN_VA} calls CreateMutexW;" for _ in range(2_000))
        began = time.perf_counter()
        named_values(body)
        assert time.perf_counter() - began < 1.0

    def test_a_name_inside_a_statement_of_absence_is_no_claimed_call(self) -> None:
        held = _check(f"{MAIN_VA} does not use CreateRemoteThread; it guards with CreateMutexW.")
        assert held.violations == []
        asked = _check(f"{MAIN_VA} does not use CreateRemoteThread; it waits with SleepEx.")
        (violation,) = asked.violations
        assert (
            '"SleepEx"' in violation.message
            and "CreateRemoteThread" not in (violation.message.split("names", 1)[1])
        )

    def test_a_name_a_noun_negation_s_list_names_far_back_in_its_clause_is_no_claimed_call(
        self,
    ) -> None:
        found = _check(f"{MAIN_VA} shows no evidence of process injection, such as VirtualAllocEx.")
        assert found.violations == [] and found.checked == 1

    def test_a_quoted_value_said_to_be_absent_or_missing_is_no_claimed_string(self) -> None:
        for sentence in (
            f'In {MAIN_VA} "settings.ini path" is absent, and it calls CreateMutexW.',
            f'{MAIN_VA} calls CreateMutexW; "settings.ini path" is absent.',
            f'{MAIN_VA} calls CreateMutexW; "settings.ini path" is missing from it.',
        ):
            found = _check(sentence)
            assert found.violations == [] and found.checked == 1, sentence

    def test_a_negation_in_an_earlier_clause_does_not_reach_a_later_one(self) -> None:
        found = _check(f"{MAIN_VA} shows no evidence of process injection: it calls SleepEx.")
        (violation,) = found.violations
        assert '"SleepEx"' in violation.message

    def test_a_quoted_phrase_no_strings_source_holds_is_recorded_not_asked(self) -> None:
        capa = LedgerEntry(id="ev_0006", agent="pipeline", tool="capa", output="PEB access")
        found = _check(f'{MAIN_VA} matches "PEB access" at its start.', pack=[capa])
        assert found.violations == []
        assert found.not_checked == [
            f"claim 1: {fc.NOT_A_SAMPLE_STRING.format(value='PEB access')}"
        ]

    def test_a_string_a_strings_tool_holds_is_read(self) -> None:
        floss = LedgerEntry(id="ev_0006", agent="pipeline", tool="floss", output='"a stack text"')
        found = _check(f'{MAIN_VA} builds "a stack text" on its stack.', pack=[floss])
        (violation,) = found.violations
        assert '"a stack text"' in violation.message

    def test_a_string_the_run_holds_nowhere_is_not_asked(self) -> None:
        assert not _check(f'{MAIN_VA} is "the update routine" of the loader.').violations

    def test_a_string_the_run_holds_for_another_function_is_asked(self) -> None:
        found = _check(f'{MAIN_VA} opens "settings.ini path".')
        (violation,) = found.violations
        assert '"settings.ini path"' in violation.message


class TestCallsThroughFilledSlots:
    """A function whose calls go through slots the hash resolution fills is checkable."""

    @staticmethod
    def _index() -> LedgerEntry:
        main = _row(MAIN, callees=[HELPER])
        main["slot_calls"] = [
            {
                "name": "CreateMutexW",
                "sources": ["ev_0003"],
                "slot": hex(BASE + 0x9000),
                "named_at": hex(BASE + 0x2000),
            }
        ]
        return _index([main, *ROWS[1:]])

    def test_a_call_through_a_named_slot_holds(self) -> None:
        found = _check(f"{MAIN_VA} creates the guard with CreateMutexW.", index=self._index())
        assert found.violations == [] and found.not_checked == [] and found.checked == 1

    def test_a_name_no_slot_call_holds_is_asked(self) -> None:
        found = _check(f"{MAIN_VA} waits with SleepEx.", index=self._index())
        (violation,) = found.violations
        assert 'calls through slots the hash resolution fills "CreateMutexW"' in violation.message


class TestWhatASentenceNames:
    def test_a_word_of_running_text_is_no_api(self) -> None:
        apis, _strings = named_values("The routine will connect and send the data.")
        assert apis == []

    def test_a_name_in_a_code_span_or_with_a_capital_inside_is(self) -> None:
        apis, _strings = named_values("It calls `send` and then CreateMutexW and CreateProcess.")
        assert apis == ["send", "CreateMutexW", "CreateProcess"]

    def test_a_name_inside_a_span_s_expression_is_no_api(self) -> None:
        apis, _strings = named_values("It waits `(rand%150+450)s` and calls `send()`.")
        assert apis == ["send"]

    def test_quoted_strings_and_code_spans_holding_quotes_are_strings(self) -> None:
        _apis, strings = named_values(
            'It splits on `"\\r\\n"`, compares "update-channel" and `"/files/"`, and `x+0x88`.'
        )
        assert strings == ["update-channel", "/files/"]


class TestWhenTheFactIsAbsent:
    def test_no_index_states_nothing_and_says_why(self) -> None:
        pack = [LedgerEntry(id="ev_0003", agent="pipeline", tool="capa", output="{}")]
        own = [_listing()]
        facts = function_facts(own, function_artefacts(pack), pack_entries=pack, bases=(BASE,))
        claims = [
            ClaimEvidence(
                claim=f"{MAIN_VA} calls SleepEx.", evidence_ref=f"[{LISTING_ID}]", confidence=0.8
            )
        ]
        found = check_function_claims(
            SimpleNamespace(claims=claims), listed_functions(own), facts, (BASE,)
        )
        assert found.violations == []
        assert found.not_checked == [f"claim 1: {fc.NO_INDEX}"]

    def test_an_index_the_byte_budget_blanked_is_absent(self) -> None:
        blanked = LedgerEntry(
            id=INDEX_ID, agent="pipeline", tool="function_index", output="", truncated=True
        )
        found = _check(f"{MAIN_VA} calls SleepEx.", index=blanked)
        assert found.violations == []
        assert found.not_checked == [f"claim 1: {INDEX_NOT_KEPT.format(entry=INDEX_ID)}"]

    def test_a_function_the_index_does_not_know(self) -> None:
        # Neither a row nor any row's caller or callee: the index never met it.
        index = _index([_row(OTHER, decoded=["settings.ini path"])])
        found = _check(f"{MAIN_VA} calls SleepEx.", index=index)
        assert found.violations == []
        assert found.not_checked == [f"claim 1: {fc.NOT_KNOWN.format(address=hex(BASE + MAIN))}"]

    def test_a_row_the_pack_shown_to_the_analyst_left_out(self) -> None:
        index = _index(ROWS)
        shown = "\n".join(row_line(r, INDEX_ID) for r in ROWS if r["offset"] != hex(MAIN))
        found = _check(f"{MAIN_VA} calls SleepEx.", index=index, block=shown)
        assert found.violations == []
        assert found.not_checked == [f"claim 1: {fc.ROW_NOT_SHOWN.format(address=MAIN_VA)}"]
        everything = "\n".join(row_line(r, INDEX_ID) for r in ROWS)
        assert _check(f"{MAIN_VA} calls SleepEx.", index=index, block=everything).violations

    def test_a_function_the_decoder_stopped_in(self) -> None:
        found = _check(f"{MAIN_VA} calls SleepEx.", index=_index(ROWS, undecoded=[HELPER]))
        assert found.violations == []
        assert found.not_checked == [f"claim 1: {fc.UNDECODED.format(address=MAIN_VA)}"]

    def test_calls_that_name_nothing_leave_api_names_unasked_and_strings_asked(self) -> None:
        index = _index(ROWS, unnamed={HELPER: 1})
        found = _check(f'{MAIN_VA} calls SleepEx and opens "settings.ini path".', index=index)
        (violation,) = found.violations
        assert '"SleepEx"' not in violation.message
        assert '"settings.ini path"' in violation.message
        assert found.not_checked == [f"claim 1: {fc.UNNAMED_CALLS.format(address=MAIN_VA)}"]

    def test_a_name_the_facts_hold_is_held_whatever_else_is_called(self) -> None:
        index = _index(ROWS, unnamed={HELPER: 1})
        found = _check(f"{MAIN_VA} creates the guard with CreateMutexW.", index=index)
        assert found.violations == [] and found.not_checked == []

    def test_an_index_that_counts_no_unnamed_calls_leaves_api_names_unasked(self) -> None:
        found = _check(f"{MAIN_VA} calls SleepEx.", index=_index(ROWS, unnamed=False))
        assert found.violations == []
        assert found.not_checked == [f"claim 1: {fc.UNNAMED_UNKNOWN.format(entry=INDEX_ID)}"]

    def test_a_listing_the_model_never_read_makes_no_function_claim(self) -> None:
        unread = LedgerEntry(
            id=LISTING_ID,
            agent="reverser",
            tool="decompile_function",
            args={"address": f"{BASE + MAIN:x}"},
            output=not_shown_record(4096),
            truncated=True,
        )
        found = _check(f"{MAIN_VA} calls SleepEx.", own=[unread])
        assert found.violations == [] and found.checked == 0

    def test_a_claim_citing_no_listing_is_not_a_function_claim(self) -> None:
        found = _check("The sample calls SleepEx.", evidence="[ev_0003]")
        assert found.violations == [] and found.checked == 0 and found.not_checked == []


class TestTheRecord:
    def test_the_record_counts_and_says_why(self) -> None:
        found = _check(f"{MAIN_VA} calls SleepEx.", index=_index(ROWS, undecoded=[MAIN]))
        assert found.record() == {
            "checked": 0,
            "asked": 0,
            "not_checked": [f"claim 1: {fc.UNDECODED.format(address=MAIN_VA)}"],
        }
