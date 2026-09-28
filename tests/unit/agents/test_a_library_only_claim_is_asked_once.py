"""Claims that say only that a library or its APIs are used are found, and asked about once.

A reverser's answer carried 36 claims of one line each, "uses `x.dll` APIs
for y", every one citing only the hash-resolution listing. Such a claim states
no code location, no behaviour of the sample and no evidence beyond an import
listing. The validation finds them and asks the analyst once to merge them
into the claims they support or to detail each; what it answers stands, a
merge that folds them away included.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage

from maljan.agents.base_agent import BaseAnalyst
from maljan.pipeline.validation import (
    LIBRARY_ONLY_CLAIMS_CODE,
    library_only_claims,
    library_only_claims_violation,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


def _isr(*claims: tuple[str, str]) -> AgentISR:
    return AgentISR(
        agent_id="reverser",
        domain="static",
        claims=[ClaimEvidence(claim=c, evidence_ref=e, confidence=0.9) for c, e in claims],
    )


def _found(claim: str, evidence: str = "[ev_0020]") -> bool:
    return library_only_claims(_isr((claim, evidence))) == [0]


class TestWhatIsALibraryOnlyClaim:
    def test_a_library_and_a_purpose(self) -> None:
        assert _found("The sample uses `kernel32.dll` APIs for synchronization and mutex creation.")

    def test_two_libraries_and_no_purpose(self) -> None:
        assert _found("The sample uses `kernel32.dll` and `user32.dll` APIs.")

    def test_a_named_api_family_with_no_subject(self) -> None:
        assert _found("Uses WinINet APIs for network communication.")

    def test_a_library_with_no_api_word(self) -> None:
        assert _found("The binary imports shlwapi.dll for registry operations.")

    def test_evidence_that_restates_an_import_listing(self) -> None:
        assert _found(
            "The sample uses kernel32.dll APIs for mutex creation.",
            "[ev_0020] (Resolved APIs: kernel32.dll!CreateMutexW, GetLastError)",
        )


class TestWhatIsNot:
    def test_a_behaviour_with_an_api_named_in_it(self) -> None:
        assert not _found("The sample downloads additional payloads using URLDownloadToFileW.")

    def test_a_code_location(self) -> None:
        assert not _found("The sample uses kernel32.dll APIs at 0x140001200 to create a mutex.")

    def test_a_code_location_in_the_evidence(self) -> None:
        assert not _found(
            "The sample uses kernel32.dll APIs for mutex creation.",
            "[ev_0031] decompile of FUN_140001200",
        )

    def test_evidence_that_quotes_a_string(self) -> None:
        assert not _found(
            "The sample uses kernel32.dll APIs for mutex creation.",
            '[ev_0019] (String: "Global\\m-example")',
        )

    def test_evidence_from_another_reading(self) -> None:
        assert not _found(
            "The sample uses kernel32.dll APIs for process injection.",
            "[ev_0008] (Capa: allocate memory in another process)",
        )

    def test_a_technique_of_its_own(self) -> None:
        assert not _found("The sample uses CRC32 API hashing to resolve Windows API functions.")

    def test_a_second_sentence_that_says_more(self) -> None:
        assert not _found(
            "The sample uses kernel32.dll APIs. It exits when the mutex already exists."
        )


class TestTheQuestion:
    def test_it_quotes_every_such_claim_and_asks_once_to_merge_or_detail(self) -> None:
        isr = _isr(
            ("The sample uses `kernel32.dll` APIs for pipe operations.", "[ev_0020]"),
            ("The sample writes a scheduled task at logon.", "[ev_0066]"),
            ("The sample uses `user32.dll` APIs for message box display.", "[ev_0020]"),
        )

        violation = library_only_claims_violation(isr)

        assert violation is not None
        assert violation.code == LIBRARY_ONLY_CLAIMS_CODE
        assert violation.message.startswith("2 CLAIM block(s) say only that a library")
        assert "pipe operations" in violation.message
        assert "message box display" in violation.message
        assert "scheduled task" not in violation.message
        assert "Merge them into the claims" in violation.message
        assert "What you answer stands" in violation.message
        assert "?" not in violation.message

    def test_none_is_no_question(self) -> None:
        assert library_only_claims_violation(_isr(("The sample exits.", "[ev_0001]"))) is None


def _block(sentence: str, evidence: str = "[ev_0020]") -> str:
    return f"CLAIM: {sentence}\nEVIDENCE: {evidence}\nCONFIDENCE: 0.9\nTECHNIQUE: NONE\n---\n"


BEHAVIOUR = _block("The sample exits when the mutex already exists.", "[ev_0066]")
LIBRARIES = "".join(
    _block(f"The sample uses `kernel32.dll` APIs for {purpose}.")
    for purpose in ("mutex creation", "pipe operations", "handle closing")
)
MERGED = _block(
    "The sample exits when the mutex already exists, after CreateMutexW and GetLastError.",
    "[ev_0066], [ev_0020]",
)


class _Analyst(BaseAnalyst):
    def __init__(self, replies: list[str]) -> None:
        super().__init__(llm=MagicMock(), name="reverser")
        self.pack_ledger_ids = ["ev_0020", "ev_0066"]
        self._replies = list(replies)
        self.seen_turns: list[list[Any]] = []

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def _invoke_llm_with_timeout(self, messages: list, timeout: float, **_: Any) -> str:
        self.seen_turns.append(list(messages))
        text = self._replies.pop(0)
        self._record_usage(AIMessage(content=text))
        return text


def _check(analyst: _Analyst, first: str = BEHAVIOUR + LIBRARIES) -> AgentISR:
    isr = analyst._text_to_isr(first, 0)
    with (
        patch("maljan.agents.base_agent.validity_check_available", return_value=True),
        patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
    ):
        return analyst._validate_isr(isr, "evidence")


class TestTheValidationTurn:
    def test_a_merge_that_folds_them_away_stands(self) -> None:
        analyst = _Analyst([MERGED])

        result = _check(analyst)

        (turns,) = analyst.seen_turns
        assert LIBRARY_ONLY_CLAIMS_CODE in str(turns[-1].content)
        assert [c.claim for c in result.claims] == [
            "The sample exits when the mutex already exists, after CreateMutexW and GetLastError."
        ]
        assert LIBRARY_ONLY_CLAIMS_CODE not in [v.code for v in analyst.validation_findings]

    def test_an_answer_that_keeps_them_stands_and_the_finding_is_recorded(self) -> None:
        analyst = _Analyst([BEHAVIOUR + LIBRARIES])

        result = _check(analyst)

        assert len(result.claims) == 4
        assert LIBRARY_ONLY_CLAIMS_CODE in [v.code for v in analyst.validation_findings]

    def test_a_retry_that_loses_the_other_claims_too_keeps_the_first_answer(self) -> None:
        analyst = _Analyst([MERGED])

        result = _check(analyst, BEHAVIOUR + BEHAVIOUR.replace("mutex", "event") + LIBRARIES)

        assert len(result.claims) == 5

    def test_an_answer_with_none_is_not_asked(self) -> None:
        analyst = _Analyst([])

        _check(analyst, BEHAVIOUR)

        assert analyst.seen_turns == []
