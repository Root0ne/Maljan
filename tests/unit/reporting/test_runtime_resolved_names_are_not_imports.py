"""A function name the run resolved at runtime from a stored value is not an import.

One run's static analyst passed the names ``resolve_api_hashes`` had resolved
(``CreateRemoteThread``, ``QueueUserAPC``, ``VirtualAllocEx``,
``WriteProcessMemory``) to the capability lookup. The report printed the rule
that fired on them as "imports ``CreateRemoteThread`` …" beside a five-name
import table that held none of them, and published Process Injection
"corroborated" although every analyst statement naming it said the functions
were resolved and never invoked.

Now the names are told apart wherever they are printed: the lookup can be
told which names were resolved, the report's projection reads the ledger's
own resolutions, a rule that matched only such names says so, and a
technique every analyst statement says is never called is not stated as
corroborated.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from maljan.extractors.capability_matrix import build_capability_matrix, says_never_called
from maljan.reporting.ledger_projection import static_from_ledger
from maljan.reporting.renderers.markdown import _rule_words
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import NEVER_CALLED_TECHNIQUE_MARKER
from maljan.tools import knowledge

INJECTION = ["CreateRemoteThread", "QueueUserAPC", "VirtualAllocEx", "WriteProcessMemory"]
IMPORTS = ["PeekNamedPipe", "GetLastError", "CreateMutexW", "MessageBeep", "MessageBoxA"]


def _entry(entry_id: str, tool: str, structured: dict[str, Any]) -> LedgerEntry:
    return LedgerEntry(id=entry_id, agent="static", tool=tool, structured=structured)


def _ledger(capability: dict[str, Any]) -> list[LedgerEntry]:
    return [
        _entry(
            "ev_0001",
            "pe_info",
            {"imports": [{"dll": "KERNEL32.dll", "function": name} for name in IMPORTS]},
        ),
        _entry(
            "ev_0002",
            "resolve_api_hashes",
            {
                "hits": [
                    {
                        "value": f"0x{index:08x}",
                        "readings": [
                            {"algorithm": "crc32", "set": "exports", "name": name, "dlls": ["k"]}
                        ],
                    }
                    for index, name in enumerate(INJECTION, start=1)
                ]
            },
        ),
        _entry("ev_0003", "api_capability", capability),
    ]


def _injection_hit(static: Any) -> dict[str, Any]:
    (hit,) = [
        h
        for h in static.api_technique_hits
        if h.get("source") == "api_capability" and h.get("technique_id") == "T1055"
    ]
    return hit


class TestTheReportTellsTheNamesApart:
    def test_names_the_ledger_resolved_are_not_counted_as_imports(self) -> None:
        # Passed as plain names, the way the run's analyst passed them.
        static = static_from_ledger(_ledger(knowledge.api_capability(INJECTION)))

        assert static is not None
        hit = _injection_hit(static)
        assert hit["resolved_apis"] == hit["matched_apis"]
        assert static.api_capabilities == {}
        assert static.api_capabilities_resolved
        assert static.api_capabilities_resolved_evidence_ids == ["ev_0003"]

    def test_the_rule_row_says_it_matched_only_resolved_names(self) -> None:
        static = static_from_ledger(_ledger(knowledge.api_capability(INJECTION)))

        words = _rule_words(_injection_hit(static))

        assert "matched only names resolved at runtime from hashes, no import" in words
        assert "imports `" not in words

    def test_a_name_the_import_table_holds_stays_an_import(self) -> None:
        answer = knowledge.api_capability(["CreateMutexW", "MessageBoxA"])
        static = static_from_ledger(_ledger(answer))

        assert static is not None
        assert static.api_capabilities_resolved == {}
        assert all("resolved_apis" not in h for h in static.api_technique_hits)

    def test_the_lookup_says_which_names_it_was_told_were_resolved(self) -> None:
        answer = knowledge.api_capability(["CreateMutexW"], resolved_names=INJECTION)

        assert answer["resolved_at_runtime_from_hashes"] == INJECTION
        obtained = {row["api"]: row.get("obtained") for row in answer["capabilities"]}
        assert obtained["CreateMutexW"] is None
        assert {obtained[name] for name in INJECTION} == {knowledge.RESOLVED_AT_RUNTIME}
        # Without the ledger's own resolutions, the answer's word decides.
        static = static_from_ledger([_entry("ev_0009", "api_capability", answer)])
        assert static is not None
        assert _injection_hit(static)["resolved_apis"] == _injection_hit(static)["matched_apis"]


def _judge_bundle(technique: str) -> dict[str, Any]:
    return {
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--00000000-0000-4000-8000-000000000001",
                "name": "Process Injection",
                "external_references": [{"source_name": "mitre-attack", "external_id": technique}],
            }
        ]
    }


def _finding_isr(agent: str, domain: str, title: str) -> Any:
    finding = SimpleNamespace(technique_ids=["T1055"], confidence=0.85, title=title)
    return SimpleNamespace(agent_id=agent, domain=domain, claims=[], findings=[finding])


class TestATechniqueTheAnalystsSayIsNeverCalledIsNotCorroborated:
    def test_the_injection_case(self) -> None:
        isrs = {
            "static": _finding_isr(
                "static", "static", "Injection primitives resolved but never invoked"
            ),
            "dynamic": _finding_isr(
                "dynamic", "dynamic", "Process-injection primitives resolved but never invoked"
            ),
        }

        cells, mappings = build_capability_matrix(
            stix_output=_judge_bundle("T1055"), isr_reports=isrs
        )

        (mapping,) = [m for m in mappings if m.technique_id == "T1055"]
        (cell,) = [c for c in cells if c.technique_id == "T1055"]
        assert mapping.is_corroborated is False
        assert NEVER_CALLED_TECHNIQUE_MARKER in cell.note

    def test_two_analysts_that_say_the_sample_does_it_still_corroborate_it(self) -> None:
        isrs = {
            "static": _finding_isr("static", "static", "Writes into a remote process"),
            "dynamic": _finding_isr("dynamic", "dynamic", "Remote thread started in a child"),
        }

        _cells, mappings = build_capability_matrix(
            stix_output=_judge_bundle("T1055"), isr_reports=isrs
        )

        (mapping,) = [m for m in mappings if m.technique_id == "T1055"]
        assert mapping.is_corroborated is True

    def test_the_reading(self) -> None:
        assert says_never_called("resolved but never invoked")
        assert says_never_called("the slots have zero call cross-references")
        assert says_never_called("OpenProcess is not called")
        assert not says_never_called("WriteProcessMemory is called at 0x4010")
