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
own resolutions, and a rule that matched only such names says so and is not
counted as corroboration, with each analyst statement naming the technique
printed verbatim beside it for the reader to weigh; the platform reads none of
those statements.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from maljan.extractors.capability_matrix import build_capability_matrix
from maljan.reporting.ledger_projection import static_from_ledger
from maljan.reporting.renderers.markdown import _rule_words
from maljan.schemas.evidence import LedgerEntry
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


# Statements an analyst may write about one technique, some saying the sample
# does it: the platform reads none of them, it prints them.
STATEMENTS = [
    "WriteProcessMemory is not called directly; it is invoked through the resolved slot",
    "CreateRemoteThread is not used, but NtCreateThreadEx is",
    "has no call sites other than the command dispatcher, which runs it for one id",
    "VirtualAllocEx is never invoked with a remote handle; the local path injects code",
]


def _report_with(hit: dict[str, Any], isrs: dict[str, Any]) -> Any:
    from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity, StaticAnalysis

    cells, mappings = build_capability_matrix(stix_output=_judge_bundle("T1055"), isr_reports=isrs)
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        static=StaticAnalysis(api_technique_hits=[hit]),
        capability_matrix=cells,
        ttp_mappings=mappings,
    )


_RESOLVED_ONLY_HIT = {
    "technique_id": "T1055",
    "name": "Process Injection",
    "rule": "writes into another process",
    "source": "api_capability",
    "evidence_id": "ev_0003",
    "matched_apis": INJECTION,
    "resolved_apis": INJECTION,
}


class TestARuleMatchOnRuntimeNamesIsStatedAndNotCounted:
    def test_the_source_says_the_match_is_on_runtime_names_and_not_corroboration(self) -> None:
        from maljan.reporting.renderers.markdown import (
            RESOLVED_ONLY_RULE_LABEL,
            MarkdownRenderer,
        )

        isrs = {"static": _finding_isr("static", "static", STATEMENTS[0])}
        markdown = MarkdownRenderer().render(_report_with(_RESOLVED_ONLY_HIT, isrs))

        assert f"api_capability ({RESOLVED_ONLY_RULE_LABEL})" in markdown

    def test_the_analysts_statements_are_printed_verbatim_not_classified(self) -> None:
        from maljan.reporting.renderers.markdown import MarkdownRenderer

        isrs = {
            f"a{index}": _finding_isr(f"a{index}", "static" if index % 2 else "dynamic", text)
            for index, text in enumerate(STATEMENTS)
        }
        report = _report_with(_RESOLVED_ONLY_HIT, isrs)
        markdown = MarkdownRenderer().render(report)

        (mapping,) = [m for m in report.ttp_mappings if m.technique_id == "T1055"]
        # Two analyst layers named it: corroborated, whatever their words say.
        assert mapping.is_corroborated is True
        assert (
            "published, corroborated (named by 2 analyst layers; their statements are listed "
            "below the table)"
        ) in markdown
        assert "Techniques a rule matched only on names resolved at runtime" in markdown
        for text in STATEMENTS:
            assert text in markdown
        assert "never called" not in (report.capability_matrix[0].note or "")

    def test_a_rule_that_matched_an_import_is_a_plain_rule_match(self) -> None:
        from maljan.reporting.renderers.markdown import MarkdownRenderer

        hit = {**_RESOLVED_ONLY_HIT, "resolved_apis": INJECTION[:2]}
        isrs = {"static": _finding_isr("static", "static", STATEMENTS[0])}
        markdown = MarkdownRenderer().render(_report_with(hit, isrs))

        assert "api_capability (rule match)" in markdown
        assert "Techniques a rule matched only on names resolved at runtime" not in markdown
