"""An API the sandbox saw called reaches the section of its category.

The encryption, discovery and evasion sections counted only the import
profile's APIs. A sample importing no crypto API whose sandbox report holds
``CryptAcquireContextW`` calls was skipped as evidence-empty. The sandbox's
API reading (declared kind ``sandbox_api_calls``) is now counted by what an
API catalogue answer of the run (declared kind ``api_catalogue``) says of each
called name, and shown beside the import count. A name no catalogue answer
covers is not counted; a zero count is not shown and asks nothing.
"""

from __future__ import annotations

import time
from typing import Any

from maljan.reporting.evidence_bundles import bundle_for, is_empty
from maljan.reporting.ledger_projection import dynamic_from_ledger
from maljan.reporting.models import DynamicBehavior, FileHashes, MalwareReport, SampleIdentity
from maljan.schemas.evidence import LedgerEntry


def _entry(n: int, tool: str, kind: str, structured: dict[str, Any]) -> LedgerEntry:
    return LedgerEntry(
        id=f"ev_{n:04d}",
        agent="dynamic",
        tool=tool,
        source="mcp:somewhere",
        facts={"v": 1, "kind": kind},
        structured=structured,
        output="{}",
    )


CALLED = _entry(
    1,
    "api_reading",
    "sandbox_api_calls",
    {"apis": [{"api": "CryptAcquireContextW"}, {"api": "HttpSendRequestW"}]},
)


def _catalogue(n: int, rows: list[tuple[str, str | None]]) -> LedgerEntry:
    return _entry(
        n,
        "lookup",
        "api_catalogue",
        {"capabilities": [{"api": api, "category": cat} for api, cat in rows]},
    )


def test_the_categories_of_the_called_apis_are_counted_once_per_name() -> None:
    catalogue = _catalogue(
        2,
        [("CryptAcquireContextA", "crypto"), ("HttpSendRequestW", "network"), ("Sleep", None)],
    )
    again = _catalogue(3, [("CryptAcquireContextW", "crypto")])
    dynamic = dynamic_from_ledger([CALLED, catalogue, again])
    assert dynamic is not None
    # The A/W spellings are one name; a name asked but never called is not counted.
    assert dynamic.api_capabilities == {"crypto": 1, "network": 1}


def test_a_called_name_no_answer_covers_is_not_counted() -> None:
    dynamic = dynamic_from_ledger([CALLED, _catalogue(2, [("Sleep", "execution")])])
    assert dynamic is not None and dynamic.api_capabilities == {}


def _report(called: dict[str, int], static: bool = False) -> MalwareReport:
    from maljan.reporting.models import StaticAnalysis

    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        dynamic=DynamicBehavior(api_capabilities=called),
        static=StaticAnalysis() if static else None,
    )


def test_a_sandbox_only_crypto_call_asks_the_encryption_section() -> None:
    for static in (False, True):
        bundle = bundle_for("encryption_scheme", _report({"crypto": 1}, static))
        assert bundle["facts"]["sandbox_called_crypto_api_count"] == 1
        assert not is_empty(bundle)
    evasion = bundle_for("evasion_antiforensics", _report({"evasion": 2}, True))["facts"]
    assert evasion["sandbox_called_evasion_api_count"] == 2
    assert "sandbox_called_anti_debug_api_count" not in evasion


def test_no_called_category_asks_nothing() -> None:
    assert is_empty(bundle_for("encryption_scheme", _report({})))
    assert is_empty(bundle_for("encryption_scheme", _report({"network": 3})))
    assert bundle_for("packing_obfuscation", _report({"crypto": 1}))["facts"] == {}


def test_counting_stays_linear() -> None:
    def took(size: int) -> float:
        rows = [{"api": f"Api{n}"} for n in range(size)]
        called = _entry(1, "api_reading", "sandbox_api_calls", {"apis": rows})
        catalogue = _catalogue(2, [(f"Api{n}", f"cat{n % 7}") for n in range(size)])
        start = time.perf_counter()
        dynamic_from_ledger([called, catalogue])
        return time.perf_counter() - start

    small, large = took(1_000), took(10_000)
    assert large < small * 30, (small, large)


# The label the pack's line gives the catalogue asked about the sandbox's calls.
CALLED_LABEL = "sandbox-called api catalogue"


def _kind(entry: Any) -> str:
    return str((entry.facts or {}).get("kind") or "")


def test_the_pack_asks_the_catalogue_about_the_sandbox_s_calls(tmp_path: Any) -> None:
    from maljan.reporting.ledger_projection import static_from_ledger
    from tests.unit.pipeline.test_triage_pack import SANDBOX_REPORT, _pack, _pe, _write

    behaviour = {
        **SANDBOX_REPORT["behavior"],
        "apistats": {"4": {"CryptAcquireContextW": 2, "HttpSendRequestW": 9}},
    }
    report = {**SANDBOX_REPORT, "behavior": behaviour}
    result = _pack(_write(tmp_path, "s.exe", _pe()), "pe", sandbox_report=report)
    (asked,) = [e for e in result.entries if _kind(e) == "called_api_catalogue"]
    assert asked.tool == "api_capability" and asked.ok
    assert asked.args == {
        "api_names": ["HttpSendRequestW", "CryptAcquireContextW"],
        "platform": "windows",
    }
    # After it only the directed-text pass and the behaviour links, the pack's last steps.
    assert result.entries[-3] is asked
    assert [e.tool for e in result.entries[-2:]] == ["find_directed_text", "behaviour_code_links"]
    # Its line says these are the sandbox's recorded calls; an import
    # catalogue line keeps its own name.
    from maljan.pipeline.triage_pack import render_pack

    lines = render_pack(result.entries, 1_000_000).splitlines()
    (line,) = [x for x in lines if x.startswith(f"[{asked.id}] ")]
    assert line.startswith(f"[{asked.id}] {CALLED_LABEL}: API catalogue associations")
    for other in result.entries:
        if other.tool == "api_capability" and other is not asked:
            (own,) = [x for x in lines if x.startswith(f"[{other.id}] ")]
            assert own.startswith(f"[{other.id}] api catalogue: ")
    dynamic = dynamic_from_ledger(result.entries)
    assert dynamic is not None and dynamic.api_capabilities.get("crypto") == 1
    # The import profile never reads the calls' catalogue answer.
    static = static_from_ledger(result.entries)
    assert static is None or "crypto" not in static.api_capabilities
    # No API calls in the report: nothing is asked.
    plain = _pack(_write(tmp_path, "t.exe", _pe()), "pe", sandbox_report=SANDBOX_REPORT)
    assert not [e for e in plain.entries if _kind(e) == "called_api_catalogue"]
