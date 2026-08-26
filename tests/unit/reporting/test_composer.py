"""Phase 4: section-wise Report Composer.

Verifies each section is authored only from its isolated bundle, empty bundles
are skipped (never fabricated), per-section timeout is graceful, and structured
output maps onto the report.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import patch

import pytest

from maljan.reporting.composer import ReportComposer, _bundle_text, _has_content
from maljan.reporting.models import (
    EncryptionScheme,
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    SampleIdentity,
    StaticAnalysis,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


def _report(**over: object) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        **over,  # type: ignore[arg-type]
    )


class _StructuredStub:
    """Mimics ``llm.with_structured_output(schema)`` returning a fixed instance."""

    def __init__(self, schema: type, payload: dict[str, Any] | None) -> None:
        self._schema = schema
        self._payload = payload

    async def ainvoke(self, messages: Any) -> Any:
        if self._payload is None:
            raise RuntimeError("structured output unavailable")
        return self._schema.model_validate(self._payload)


class _FakeLLM:
    """Returns per-schema canned structured output; records which schemas ran."""

    def __init__(self, by_schema: dict[str, dict[str, Any]]) -> None:
        self.by_schema = by_schema
        self.seen: list[str] = []

    def with_structured_output(self, schema: type) -> _StructuredStub:
        self.seen.append(schema.__name__)
        return _StructuredStub(schema, self.by_schema.get(schema.__name__))

    async def ainvoke(self, messages: Any) -> Any:  # manual-parse fallback (unused here)
        raise RuntimeError("no fallback")


def _compose(
    report: MalwareReport, by_schema: dict[str, dict], isr: dict | None = None
) -> _FakeLLM:
    llm = _FakeLLM(by_schema)
    comp = ReportComposer(llm=llm, per_section_timeout=5)  # type: ignore[arg-type]
    # These tests exercise the structured-output path, which the composer now
    # asks about before taking (see ``structured_output_supported``). This
    # repo's own .env points at a local llama-server, where it does not work,
    # so without this the suite would silently test the manual-parse fallback
    # instead and ``_FakeLLM.ainvoke`` would raise.
    with patch("maljan.reporting.composer.structured_output_supported_for_llm", return_value=True):
        asyncio.run(comp.compose(report, isr))
    return llm


class TestComposer:
    def test_empty_report_authors_nothing_structured(self) -> None:
        # No static/network/evidence → every technical bundle is empty. Only the
        # executive-summary-style bundles (intro/conclusion) have facts.
        r = _report()
        _compose(r, by_schema={"_IntroOut": {"text": "A Windows malware sample."}})
        assert r.intro_background == "A Windows malware sample."
        # No crypto/CLI/ransom evidence → those stay unset.
        assert r.technical_analysis is None or r.technical_analysis.encryption_scheme is None

    def test_encryption_authored_from_crypto_bundle(self) -> None:
        r = _report(
            technical_evidence={
                "static": [
                    {
                        "tool_name": "detect_crypto_constants",
                        "symbol": "",
                        "output": "AES-256 sbox constant at 0x401000",
                    }
                ]
            }
        )
        _compose(
            r,
            by_schema={
                "EncryptionScheme": {"cipher": "AES-256", "mode": "CBC", "extension": ".locked"}
            },
        )
        assert r.technical_analysis is not None
        assert r.technical_analysis.encryption_scheme is not None
        assert r.technical_analysis.encryption_scheme.cipher == "AES-256"

    def test_prose_subsection_set_from_evidence(self) -> None:
        isr = {
            "static": AgentISR(
                agent_id="static",
                domain="static",
                claims=[
                    ClaimEvidence(
                        claim="Creates a Run key for persistence",
                        evidence_ref="string: SOFTWARE\\...\\Run",
                        confidence=0.7,
                    )
                ],
            )
        }
        r = _report()
        _compose(
            r,
            by_schema={
                "_ProseOut": {"body": "The sample installs a Run key.", "evidence_refs": ["Run"]}
            },
            isr=isr,
        )
        assert r.technical_analysis is not None
        assert r.technical_analysis.persistence_detail is not None
        assert "Run key" in r.technical_analysis.persistence_detail.body

    def test_communications_authored_from_network(self) -> None:
        r = _report(network=NetworkIOCs(domains=[NetworkDomain(fqdn="c2.evil")]))
        _compose(
            r,
            by_schema={"_C2Out": {"channels": [{"name": "HTTP C2", "protocol": "HTTP"}]}},
        )
        assert len(r.c2_channels) == 1
        assert r.c2_channels[0].name == "HTTP C2"

    def test_conclusion_authored(self) -> None:
        r = _report()
        _compose(
            r,
            by_schema={
                "Conclusion": {"sophistication_rating": "medium", "text": "A capable dropper."}
            },
        )
        assert r.conclusion is not None
        assert r.conclusion.sophistication_rating == "medium"

    def test_empty_llm_output_leaves_section_unset(self) -> None:
        # LLM returns an all-empty EncryptionScheme → not attached (no fabrication).
        r = _report(
            technical_evidence={
                "static": [{"tool_name": "detect_crypto_constants", "symbol": "", "output": "x"}]
            }
        )
        _compose(r, by_schema={"EncryptionScheme": {}})
        assert r.technical_analysis is None or r.technical_analysis.encryption_scheme is None

    def test_timeout_skips_section(self) -> None:
        class _SlowLLM:
            def with_structured_output(self, schema: type) -> Any:
                class _S:
                    async def ainvoke(self, messages: Any) -> Any:
                        await asyncio.sleep(2)
                        return schema()

                return _S()

            async def ainvoke(self, messages: Any) -> Any:
                await asyncio.sleep(2)
                return None

        r = _report(network=NetworkIOCs(domains=[NetworkDomain(fqdn="c2.evil")]))
        comp = ReportComposer(llm=_SlowLLM(), per_section_timeout=0)  # type: ignore[arg-type]
        asyncio.run(comp.compose(r, None))  # must not raise
        assert r.c2_channels == []

    def test_compose_never_raises_on_llm_error(self) -> None:
        class _BoomLLM:
            def with_structured_output(self, schema: type) -> Any:
                raise RuntimeError("boom")

            async def ainvoke(self, messages: Any) -> Any:
                raise RuntimeError("boom")

        r = _report(network=NetworkIOCs(domains=[NetworkDomain(fqdn="c2.evil")]))
        comp = ReportComposer(llm=_BoomLLM(), per_section_timeout=5)  # type: ignore[arg-type]
        asyncio.run(comp.compose(r, None))  # must not raise
        assert r.c2_channels == []


class TestHelpers:
    def test_has_content_ignores_bools(self) -> None:
        assert not _has_content(EncryptionScheme(per_file_key=True))
        assert _has_content(EncryptionScheme(cipher="AES"))

    def test_bundle_text_includes_evidence(self) -> None:
        r = _report(static=StaticAnalysis())
        from maljan.reporting.evidence_bundles import bundle_for

        b = bundle_for("executive_summary", r)
        text = _bundle_text("executive_summary", b)
        assert "SECTION: executive_summary" in text
        assert "verdict" in text


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-q"])


class TestFactsOutrankClaimsInThePrompt:
    """The prompt half of the 2026-07-28 grounding fix.

    Bundle isolation is what keeps each call small enough for the local model
    to stay coherent, and it was also removing the evidence that falsifies a
    wrong claim. Both blocks used to arrive under one undifferentiated
    "evidence" heading with no stated precedence, so a static-analyst claim of
    ".NET / _CorExeMain" had nothing above it to lose to.
    """

    def test_the_binary_block_is_rendered_and_labelled_as_outranking(self) -> None:
        text = _bundle_text(
            "conclusion",
            {
                "binary": {
                    "language_or_compiler": "Microsoft Visual C++ 2015-2022 (C/C++)",
                    "imported_dlls": ["kernel32.dll", "advapi32.dll"],
                },
                "facts": {"verdict": "Malware"},
                "claims": [{"claim": "Sample is a .NET loader", "evidence_ref": "static:entry"}],
                "tool_outputs": [],
            },
        )
        assert "BINARY FACTS" in text
        assert "outrank" in text
        assert "Microsoft Visual C++" in text
        assert "kernel32.dll" in text
        # The contradicting claim is still shown — the model is told to prefer
        # the fact, not kept ignorant of the disagreement.
        assert ".NET loader" in text
        assert text.index("BINARY FACTS") < text.index("ANALYST CLAIMS")

    def test_the_system_prompt_states_the_precedence(self) -> None:
        from maljan.reporting.composer import _SYSTEM

        lowered = _SYSTEM.lower()
        assert "outrank" in lowered
        assert "deterministic facts" in lowered

    def test_duplicate_keys_are_not_printed_twice(self) -> None:
        """The introduction repeats identity in ``facts`` because identity is
        its subject; the shared block must not restate it."""
        text = _bundle_text(
            "introduction",
            {
                "binary": {"file_type": "PE", "language_or_compiler": "Rust"},
                "facts": {"file_type": "PE", "language_or_compiler": "Rust", "category": "loader"},
                "claims": [],
                "tool_outputs": [],
            },
        )
        assert text.count("Rust") == 1
        assert text.count("file_type") == 1

    def test_an_all_duplicate_block_prints_no_empty_heading(self) -> None:
        text = _bundle_text(
            "introduction",
            {
                "binary": {"file_type": "PE"},
                "facts": {"file_type": "PE"},
                "claims": [],
                "tool_outputs": [],
            },
        )
        assert "BINARY FACTS" not in text
