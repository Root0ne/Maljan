"""Capability-matrix signal-quality tests (§2.4).

Zero-signal techniques (no confidence, no evidence, no contributing layer) must
not be emitted as cells/mappings — they would render as "verified" capabilities
and seed fabricated narrative prose.
"""

from __future__ import annotations

from types import SimpleNamespace

from maljan.extractors.capability_matrix import build_capability_matrix


def test_zero_signal_technique_dropped() -> None:
    empty = SimpleNamespace(
        technique_id="T1000", weighted_confidence=0.0, contributing_layers=[], evidence=[]
    )
    real = SimpleNamespace(
        technique_id="T1055",
        weighted_confidence=0.8,
        contributing_layers=["yara"],
        evidence=["WriteProcessMemory @ 0x401000"],
    )
    cells, mappings = build_capability_matrix(cascade_summary=[empty, real], isr_reports=None)
    cell_ids = {c.technique_id for c in cells}
    mapping_ids = {m.technique_id for m in mappings}
    assert "T1055" in cell_ids
    assert "T1000" not in cell_ids
    assert "T1000" not in mapping_ids


def test_technique_with_evidence_but_zero_conf_kept() -> None:
    # Evidence present (even if confidence wasn't computed) is real signal.
    entry = SimpleNamespace(
        technique_id="T1059",
        weighted_confidence=0.0,
        contributing_layers=[],
        evidence=["cmd.exe /c whoami"],
    )
    cells, _ = build_capability_matrix(cascade_summary=[entry], isr_reports=None)
    assert {c.technique_id for c in cells} == {"T1059"}


# ---------------------------------------------------------------------------
# 2026-07 round 3 — deterministic confidence cap for LLM-only over-claims
# ---------------------------------------------------------------------------

from maljan.extractors.capability_matrix import (  # noqa: E402
    _LOW_CONF_CAP,
    _cap_unsupported_confidence,
    _static_evidence_flags,
)


def _static(*, packer=None, entropies=(), obf=(), imports=()):
    sections = [SimpleNamespace(entropy=e) for e in entropies]
    imps = [SimpleNamespace(category=c, function=f) for c, f in imports]
    return SimpleNamespace(
        packer_hint=packer, sections=sections, obfuscation_indicators=list(obf), imports=imps
    )


class TestStaticEvidenceFlags:
    def test_no_evidence(self) -> None:
        # ordinary MFC-like sample: no packer, normal entropy, no injection
        st = _static(entropies=(5.4, 3.4), imports=[("execution", "LoadLibraryA")])
        assert _static_evidence_flags(st) == (False, False)

    def test_obfuscation_via_entropy(self) -> None:
        st = _static(entropies=(7.5,))
        assert _static_evidence_flags(st)[0] is True

    def test_obfuscation_via_packer_hint(self) -> None:
        assert _static_evidence_flags(_static(packer="UPX"))[0] is True

    def test_injection_real(self) -> None:
        st = _static(imports=[("process_injection", "WriteProcessMemory")])
        assert _static_evidence_flags(st)[1] is True

    def test_none_static_does_not_cap(self) -> None:
        assert _static_evidence_flags(None) == (True, True)


class TestConfidenceCap:
    def test_t1027_capped_without_obfuscation(self) -> None:
        assert _cap_unsupported_confidence("T1027", 0.85, ["static"], False, False) == _LOW_CONF_CAP

    def test_t1055_capped_without_injection(self) -> None:
        assert _cap_unsupported_confidence("T1055", 0.80, ["static"], False, False) == _LOW_CONF_CAP

    def test_subtechnique_capped(self) -> None:
        assert (
            _cap_unsupported_confidence("T1027.002", 0.9, ["static"], False, False) == _LOW_CONF_CAP
        )

    def test_not_capped_when_evidence_present(self) -> None:
        assert _cap_unsupported_confidence("T1027", 0.85, ["static"], True, False) == 0.85
        assert _cap_unsupported_confidence("T1055", 0.80, ["static"], False, True) == 0.80

    def test_not_capped_when_corroborated_by_yara(self) -> None:
        # a non-LLM layer (yara) corroborates -> trust it, no cap
        assert _cap_unsupported_confidence("T1027", 0.85, ["static", "yara"], False, False) == 0.85

    def test_ungated_technique_untouched(self) -> None:
        assert _cap_unsupported_confidence("T1071", 0.60, ["static"], False, False) == 0.60
