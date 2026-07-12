"""Tests for the deterministic import-capability Layer-0 (2026-07 round 2).

Grounds ATT&CK techniques in the PE extractor's already-classified imports +
static-string IOCs, closing the under-reporting gap the byte-scan YARA corpus
leaves (a WS2_32 network client with a hard-coded C2 domain was mapped to no
technique at all).
"""

from __future__ import annotations

from maljan.analysis.import_capability_layer import build_import_capability_isr
from maljan.reporting.models import ImportRow, StaticAnalysis, StringIOC


def _static(imports: list[ImportRow], strings: list[StringIOC] | None = None) -> StaticAnalysis:
    return StaticAnalysis(imports=imports, interesting_strings=strings or [])


def _imp(dll: str, fn: str, cat: str | None) -> ImportRow:
    return ImportRow(dll=dll, function=fn, is_suspicious=bool(cat), category=cat)


class TestNetworkT1071:
    def test_network_imports_plus_domain_map_to_t1071(self) -> None:
        static = _static(
            imports=[
                _imp("WS2_32.dll", "connect", "network"),
                _imp("WS2_32.dll", "recv", "network"),
                _imp("WS2_32.dll", "send", "network"),
            ],
            strings=[StringIOC(value="888kafa.com", kind="domain", notes=None)],
        )
        isr = build_import_capability_isr(static)
        assert isr is not None
        assert isr.domain == "static"
        t1071 = [c for c in isr.claims if c.technique_id == "T1071"]
        assert len(t1071) == 1
        # domain present -> higher confidence + IOC cited in evidence
        assert t1071[0].confidence == 0.60
        assert "888kafa.com" in t1071[0].evidence_ref
        assert "WS2_32" in t1071[0].evidence_ref

    def test_network_imports_without_ioc_lower_confidence(self) -> None:
        static = _static(imports=[_imp("WS2_32.dll", "connect", "network")])
        isr = build_import_capability_isr(static)
        assert isr is not None
        t1071 = [c for c in isr.claims if c.technique_id == "T1071"]
        assert t1071 and t1071[0].confidence == 0.45


class TestInjectionT1055:
    def test_only_when_injection_api_actually_imported(self) -> None:
        # WriteProcessMemory present -> T1055.
        static = _static(imports=[_imp("KERNEL32.dll", "WriteProcessMemory", "process_injection")])
        isr = build_import_capability_isr(static)
        assert isr is not None
        assert any(c.technique_id == "T1055" for c in isr.claims)

    def test_no_injection_api_no_t1055(self) -> None:
        # The audited MFC sample: LoadLibraryA/GetProcAddress classified as
        # "execution", never as injection -> no T1055.
        static = _static(
            imports=[
                _imp("KERNEL32.dll", "LoadLibraryA", "execution"),
                _imp("KERNEL32.dll", "GetProcAddress", "execution"),
            ]
        )
        isr = build_import_capability_isr(static)
        # No network/injection/crypto categories -> nothing to ground.
        assert isr is None


class TestEmptyAndNone:
    def test_none_static_returns_none(self) -> None:
        assert build_import_capability_isr(None) is None

    def test_no_suspicious_imports_returns_none(self) -> None:
        static = _static(imports=[_imp("USER32.dll", "DrawIcon", None)])
        assert build_import_capability_isr(static) is None
