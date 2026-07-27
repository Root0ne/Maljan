"""Tests for the deterministic import-capability Layer-0 (2026-07 round 2).

Grounds ATT&CK techniques in the PE extractor's already-classified imports +
static-string IOCs, closing the under-reporting gap the byte-scan YARA corpus
leaves (a WS2_32 network client with a hard-coded C2 domain was mapped to no
technique at all).

**2026-07-27** — the three hand-written technique blocks were replaced by a pass
over ``data/api_attck_map_v1.json`` (46 techniques). Two expectations here moved
with it, both deliberately:

* ``connect``/``send``/``recv`` now map to **T1095** (Non-Application Layer
  Protocol) rather than T1071 (Application Layer Protocol). Raw Winsock is not
  an application-layer protocol; the old rule reached T1071 because it keyed on
  the *category* ``network``, which lumps WS2_32 together with WinINet. The
  table distinguishes them, and T1071.001 is now reserved for binaries that
  actually import HTTP APIs.
* ``LoadLibraryA`` + ``GetProcAddress`` still map to nothing. They briefly
  mapped to T1129 (Shared Modules) while the table was being written, which was
  a mistake worth recording: that pair appears in essentially every PE ever
  compiled, so a rule keyed on it fires always and carries no information.

The invariant both cases protect is the one the layer exists for — a claim must
describe a capability, not a coincidence.
"""

from __future__ import annotations

from maljan.analysis.import_capability_layer import build_import_capability_isr
from maljan.reporting.models import ImportRow, StaticAnalysis, StringIOC


def _static(imports: list[ImportRow], strings: list[StringIOC] | None = None) -> StaticAnalysis:
    return StaticAnalysis(imports=imports, interesting_strings=strings or [])


def _imp(dll: str, fn: str, cat: str | None) -> ImportRow:
    return ImportRow(dll=dll, function=fn, is_suspicious=bool(cat), category=cat)


class TestNetworkT1071:
    def test_raw_socket_imports_plus_domain_map_to_t1095(self) -> None:
        """The audited MFC sample. Same evidence, more precise technique."""
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
        t1095 = [c for c in isr.claims if c.technique_id == "T1095"]
        assert len(t1095) == 1
        # A hard-coded endpoint in the strings corroborates the imports.
        assert "888kafa.com" in t1095[0].evidence_ref
        assert t1095[0].confidence > 0.40

    def test_http_imports_map_to_t1071_001(self) -> None:
        """WinINet, unlike raw Winsock, *is* an application-layer protocol."""
        static = _static(
            imports=[
                _imp("WININET.dll", "InternetOpenA", "network"),
                _imp("WININET.dll", "InternetConnectA", "network"),
                _imp("WININET.dll", "HttpSendRequestA", "network"),
            ]
        )
        isr = build_import_capability_isr(static)
        assert isr is not None
        assert any(c.technique_id == "T1071.001" for c in isr.claims)

    def test_a_single_socket_import_is_not_a_capability(self) -> None:
        """One import is a coincidence; ``min_apis`` is what says so."""
        static = _static(imports=[_imp("WS2_32.dll", "connect", "network")])
        isr = build_import_capability_isr(static)
        assert isr is None or not any(c.technique_id == "T1095" for c in isr.claims)


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
