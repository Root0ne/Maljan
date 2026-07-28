"""Packer detection was four `if` statements, and better detection made T1027 worse.

The four checks — UPX, ASPack, Themida, VMProtect by section name — answered a
yes/no question with a string. That was enough while nothing downstream needed
to know *how sure* the answer was, and it stopped being enough the moment the
catalog grew.

The trap, and the reason this file exists: `capability_matrix._static_evidence_flags`
gates the T1027/T1140 over-claim cap on whether static evidence supports an
obfuscation claim. The cap exists because the local model over-claims that
technique. So a detector that fires on *more* samples makes the cap fire on
*fewer* — and shipping a better packer detector on its own would have produced
**more** high-confidence hallucinated T1027, not less. A confidence threshold is
what breaks the inversion: a string-only guess is not corroboration, a
structural match is.

The other half is the language table, which replaced six literal checks. The old
code answered "Rust" to any binary containing the string `rustc` — including a
scanner carrying Rust signatures.
"""

from __future__ import annotations

from maljan.extractors.capability_matrix import _PACKER_CONFIDENCE_FLOOR, _static_evidence_flags
from maljan.extractors.sample_identity import _detect_language_or_compiler, _infer_platform
from maljan.reporting.models import PESection, StaticAnalysis


def _static(**kw: object) -> StaticAnalysis:
    return StaticAnalysis(**kw)  # type: ignore[arg-type]


class TestTheT1027CapSurvivesABetterDetector:
    def test_a_structural_match_counts_as_corroboration(self) -> None:
        static = _static(
            packer_matches=[
                {"name": "UPX", "kind": "packer", "confidence": 0.85, "method": "section"}
            ]
        )
        obf, _inj = _static_evidence_flags(static)
        assert obf is True

    def test_a_string_only_guess_does_not(self) -> None:
        """This is the whole point. Without the threshold, every sample whose
        strings mention a packer would suppress the over-claim cap."""
        static = _static(
            packer_matches=[
                {"name": "UPX", "kind": "packer", "confidence": 0.45, "method": "string"}
            ]
        )
        obf, _inj = _static_evidence_flags(static)
        assert obf is False, "a 0.45 string hit must not count as evidence of packing"

    def test_the_floor_sits_between_the_two_bands(self) -> None:
        """String-only matches are capped at 0.45; structural start at 0.60."""
        assert 0.45 < _PACKER_CONFIDENCE_FLOOR <= 0.60

    def test_without_a_catalog_the_old_behaviour_holds(self) -> None:
        """No packer_matches -> fall back to the bare hint, which is what the
        code did before the catalog existed."""
        static = _static(packer_hint="UPX")
        obf, _inj = _static_evidence_flags(static)
        assert obf is True

    def test_high_entropy_still_counts_on_its_own(self) -> None:
        static = _static(sections=[PESection(name=".text", virtual_address="0x1000", entropy=7.6)])
        obf, _inj = _static_evidence_flags(static)
        assert obf is True

    def test_a_clean_sample_has_no_obfuscation_evidence(self) -> None:
        static = _static(sections=[PESection(name=".text", virtual_address="0x1000", entropy=6.1)])
        obf, inj = _static_evidence_flags(static)
        assert obf is False and inj is False


class TestTheLanguageTable:
    def test_a_single_suggestive_string_is_not_an_identification(self) -> None:
        """The old code answered "Rust" to anything containing "rustc" — a
        scanner carrying Rust signatures included."""
        assert _detect_language_or_compiler(b"\x00rustc\x00" + b"\x00" * 500) != "Rust"

    def test_real_runtime_markers_identify_go(self) -> None:
        blob = b"\x00Go build ID\x00.gopclntab\x00runtime.gopanic\x00"
        assert _detect_language_or_compiler(blob) == "Go"

    def test_real_runtime_markers_identify_rust(self) -> None:
        blob = b"\x00rust_begin_unwind\x00core::panicking\x00rustc\x00"
        assert _detect_language_or_compiler(blob) == "Rust"

    def test_autoit_is_recognised(self) -> None:
        blob = b"\x00AU3!EA06\x00AutoIt v3\x00"
        assert _detect_language_or_compiler(blob) == "AutoIt"

    def test_pyinstaller_is_recognised(self) -> None:
        blob = b"\x00PYZ-00.pyz\x00_MEIPASS\x00pyi-runtime-tmpdir\x00"
        assert _detect_language_or_compiler(blob) == "Python (PyInstaller)"

    def test_an_empty_blob_is_handled(self) -> None:
        assert _detect_language_or_compiler(b"") is None
        assert _detect_language_or_compiler(None) is None


class TestPlatformDisambiguation:
    def test_magic_bytes_still_win(self) -> None:
        assert _infer_platform("PE", None, None) == "windows"
        assert _infer_platform("ELF", None, None) == "linux"

    def test_a_windows_only_toolchain_rescues_an_unknown_blob(self) -> None:
        """`unknown` is not neutral downstream: it makes the YARA layer drop
        every platform-specific rule, so the sample is scanned by a fraction of
        the corpus."""
        assert _infer_platform("unknown", None, None, "AutoIt") == "windows"
        assert _infer_platform("unknown", None, None, "Microsoft Visual C++ 2015-2022") == "windows"

    def test_a_cross_platform_toolchain_does_not(self) -> None:
        """Go and Rust say nothing about the target OS. Guessing from them
        would assign a platform on no evidence."""
        assert _infer_platform("unknown", None, None, "Go") == "unknown"
        assert _infer_platform("unknown", None, None, "Rust") == "unknown"

    def test_no_hint_is_still_unknown(self) -> None:
        assert _infer_platform("unknown", None, None, None) == "unknown"


class TestThePdbPathIsExtracted:
    """The single highest-value string in a PE, and Maljan was not reading it.

    Found by diffing Qu1cksc0pe's report for the same sample, which contained
    ``E:\\xml-data\\build-dir\\CODRU-CL23M-SOURCES\\bin\\Win32\\Release\\BdUserHost.pdb``
    where Maljan's had nothing. One field carrying the build machine's drive
    layout, the internal project name, the target architecture and the build
    configuration — and the internal name is frequently the family's own, before
    anyone in the industry chose one for it.

    Required adding IMAGE_DIRECTORY_ENTRY_DEBUG to the directories `_parse_pe`
    asks pefile for; it previously requested only IMPORT, EXPORT and RESOURCE,
    so the data was never parsed at all.
    """

    def test_the_debug_directory_is_requested(self) -> None:
        import inspect

        from maljan.extractors import pe_extractor

        source = inspect.getsource(pe_extractor._parse_pe)
        assert "IMAGE_DIRECTORY_ENTRY_DEBUG" in source, (
            "without this directory the PDB path is never parsed"
        )

    def test_a_codeview_entry_is_read(self) -> None:
        from types import SimpleNamespace

        from maljan.extractors.pe_extractor import _pe_pdb_path

        pe = SimpleNamespace(
            DIRECTORY_ENTRY_DEBUG=[
                SimpleNamespace(
                    entry=SimpleNamespace(PdbFileName=b"E:\\build\\Release\\Payload.pdb\x00")
                )
            ]
        )
        assert _pe_pdb_path(pe) == "E:\\build\\Release\\Payload.pdb"

    def test_a_stripped_binary_yields_none(self) -> None:
        from types import SimpleNamespace

        from maljan.extractors.pe_extractor import _pe_pdb_path

        assert _pe_pdb_path(SimpleNamespace()) is None
        assert _pe_pdb_path(SimpleNamespace(DIRECTORY_ENTRY_DEBUG=[])) is None

    def test_a_malformed_entry_does_not_raise(self) -> None:
        from types import SimpleNamespace

        from maljan.extractors.pe_extractor import _pe_pdb_path

        pe = SimpleNamespace(
            DIRECTORY_ENTRY_DEBUG=[SimpleNamespace(entry=SimpleNamespace(PdbFileName=None))]
        )
        assert _pe_pdb_path(pe) is None
