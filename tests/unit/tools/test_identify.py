"""``maljan.tools.identify`` answers about real bytes, not about types.

Every assertion here names a value: the format string, the platform, the
digest, the signing-scheme label. A test that only checked the keys were
present would pass against a tool that reported every file as ``unknown``,
which is the failure mode that actually matters — an identification tool that
never identifies anything looks exactly like a working one from the outside.
"""

from __future__ import annotations

import hashlib
import struct
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from maljan.tools import identify

ELF_HEADER = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + struct.pack("<HH", 2, 0x3E)
PE_STUB = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80) + b"\x00" * 62 + b"PE\x00\x00"
MACHO_64_LE = b"\xcf\xfa\xed\xfe"


def _macho_64(commands: bytes, ncmds: int) -> bytes:
    """A 32-byte mach_header_64 followed by its load commands."""
    header = MACHO_64_LE + struct.pack("<IIIIIII", 0x01000007, 0, 2, ncmds, len(commands), 0, 0)
    return header + commands


def _write(tmp_path: Path, name: str, blob: bytes) -> str:
    target = tmp_path / name
    target.write_bytes(blob)
    return str(target)


APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
APK_SCHEME_V2 = 0x7109871A
APK_SCHEME_V3 = 0xF05368C0
APK_SCHEME_V31 = 0x1B93AD61
# The padding pair apksigner writes to align the block; not a scheme.
APK_PADDING_ID = 0x42726577


def _signing_block(pair_ids: list[int]) -> bytes:
    """An APK Signing Block holding one value per id, laid out as the spec has it.

    Leading uint64 size, the id-value pairs, the same size again, the magic.
    The size counts everything after the leading field, so the first pair
    begins eight bytes past the block's start.
    """
    pairs = b""
    for pair_id in pair_ids:
        value = b"\x30\x82" + b"\x00" * 46
        pairs += struct.pack("<QI", 4 + len(value), pair_id) + value
    block_size = len(pairs) + 8 + len(APK_SIG_BLOCK_MAGIC)
    size_field = struct.pack("<Q", block_size)
    return size_field + pairs + size_field + APK_SIG_BLOCK_MAGIC


def _apk_with_block(tmp_path: Path, name: str, block: bytes, *, cert: bool = False) -> str:
    """A real zip with a signing block spliced in where apksigner puts it.

    Between the last local entry and the central directory, with the end
    record's directory offset moved on by the block's length, so the file is
    still a readable archive.
    """
    raw = tmp_path / f"{name}.staging"
    with zipfile.ZipFile(raw, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00binary manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
        if cert:
            archive.writestr("META-INF/CERT.RSA", b"\x30\x82 not a real pkcs7")
    blob = bytearray(raw.read_bytes())
    end = blob.rfind(b"PK\x05\x06")
    directory_at = struct.unpack_from("<I", blob, end + 16)[0]
    struct.pack_into("<I", blob, end + 16, directory_at + len(block))
    spliced = bytes(blob[:directory_at]) + block + bytes(blob[directory_at:])
    return _write(tmp_path, name, spliced)


class TestIdentifyFile:
    def test_an_elf_is_an_elf_on_linux(self, tmp_path: Path) -> None:
        result = identify.identify_file(_write(tmp_path, "s.bin", ELF_HEADER + b"\x00" * 512))
        assert result["file_type"] == "elf"
        assert result["platform"] == "linux"
        assert result["category"] == "executable"
        assert result["magic_hex"].startswith("7f454c46")

    def test_a_pe_is_a_pe_on_windows(self, tmp_path: Path) -> None:
        result = identify.identify_file(_write(tmp_path, "s.exe", PE_STUB + b"\x00" * 512))
        assert result["file_type"] == "pe"
        assert result["platform"] == "windows"

    def test_a_missing_file_is_an_error_and_not_an_exception(self) -> None:
        result = identify.identify_file("/nonexistent/sample.bin")
        assert result["tool"] == "identify_file"
        assert "no such file" in result["error"]


class TestHashes:
    def test_the_three_cryptographic_digests_are_the_real_ones(self, tmp_path: Path) -> None:
        blob = b"maljan test sample" * 64
        result = identify.hashes(_write(tmp_path, "s.bin", blob))
        assert result["sha256"] == hashlib.sha256(blob).hexdigest()
        assert result["md5"] == hashlib.md5(blob, usedforsecurity=False).hexdigest()
        assert result["sha1"] == hashlib.sha1(blob, usedforsecurity=False).hexdigest()

    def test_an_uncomputable_fuzzy_hash_is_absent_rather_than_null(self, tmp_path: Path) -> None:
        """A missing key means "could not compute"; ``None`` would read as a value."""
        result = identify.hashes(_write(tmp_path, "s.txt", b"not a binary"))
        for key in ("ssdeep", "tlsh", "imphash", "telfhash"):
            assert result.get(key) is None
            assert key not in result or result[key]

    def test_imphash_is_absent_for_a_file_that_is_not_a_pe(self, tmp_path: Path) -> None:
        result = identify.hashes(_write(tmp_path, "s.bin", ELF_HEADER + b"\x00" * 512))
        assert "imphash" not in result


class TestSigningInfo:
    """One answer, about the format this sample was routed as.

    The three schemes used to be reported together, so a PE carried "apk
    present=no" and "macho present=no" beside the row that was about it —
    statements about what the tool looks for, read downstream as findings
    about the sample.
    """

    def test_a_format_with_no_signing_scheme_says_so_once(self, tmp_path: Path) -> None:
        result = identify.signing_info(
            _write(tmp_path, "s.bin", ELF_HEADER + b"\x00" * 512), file_type="elf"
        )
        assert result == {"format": "elf", "applicable": False}

    def test_a_pe_is_asked_about_authenticode_and_nothing_else(self, tmp_path: Path) -> None:
        result = identify.signing_info(_write(tmp_path, "s.exe", PE_STUB), file_type="pe")
        assert result["format"] == "pe"
        assert result["authenticode"]["present"] is False
        assert "apk" not in result
        assert "macho" not in result

    def test_a_v1_signed_apk_is_found_from_its_meta_inf_certificate(self, tmp_path: Path) -> None:
        apk = tmp_path / "app.apk"
        with zipfile.ZipFile(apk, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00binary manifest")
            archive.writestr("classes.dex", b"dex\n035\x00")
            archive.writestr("META-INF/CERT.RSA", b"\x30\x82 fake pkcs7")
        result = identify.signing_info(str(apk), file_type="apk")
        assert result["format"] == "apk"
        assert result["apk"]["present"] is True
        assert result["apk"]["schemes"] == ["v1"]
        assert result["apk"]["cert_files"] == ["META-INF/CERT.RSA"]
        assert "authenticode" not in result

    def test_an_apk_signed_only_with_scheme_v2_is_not_reported_unsigned(
        self, tmp_path: Path
    ) -> None:
        """Every modern APK is v2/v3 only; reading the block wrong calls them all unsigned."""
        apk = _apk_with_block(tmp_path, "v2.apk", _signing_block([APK_SCHEME_V2]))
        result = identify.signing_info(apk, file_type="apk")
        assert result["apk"]["present"] is True
        assert result["apk"]["schemes"] == ["v2"]
        assert result["apk"]["cert_files"] == []

    def test_an_apk_signed_only_with_scheme_v3_names_that_scheme(self, tmp_path: Path) -> None:
        apk = _apk_with_block(tmp_path, "v3.apk", _signing_block([APK_SCHEME_V3]))
        result = identify.signing_info(apk, file_type="apk")
        assert result["apk"]["present"] is True
        assert result["apk"]["schemes"] == ["v3"]

    def test_a_rotated_key_reports_scheme_v3_1(self, tmp_path: Path) -> None:
        """v3.1 carries a rotated signing key beside v3, and its id is its own."""
        block = _signing_block([APK_SCHEME_V3, APK_SCHEME_V31])
        result = identify.signing_info(_apk_with_block(tmp_path, "rot.apk", block), "apk")
        assert result["apk"]["schemes"] == ["v3", "v3.1"]

    def test_an_apk_signed_with_v2_and_v3_names_both_and_skips_the_padding_pair(
        self, tmp_path: Path
    ) -> None:
        """The shape of a production APK: both schemes, no META-INF certificate."""
        block = _signing_block([APK_SCHEME_V2, APK_SCHEME_V3, APK_PADDING_ID])
        result = identify.signing_info(_apk_with_block(tmp_path, "both.apk", block), "apk")
        assert result["apk"]["present"] is True
        assert result["apk"]["schemes"] == ["v2", "v3"]

    def test_an_apk_carrying_both_a_certificate_and_a_block_names_all_three(
        self, tmp_path: Path
    ) -> None:
        block = _signing_block([APK_SCHEME_V2, APK_SCHEME_V3])
        apk = _apk_with_block(tmp_path, "all.apk", block, cert=True)
        result = identify.signing_info(apk, file_type="apk")
        assert result["apk"]["schemes"] == ["v1", "v2", "v3"]
        assert result["apk"]["cert_files"] == ["META-INF/CERT.RSA"]

    def test_an_apk_with_no_signature_at_all_is_the_only_unsigned_answer(
        self, tmp_path: Path
    ) -> None:
        apk = tmp_path / "bare.apk"
        with zipfile.ZipFile(apk, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00binary manifest")
            archive.writestr("classes.dex", b"dex\n035\x00")
        result = identify.signing_info(str(apk), file_type="apk")
        assert result["apk"] == {"present": False, "schemes": [], "cert_files": []}

    def test_a_block_whose_two_size_fields_disagree_yields_no_schemes(self, tmp_path: Path) -> None:
        """Without a coherent footer the block was not located, so nothing is claimed."""
        block = bytearray(_signing_block([APK_SCHEME_V2]))
        struct.pack_into("<Q", block, 0, len(block) + 64)
        apk = _apk_with_block(tmp_path, "torn.apk", bytes(block))
        assert identify.signing_info(apk, file_type="apk")["apk"]["schemes"] == []

    def test_a_zip_that_is_not_an_apk_is_not_asked_about_apk_signing(self, tmp_path: Path) -> None:
        """A .docx is a zip. Nothing about it is an Android signing scheme."""
        document = tmp_path / "letter.docx"
        with zipfile.ZipFile(document, "w") as archive:
            archive.writestr("word/document.xml", b"<w:document/>")
        assert identify.signing_info(str(document)) == {"format": "unknown", "applicable": False}
        assert identify.signing_info(str(document), file_type="docx") == {
            "format": "docx",
            "applicable": False,
        }

    def test_a_macho_load_command_chain_without_a_signature_says_so(self, tmp_path: Path) -> None:
        # One LC_SEGMENT_64 (0x19) command and nothing else.
        command = struct.pack("<II", 0x19, 16) + b"\x00" * 8
        result = identify.signing_info(
            _write(tmp_path, "bin", _macho_64(command, 1)), file_type="mach-o"
        )
        assert result["macho"] == {"present": False}

    def test_a_macho_carrying_lc_code_signature_is_reported_as_signed(self, tmp_path: Path) -> None:
        commands = struct.pack("<II", 0x19, 16) + b"\x00" * 8
        commands += struct.pack("<II", 0x1D, 16) + b"\x00" * 8
        result = identify.signing_info(_write(tmp_path, "bin", _macho_64(commands, 2)))
        assert result["format"] == "mach-o"
        assert result["macho"]["present"] is True
        assert result["macho"]["load_command"] == "LC_CODE_SIGNATURE"

    def test_the_bytes_answer_when_the_caller_routed_nothing(self, tmp_path: Path) -> None:
        """An agent calling the tool directly has a path and nothing else."""
        result = identify.signing_info(_write(tmp_path, "s.exe", PE_STUB))
        assert result["format"] == "pe"
        assert "authenticode" in result


CODE_SIGNING_USAGE = "1.3.6.1.5.5.7.3.3"
TIME_STAMPING_USAGE = "1.3.6.1.5.5.7.3.8"


def _a_certificate(
    common_name: str,
    *,
    issuer_name: str | None = None,
    issuer_key: Any = None,
    authority: bool = False,
    usages: tuple[str, ...] = (),
) -> tuple[Any, Any]:
    """A throwaway certificate and its key, generated for this test alone."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    opened = datetime(2026, 1, 1, tzinfo=UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name or common_name)])
        )
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(opened)
        .not_valid_after(opened + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=authority, path_length=None), critical=True)
    )
    if usages:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier(oid) for oid in usages]), critical=False
        )
    return builder.sign(issuer_key or key, hashes.SHA256()), key


def _authenticode_blob(extra: tuple[Any, ...] = (), *, publisher_usages: tuple[str, ...] = ()):
    """A PKCS#7 SignedData carrying a publisher certificate and its issuer.

    ``extra`` is whatever else the producer put in the bundle — a timestamp
    authority's chain, a cross-signing root — which is where the wrong answer
    used to come from.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import pkcs7

    authority, authority_key = _a_certificate("Maljan Test Root CA", authority=True)
    publisher, publisher_key = _a_certificate(
        "Maljan Test Publisher",
        issuer_name="Maljan Test Root CA",
        issuer_key=authority_key,
        usages=publisher_usages,
    )
    builder = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(b"authenticode")
        .add_signer(publisher, publisher_key, hashes.SHA256())
        .add_certificate(authority)
    )
    for certificate in extra:
        builder = builder.add_certificate(certificate)
    der = builder.sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature])
    return der, publisher


def _a_timestamp_chain() -> tuple[Any, ...]:
    """A timestamp authority's root and signer, as a timestamped file carries them."""
    root, root_key = _a_certificate("Maljan Test TSA Root", authority=True)
    signer, _key = _a_certificate(
        "Maljan Test Time Stamping Signer",
        issuer_name="Maljan Test TSA Root",
        issuer_key=root_key,
        usages=(TIME_STAMPING_USAGE,),
    )
    return root, signer


def _signed_pe(pkcs7_der: bytes) -> bytes:
    """A PE32 whose security directory points at ``pkcs7_der``.

    Hand-built for the same reason the import-table fixtures are: the one
    thing under test is the certificate table, and every other field is here
    only so that ``pefile`` will walk to it.
    """
    opt = bytearray()
    opt += struct.pack("<HBB", 0x10B, 14, 29)
    opt += struct.pack("<III", 0x200, 0, 0)
    opt += struct.pack("<III", 0x1000, 0x1000, 0x1000)
    opt += struct.pack("<III", 0x400000, 0x1000, 0x200)
    opt += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)
    opt += struct.pack("<I", 0)
    opt += struct.pack("<II", 0x2000, 0x200)
    opt += struct.pack("<IHH", 0, 3, 0x8140)
    opt += struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<II", 0, 16)
    # The WIN_CERTIFICATE is at a file offset, not an RVA — the one data
    # directory of the sixteen that is addressed that way.
    certificate = struct.pack("<IHH", len(pkcs7_der) + 8, 0x0200, 0x0002) + pkcs7_der
    directories = [(0, 0)] * 16
    directories[4] = (0x400, len(certificate))
    for rva, size in directories:
        opt += struct.pack("<II", rva, size)

    file_header = struct.pack("<HHIIIHH", 0x14C, 1, 0x5F5E0FF, 0, 0, len(opt), 0x0102)
    headers = bytearray(0x200)
    headers[0:2] = b"MZ"
    headers[0x3C:0x40] = struct.pack("<I", 0x40)
    at = 0x40
    headers[at : at + 4] = b"PE\x00\x00"
    at += 4
    headers[at : at + len(file_header)] = file_header
    at += len(file_header)
    headers[at : at + len(opt)] = opt
    at += len(opt)
    headers[at : at + 40] = struct.pack(
        "<8sIIIIIIHHI", b".text\x00\x00\x00", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0xC0000040
    )
    return bytes(headers) + b"\x00" * 0x200 + certificate


class TestWhoSignedIt:
    """A signed binary was reported as `authenticode present` and nothing else.

    The subject and issuer were left for "an enrichment step" that does not
    exist, so the strongest benign fact a run had — a code-signing certificate
    naming its publisher — reached every agent anonymous. Reading the names
    out of the PKCS#7 blob is not verifying the chain, and nothing here claims
    it is: `valid` stays unset.
    """

    def test_the_publisher_and_its_issuer_are_named(self, tmp_path: Path) -> None:
        pytest.importorskip("pefile")
        der, publisher = _authenticode_blob()
        result = identify.signing_info(_write(tmp_path, "s.exe", _signed_pe(der)), file_type="pe")
        assert result["authenticode"]["present"] is True
        assert "Maljan Test Publisher" in result["authenticode"]["subject"]
        assert "Maljan Test Root CA" in result["authenticode"]["issuer"]

    def test_the_thumbprint_is_the_certificate_the_names_came_from(self, tmp_path: Path) -> None:
        pytest.importorskip("pefile")
        from cryptography.hazmat.primitives import hashes

        der, publisher = _authenticode_blob()
        result = identify.signing_info(_write(tmp_path, "s.exe", _signed_pe(der)), file_type="pe")
        assert result["authenticode"]["thumbprint"] == publisher.fingerprint(hashes.SHA1()).hex()

    def test_the_signer_is_the_leaf_and_not_its_authority(self, tmp_path: Path) -> None:
        """The blob carries the chain; the one that signed the file is the one
        nothing else in it issued."""
        pytest.importorskip("pefile")
        der, _publisher = _authenticode_blob()
        result = identify.signing_info(_write(tmp_path, "s.exe", _signed_pe(der)), file_type="pe")
        assert "Maljan Test Root CA" not in result["authenticode"]["subject"]

    def test_no_chain_verdict_is_claimed(self, tmp_path: Path) -> None:
        pytest.importorskip("pefile")
        der, _publisher = _authenticode_blob()
        result = identify.signing_info(_write(tmp_path, "s.exe", _signed_pe(der)), file_type="pe")
        assert result["authenticode"].get("valid") is None

    def test_an_unsigned_pe_names_nobody(self, tmp_path: Path) -> None:
        result = identify.signing_info(_write(tmp_path, "s.exe", PE_STUB), file_type="pe")
        assert result["authenticode"] == {
            "present": False,
            "subject": None,
            "issuer": None,
            "thumbprint": None,
        }


class TestTheTimestampAuthorityIsNeverThePublisher:
    """A timestamped file carries two chains, so two certificates look like leaves.

    Picking "the one that issued none of the others" then picks whichever the
    producer wrote first, and over the local corpus that named a timestamp
    authority as the publisher on four signed binaries out of seventeen. The
    publisher is the certificate the SignerInfo names.
    """

    def _subject(self, tmp_path: Path, der: bytes) -> str | None:
        result = identify.signing_info(_write(tmp_path, "s.exe", _signed_pe(der)), file_type="pe")
        assert result["authenticode"]["present"] is True
        return result["authenticode"]["subject"]

    def test_an_embedded_timestamp_chain_does_not_become_the_signer(self, tmp_path: Path) -> None:
        pytest.importorskip("pefile")
        der, _publisher = _authenticode_blob(_a_timestamp_chain())
        subject = self._subject(tmp_path, der)
        assert "Maljan Test Publisher" in (subject or "")
        assert "Time Stamping" not in (subject or "")

    def test_a_counter_signature_leaves_the_publisher_alone(self, tmp_path: Path) -> None:
        """A counter-signature adds its signer to the same certificate set."""
        pytest.importorskip("pefile")
        counter, _key = _a_certificate("Maljan Test Counter Signer", usages=(TIME_STAMPING_USAGE,))
        der, publisher = _authenticode_blob((counter,))
        subject = self._subject(tmp_path, der)
        assert subject == publisher.subject.rfc4514_string()

    def test_a_cross_signed_chain_still_names_the_publisher(self, tmp_path: Path) -> None:
        """A second root that also issued the publisher's authority is in the bundle."""
        pytest.importorskip("pefile")
        cross, _key = _a_certificate("Maljan Test Cross Root", authority=True)
        der, publisher = _authenticode_blob((cross,))
        assert self._subject(tmp_path, der) == publisher.subject.rfc4514_string()

    def test_the_thumbprint_follows_the_name(self, tmp_path: Path) -> None:
        pytest.importorskip("pefile")
        from cryptography.hazmat.primitives import hashes

        der, publisher = _authenticode_blob(_a_timestamp_chain())
        result = identify.signing_info(_write(tmp_path, "s.exe", _signed_pe(der)), file_type="pe")
        assert result["authenticode"]["thumbprint"] == publisher.fingerprint(hashes.SHA1()).hex()


class TestWhenNothingDecidesNoPublisherIsNamed:
    """A name that might be the timestamp authority's is worse than no name."""

    def test_an_unreadable_signer_identifier_falls_back_to_the_key_usage(self) -> None:
        from maljan.extractors.authenticode import publisher_certificate

        publisher, _key = _a_certificate("Maljan Test Publisher", usages=(CODE_SIGNING_USAGE,))
        stamper, _stamper_key = _a_certificate(
            "Maljan Test Time Stamping Signer", usages=(TIME_STAMPING_USAGE,)
        )
        picked = publisher_certificate(b"not a signed data blob", [stamper, publisher])
        assert picked is publisher

    def test_two_candidates_with_no_key_usage_name_nobody(self) -> None:
        from maljan.extractors.authenticode import publisher_certificate

        first, _a = _a_certificate("Maljan Test One")
        second, _b = _a_certificate("Maljan Test Two")
        assert publisher_certificate(b"", [first, second]) is None

    def test_a_blob_that_names_nobody_leaves_the_pack_without_a_publisher(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Still reported as signed — the signature is there — and unattributed."""
        pytest.importorskip("pefile")
        from maljan.extractors import authenticode

        monkeypatch.setattr(authenticode, "publisher_certificate", lambda der, certs: None)
        der, _publisher = _authenticode_blob()
        result = identify.signing_info(_write(tmp_path, "s.exe", _signed_pe(der)), file_type="pe")
        assert result["authenticode"]["present"] is True
        assert result["authenticode"]["subject"] is None
        assert result["authenticode"]["issuer"] is None
        assert result["authenticode"]["thumbprint"] is None
