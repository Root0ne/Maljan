"""Where the worker's code opens a file's bytes or hands them to a parser, and why (X2).

The triage pack's readings of the sample go through ``tools.readers``, which
runs each on the server declaring its tool when that server is a container of
its own; the worker then opens none of the sample's bytes for them. Every
other place is listed here, each with why: hashing and routing the sample,
handing its bytes on unread, files that are not the sample at all, the
readings' own code (which runs where its reading is placed), and the readers
left for a later change, named as such. A new place fails here until it is
placed behind the boundary or listed with its reason.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

from maljan.tools.readers import READERS

ROOT = Path(__file__).resolve().parents[2]

# The worker's own code: the pipeline and what it calls in process.
WORKER_CODE = (
    "src/maljan/app.py",
    "src/maljan/pipeline",
    "src/maljan/agents",
    "src/maljan/providers",
    "src/maljan/reporting",
    "src/maljan/analysis",
    "src/maljan/core",
    "src/maljan/parsers",
    "src/maljan/loaders",
    "src/maljan/memory",
    "src/maljan/enrichment",
    "src/maljan/extractors",
    "apps/api/app/worker",
)

HASH = "hashes or names the sample: its digest, size or leading bytes, nothing parsed"
TRANSFER = "hands the bytes on unread: a copy, an upload, a capture written"
NOT_THE_SAMPLE = "reads no file of the sample: the process table"
NOT_REACHED = "reached by no job: the loader is never built"
LEFT = "left in the worker for now (T-006): a parse a later change moves behind the boundary"
READING = (
    "a reading's own code (tools.readers): runs on the reading's server when it is placed there"
)

# ``(file, function) -> why``: every place in the worker's code that opens a
# file's bytes itself.
ALLOWED = {
    ("apps/api/app/worker/sample_files.py", "_each_directory"): TRANSFER,
    ("apps/api/app/worker/sample_files.py", "hold_copy"): TRANSFER,
    ("apps/api/app/worker/sample_files.py", "_marker_is_the_workers"): TRANSFER,
    ("apps/api/app/worker/sample_files.py", "_open_mirror"): TRANSFER,
    ("apps/api/app/worker/sample_files.py", "private_copy"): TRANSFER,
    ("apps/api/app/worker/sample_files.py", "release_copy"): TRANSFER,
    ("apps/api/app/worker/sample_files.py", "_write_marker"): TRANSFER,
    ("src/maljan/agents/sample_staging.py", "_open_regular"): TRANSFER,
    ("src/maljan/agents/sample_staging.py", "stage_sample"): TRANSFER,
    ("src/maljan/pipeline/artefacts.py", "ArtefactStore._local_copy"): TRANSFER,
    ("src/maljan/pipeline/artefacts.py", "open_beneath"): TRANSFER,
    ("src/maljan/loaders/cape2_client.py", "CAPEv2Client.submit"): TRANSFER,
    ("src/maljan/loaders/cape2_client.py", "CAPEv2Client._write_capture"): TRANSFER,
    ("src/maljan/providers/sandbox/limits.py", "stream_to_file_capped"): TRANSFER,
    ("src/maljan/providers/sandbox/rest.py", "RestSandboxProvider.submit"): TRANSFER,
    ("src/maljan/providers/sandbox/triage.py", "TriageSandboxProvider._post_sample"): TRANSFER,
    ("src/maljan/providers/sandbox/triage.py", "TriageSandboxProvider._sha256_of"): HASH,
    ("src/maljan/loaders/mock_sandbox_client.py", "MockSandboxClient._sha256"): HASH,
    ("src/maljan/analysis/sample_integrity.py", "file_sha256"): HASH,
    ("src/maljan/reporting/ledger_projection.py", "_hashes_of"): HASH,
    ("src/maljan/app.py", "MaljanApp._infer_sample_platform"): HASH,
    ("src/maljan/providers/sandbox/formats.py", "detect_sample_format"): HASH,
    ("src/maljan/analysis/isolation.py", "environ_names"): NOT_THE_SAMPLE,
    ("src/maljan/providers/servers.py", "_start_time"): NOT_THE_SAMPLE,
    ("src/maljan/providers/servers.py", "ServerHandle._child_matches"): NOT_THE_SAMPLE,
    ("src/maljan/loaders/pe_loader.py", "_detect_file_type"): NOT_REACHED,
    ("src/maljan/loaders/pe_loader.py", "PELoader._get_strings"): NOT_REACHED,
    ("src/maljan/loaders/pe_loader.py", "PELoader._load_pe"): NOT_REACHED,
    # Routing reads a fixed header or footer to name the format.
    ("src/maljan/extractors/sample_identity.py", "_has_vhd_footer"): HASH,
    ("src/maljan/extractors/sample_identity.py", "unparsed_container_reason"): HASH,
    # The identity, hash and toolchain readings' own parsers.
    ("src/maljan/extractors/sample_identity.py", "_pe_compiler_fingerprint"): READING,
    ("src/maljan/extractors/sample_identity.py", "_extract_signing"): READING,
    ("src/maljan/extractors/sample_identity.py", "_safe_imphash"): READING,
    # The network analyst's input slice parses the capture in the worker
    # (``parsers.network_parser`` over this reader), and the report's capa and
    # YARA fallback runs when the pack recorded neither.
    ("src/maljan/analysis/capture_reader.py", "Capture.__init__"): LEFT,
    ("src/maljan/providers/static/capa_yara.py", "CapaYaraStaticProvider._run_yara"): LEFT,
    # The report's YARA draft checked against the sample.
    ("src/maljan/reporting/detection_signatures.py", "_run_on_sample"): LEFT,
    # A static provider's anti-analysis pass reads the image's sections in
    # the worker to place what the provider's scan found.
    ("src/maljan/analysis/anti_analysis.py", "image_of"): LEFT,
    ("src/maljan/providers/static/declared_prepass.py", "DeclaredScan.anti_analysis"): LEFT,
    ("src/maljan/providers/static/ghidra/passes.py", "GhidraPasses.anti_analysis"): LEFT,
    # The family-feature hint (preprocessing.use_family_feature_rag, off as shipped).
    ("src/maljan/pipeline/nodes.py", "_family_rag_candidates"): LEFT,
    ("src/maljan/agents/static_analyst.py", "StaticAnalyst._compute_family_rag_hint"): LEFT,
    ("src/maljan/extractors/pe_extractor.py", "_build_static_analysis_uncached"): LEFT,
    ("src/maljan/extractors/pe_extractor.py", "_parse_pe"): LEFT,
}

# The read modes of ``open``.
_READ_MODES = ("rb", "br", "r+b", "rb+")

# The functions of ``maljan.tools`` that read a file, which only ``tools.readers``
# calls for the pack and the analyst input.
_READING_CALLS = {
    "identify": {"identify_file", "hashes", "signing_info"},
    "binary": {"pe_info", "elf_info", "macho_info", "apk_info", "document_info", "archive_list"},
    "strings": {"strings", "iocs_from_file"},
    "rules": {"yara_scan", "capa"},
    "emulated_strings": {"recovered", "floss", "floss_unavailable"},
    "api_hashes": {"resolve_api_hashes"},
    "string_blobs": {"decode_string_blobs"},
    "crypto_constants": {"find_crypto_constants"},
    "artefact_index": {"function_index"},
    "upx": {"unpack_upx", "has_pack_header_at"},
    "pcap": {"pcap_summary"},
}


def _files() -> Iterator[Path]:
    for name in WORKER_CODE:
        path = ROOT / name
        yield from [path] if path.is_file() else sorted(path.rglob("*.py"))


# The parsers' entry points a path or a file's bytes is handed to, by the name
# called: the platform's PE reader and its anti-analysis image, pefile, the
# static-analysis builder, and a YARA match over a file.
_PARSER_CALLS = {("pe_image", "load"), ("pe_image", "parse"), ("pefile", "PE")}
_PARSER_NAMES = {"build_static_analysis", "image_of"}


def _opens(node: ast.AST) -> bool:
    """Whether ``node`` opens a file's bytes or hands them to a parser.

    ``read_bytes``, ``os.open``, ``mmap``, a read ``open``; and the parsers'
    entry points (:data:`_PARSER_CALLS`, :data:`_PARSER_NAMES`, a ``match``
    given ``filepath``).
    """
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name) and func.id in _PARSER_NAMES:
        return True
    if isinstance(func, ast.Attribute):
        if func.attr == "read_bytes" and not node.args:
            return True
        if func.attr == "mmap":
            return True
        if func.attr == "open" and isinstance(func.value, ast.Name) and func.value.id == "os":
            return True
        if func.attr in _PARSER_NAMES:
            return True
        if isinstance(func.value, ast.Name) and (func.value.id, func.attr) in _PARSER_CALLS:
            return True
        if func.attr == "match" and any(k.arg == "filepath" for k in node.keywords):
            return True
    mode: ast.AST | None = None
    if isinstance(func, ast.Name) and func.id == "open" and len(node.args) >= 2:
        mode = node.args[1]
    if isinstance(func, ast.Attribute) and func.attr == "open" and node.args:
        mode = node.args[0]
    for keyword in node.keywords:
        if keyword.arg == "mode":
            mode = keyword.value
    return isinstance(mode, ast.Constant) and mode.value in _READ_MODES


def _sites(path: Path) -> Iterator[tuple[str, int]]:
    """``(enclosing function, line)`` of every place in ``path`` that opens bytes."""

    def walk(node: ast.AST, owner: str) -> Iterator[tuple[str, int]]:
        for child in ast.iter_child_nodes(node):
            name = owner
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                name = f"{owner}.{child.name}" if owner else child.name
            if _opens(child):
                yield owner, getattr(child, "lineno", 0)
            yield from walk(child, name)

    yield from walk(ast.parse(path.read_text(encoding="utf-8")), "")


def test_the_worker_opens_bytes_only_where_the_register_says() -> None:
    found: dict[tuple[str, str], int] = {}
    for path in _files():
        for owner, line in _sites(path):
            found.setdefault((str(path.relative_to(ROOT)), owner), line)
    unlisted = sorted(
        f"{file}:{line} {owner}"
        for (file, owner), line in found.items()
        if (file, owner) not in ALLOWED
    )
    assert not unlisted, (
        "the worker opens bytes here, unlisted: place the reading behind the boundary "
        f"(tools.readers) or list it with why: {unlisted}"
    )
    # Every listed place still opens bytes, so the register never outlives its code.
    assert not set(ALLOWED) - set(found), sorted(set(ALLOWED) - set(found))


def test_the_pack_and_the_analyst_input_read_the_sample_only_through_the_readers() -> None:
    for name in ("src/maljan/pipeline/triage_pack.py", "src/maljan/pipeline/nodes.py"):
        tree = ast.parse((ROOT / name).read_text(encoding="utf-8"))
        direct = sorted(
            f"{name}:{node.lineno} {node.func.value.id}.{node.func.attr}"
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.attr in _READING_CALLS.get(node.func.value.id, ())
        )
        assert not direct, direct
        # The pack opens nothing itself; the analyst input only what the register lists.
        held = {owner for owner, _line in _sites(ROOT / name)}
        if name.endswith("triage_pack.py"):
            assert not held, held
        else:
            assert {(name, owner) for owner in held} <= set(ALLOWED), held


def test_every_reading_the_pack_names_is_a_reader() -> None:
    tree = ast.parse((ROOT / "src/maljan/pipeline/triage_pack.py").read_text(encoding="utf-8"))
    named = {
        node.args[0].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"read", "place_of"}
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    }
    assert named and named <= set(READERS), sorted(named - set(READERS))
