"""A sidecar reads the sample it was given, and nothing else on the host.

A sample is adversary-authored content that the analyst model reads — strings,
PE resources, document text — so one injected instruction turns a tool whose
documented purpose is extracting typed secrets into an arbitrary host-file
read, and the answer lands in the ledger, the report and the event feed.

Every path-taking tool on both sidecars therefore resolves its argument
(symlinks followed) and refuses anything outside the roots this deployment
named: the staging directory the sidecar writes uploads into, plus whatever
``MALJAN_SAMPLE_ROOTS`` lists. The refusal carries a code and a remedy and
names no host path, because the refusal itself travels to the model.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
ANALYSIS_SERVER = ROOT / "services" / "analysis-mcp" / "server.py"
NETWORK_SERVER = ROOT / "services" / "network-mcp" / "server.py"


def _module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def analysis() -> Any:
    return _module("analysis_mcp_server_confinement", ANALYSIS_SERVER)


@pytest.fixture(scope="module")
def network() -> Any:
    return _module("network_mcp_server_confinement", NETWORK_SERVER)


@pytest.fixture
def staging(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A staging directory of this test's own, and no other root."""
    base = tmp_path / "staging"
    base.mkdir()
    monkeypatch.setenv("MALJAN_STAGING_DIR", str(base))
    monkeypatch.delenv("MALJAN_SAMPLE_ROOTS", raising=False)
    return base


def _pe(target: Path) -> str:
    target.write_bytes(b"MZ" + b"\x00" * 128)
    return str(target)


def _refusal(answer: Any) -> dict[str, Any]:
    """The structured error out of either sidecar's answer shape."""
    parsed = json.loads(answer) if isinstance(answer, str) else answer
    assert isinstance(parsed, dict), parsed
    error = parsed.get("error")
    assert isinstance(error, dict), parsed
    return error


class TestTheStagingDirectoryIsARoot:
    def test_a_sample_staged_by_put_sample_can_be_read_back(
        self, analysis: Any, staging: Path
    ) -> None:
        import base64

        blob = b"MZ" + b"\x00" * 64
        staged = analysis.put_sample("s.bin", base64.b64encode(blob).decode())

        assert staged.get("error") is None, staged
        answer = analysis.hashes(staged["path"])

        assert answer.get("error") is None, answer
        assert answer["sha256"]

    def test_a_file_placed_under_the_staging_directory_is_read(
        self, analysis: Any, staging: Path
    ) -> None:
        answer = analysis.identify_file(_pe(staging / "sample.bin"))

        assert answer.get("error") is None, answer


class TestAPathOutsideEveryRootIsRefused:
    @pytest.mark.parametrize(
        "tool, argument",
        [
            ("identify_file", "path"),
            ("hashes", "path"),
            ("signing_info", "path"),
            ("strings", "path"),
            ("iocs_from_file", "path"),
            ("pe_info", "path"),
            ("elf_info", "path"),
            ("macho_info", "path"),
            ("apk_info", "path"),
            ("archive_list", "path"),
            ("document_info", "path"),
            ("carve_payloads", "path"),
            ("capa", "path"),
            ("yara_scan", "path"),
        ],
    )
    def test_every_path_taking_tool_refuses_etc_passwd(
        self, analysis: Any, staging: Path, tool: str, argument: str
    ) -> None:
        answer = getattr(analysis, tool)(**{argument: "/etc/passwd"})

        error = _refusal(answer)
        assert error["code"] == "path_outside_roots", (tool, answer)
        assert error["remediation"]
        assert "/etc/passwd" not in json.dumps(answer), "the refusal names a host path"

    def test_the_network_sidecar_refuses_it_too(self, network: Any, staging: Path) -> None:
        for tool in ("read_pcap_summary", "extract_dns", "extract_http", "pcap_summary"):
            answer = getattr(network, tool)("/etc/passwd")

            error = _refusal(answer)
            assert error["code"] == "path_outside_roots", (tool, answer)
            assert error["remediation"]
            assert "/etc/passwd" not in json.dumps(answer, default=str)

    def test_a_relative_climb_out_of_a_root_is_refused(
        self, analysis: Any, staging: Path, tmp_path: Path
    ) -> None:
        outside = _pe(tmp_path / "outside.bin")
        climb = str(staging / ".." / Path(outside).name)

        answer = analysis.identify_file(climb)

        assert _refusal(answer)["code"] == "path_outside_roots", answer

    def test_a_symlink_under_a_root_pointing_outside_is_refused(
        self, analysis: Any, staging: Path, tmp_path: Path
    ) -> None:
        secret = tmp_path / "id_rsa"
        secret.write_text("PRIVATE KEY")
        link = staging / "sample.bin"
        link.symlink_to(secret)

        answer = analysis.strings(str(link))

        error = _refusal(answer)
        assert error["code"] == "path_outside_roots", answer
        assert "id_rsa" not in json.dumps(answer)


class TestAConfiguredRootIsRead:
    def test_a_directory_named_in_the_environment_passes(
        self, analysis: Any, staging: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        monkeypatch.setenv("MALJAN_SAMPLE_ROOTS", str(corpus))

        answer = analysis.identify_file(_pe(corpus / "sample.bin"))

        assert answer.get("error") is None, answer

    def test_the_list_is_colon_separated(
        self, analysis: Any, staging: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first = tmp_path / "one"
        second = tmp_path / "two"
        first.mkdir()
        second.mkdir()
        monkeypatch.setenv("MALJAN_SAMPLE_ROOTS", f"{first}:{second}")

        assert analysis.identify_file(_pe(second / "s.bin")).get("error") is None

    def test_a_root_reached_through_a_symlink_is_still_a_root(
        self, analysis: Any, staging: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The roots are resolved too, so a symlinked mirror directory works."""
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)
        monkeypatch.setenv("MALJAN_SAMPLE_ROOTS", str(link))

        assert analysis.identify_file(_pe(real / "s.bin")).get("error") is None

    def test_a_missing_file_under_a_root_is_a_missing_file(
        self, analysis: Any, staging: Path
    ) -> None:
        """Confinement answers about the root, not about existence."""
        answer = analysis.identify_file(str(staging / "absent.bin"))

        assert _refusal(answer)["code"] == "no_such_file", answer


class TestARulesetNamesACorpus:
    """``ruleset`` is a path the model chooses too, and it names a rule corpus.

    Held to the rule directories rather than to the sample ones, and held at
    the server rather than in ``maljan.tools.rules``: an in-process caller
    passes the corpus it built, and the trust boundary is the server.
    """

    def test_the_shipped_corpus_is_read(self, analysis: Any, staging: Path) -> None:
        answer = analysis.yara_scan(text="anything", ruleset="default")

        assert answer.get("error") is None, answer
        assert answer["rule_count"] > 0, "the shipped corpus loaded"

    def test_a_corpus_under_the_data_tree_is_read(self, analysis: Any, staging: Path) -> None:
        answer = analysis.yara_scan(text="anything", ruleset="data/yara_ttp_rules.yaml")

        assert answer.get("error") is None, answer
        assert answer["rule_count"] > 0

    def test_an_operator_s_own_corpus_is_read(
        self, analysis: Any, staging: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The environment override is set on the server, not passed to it."""
        corpus = tmp_path / "our-rules.yaml"
        corpus.write_text("rules: []\n")
        monkeypatch.setenv("MALJAN_YARA_RULES_DIR", str(corpus))

        answer = analysis.yara_scan(text="anything", ruleset=str(corpus))

        assert answer.get("error") is None, answer

    @pytest.mark.parametrize("named", ["/etc/passwd", "data/../../../../etc/passwd"])
    def test_a_corpus_outside_the_rule_directories_is_refused(
        self, analysis: Any, staging: Path, named: str
    ) -> None:
        answer = analysis.yara_scan(text="anything", ruleset=named)

        assert _refusal(answer)["code"] == "path_outside_roots", answer

    def test_the_sigma_tools_are_held_to_it_too(self, analysis: Any, staging: Path) -> None:
        for answer in (
            analysis.sigma_match([], ruleset="/etc"),
            analysis.sigma_match_sandbox({}, ruleset="/etc"),
        ):
            assert _refusal(answer)["code"] == "path_outside_roots", answer


class TestTheWorkerNamesTheDirectoriesItWritesTo:
    """A default deployment configures nothing: the worker says where it put the sample."""

    def test_the_download_directory_and_the_mirrors_are_exported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.worker import sample_files
        from maljan.tools.roots import configured_roots

        monkeypatch.delenv("MALJAN_SAMPLE_ROOTS", raising=False)
        monkeypatch.setattr(sample_files.settings, "samples_dir", str(tmp_path / "samples"))
        monkeypatch.setattr(sample_files.settings, "upload_temp_dir", str(tmp_path / "uploads"))

        exported = sample_files.export_sample_roots()

        roots = {str(root) for root in configured_roots()}
        assert str(tmp_path / "uploads") in roots
        assert str(tmp_path / "samples" / ".work") in roots
        assert {str(path) for path in exported} == roots

    def test_a_sample_under_an_exported_root_is_read(
        self, analysis: Any, staging: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.worker import sample_files

        monkeypatch.delenv("MALJAN_SAMPLE_ROOTS", raising=False)
        monkeypatch.setattr(sample_files.settings, "samples_dir", str(tmp_path / "samples"))
        monkeypatch.setattr(sample_files.settings, "upload_temp_dir", str(tmp_path / "uploads"))
        downloads = sample_files.export_sample_roots()[0]

        assert analysis.identify_file(_pe(downloads / "s.bin")).get("error") is None

    def test_the_same_directory_is_not_named_twice(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.worker import sample_files
        from maljan.tools.roots import configured_roots

        monkeypatch.delenv("MALJAN_SAMPLE_ROOTS", raising=False)
        monkeypatch.setattr(sample_files.settings, "samples_dir", str(tmp_path / "samples"))
        monkeypatch.setattr(sample_files.settings, "upload_temp_dir", str(tmp_path / "uploads"))

        sample_files.export_sample_roots()
        sample_files.export_sample_roots()

        roots = [str(root) for root in configured_roots()]
        assert len(roots) == len(set(roots))


class TestTheWriteSideKeepsItsOwnConfinement:
    def test_put_sample_writes_under_the_staging_directory(
        self, analysis: Any, staging: Path
    ) -> None:
        import base64

        answer = analysis.put_sample("../escape.bin", base64.b64encode(b"MZ").decode())

        assert answer.get("error") is None, answer
        assert Path(answer["path"]).parent == staging.resolve()

    def test_carved_payloads_land_under_the_staging_directory(
        self, analysis: Any, staging: Path
    ) -> None:
        answer = analysis.carve_payloads(_pe(staging / "carve-me.bin"))

        assert answer.get("error") is None, answer
        assert (staging / "carved").is_dir()


class TestAnArgumentIsBoundedBeforeItIsRead:
    """What a tool will materialise, decided before it materialises it.

    ``put_sample`` base64-decoded the whole argument into memory and *then*
    applied the sample ceiling, so a 4 GiB argument was held twice over before
    being refused; the chunked route was bounded per chunk and in total but not
    in the number of uploads in flight; and the two rule tools took their
    wall clock straight from the model, above the value their own manifest
    declares.
    """

    def test_an_oversized_single_shot_upload_is_refused_before_it_is_decoded(
        self, analysis: Any, staging: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import base64

        decoded: list[int] = []
        real = base64.b64decode

        def _counting(value: Any, validate: bool = False) -> bytes:
            decoded.append(len(value))
            return real(value, validate=validate)

        monkeypatch.setattr(analysis.base64, "b64decode", _counting)
        monkeypatch.setattr(analysis, "_MAX_SAMPLE_BYTES", 16)

        answer = analysis.put_sample("s.bin", "A" * 4096)

        assert answer["error"]["code"] == "bad_argument"
        assert decoded == [], "the argument was decoded before it was refused"

    def test_an_oversized_chunk_is_refused_before_it_is_decoded(
        self, analysis: Any, staging: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import base64

        decoded: list[int] = []
        real = base64.b64decode

        def _counting(value: Any, validate: bool = False) -> bytes:
            decoded.append(len(value))
            return real(value, validate=validate)

        started = analysis.put_sample_begin("s.bin", "", 1024)
        monkeypatch.setattr(analysis.base64, "b64decode", _counting)
        monkeypatch.setattr(analysis, "_MAX_CHUNK_BYTES", 16)

        answer = analysis.put_sample_chunk(started["upload_id"], 0, "A" * 4096)

        assert answer["error"]["code"] == "bad_argument"
        assert decoded == []

    def test_uploads_in_flight_are_capped_by_count(
        self, analysis: Any, staging: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(analysis, "_MAX_UPLOADS", 2)
        analysis._UPLOADS.clear()

        first = analysis.put_sample_begin("a.bin", "", 8)
        second = analysis.put_sample_begin("b.bin", "", 8)
        third = analysis.put_sample_begin("c.bin", "", 8)

        assert first["upload_id"] and second["upload_id"]
        assert third["error"]["code"] == "bad_argument"
        assert len(analysis._UPLOADS) == 2
        analysis._UPLOADS.clear()

    def test_a_ruleset_timeout_cannot_exceed_the_declared_one(
        self, analysis: Any, staging: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked: list[int] = []

        def _fake_scan(**kwargs: Any) -> dict[str, Any]:
            asked.append(int(kwargs["timeout_s"]))
            return {"matches": [], "rule_count": 0, "filtered": 0}

        monkeypatch.setattr(analysis.rule_tools, "yara_scan", _fake_scan)

        analysis.yara_scan(text="x", timeout_s=86_400)
        analysis.yara_scan(text="x", timeout_s=5)
        analysis.yara_scan(text="x", timeout_s=-1)

        assert asked == [analysis.YARA_TIMEOUT_S, 5, 1]

    def test_a_capa_timeout_cannot_exceed_the_declared_one(
        self, analysis: Any, staging: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked: list[int] = []

        def _fake_capa(**kwargs: Any) -> dict[str, Any]:
            asked.append(int(kwargs["timeout_s"]))
            return {"capabilities": [], "meta": {}}

        monkeypatch.setattr(analysis.rule_tools, "capa", _fake_capa)

        analysis.capa(_pe(staging / "s.bin"), timeout_s=86_400)

        assert asked == [analysis.CAPA_TIMEOUT_S]

    def test_the_declared_timeout_is_what_the_manifest_says(self, analysis: Any) -> None:
        declared = {tool["name"]: tool.get("timeout_s") for tool in analysis.CAPABILITIES["tools"]}
        assert declared["yara_scan"] == analysis.YARA_TIMEOUT_S
        assert declared["capa"] == analysis.CAPA_TIMEOUT_S

    def test_carving_never_holds_the_whole_sample_in_memory(
        self, analysis: Any, staging: Path
    ) -> None:
        """The digest that names the carve directory is read in chunks."""
        import hashlib
        import inspect

        source = inspect.getsource(analysis._carve_under_staging)
        assert "read_bytes()" not in source

        blob = b"MZ" + b"\x00" * 4096
        sample = staging / "big.bin"
        sample.write_bytes(blob)

        answer = analysis.carve_payloads(str(sample))

        assert answer.get("error") is None, answer
        assert (staging / "carved" / hashlib.sha256(blob).hexdigest()).is_dir()


class TestACaptureIsReadInBoundedPieces:
    def test_every_packet_walking_tool_takes_a_limit(self, network: Any) -> None:
        import inspect

        for tool in ("read_pcap_summary", "extract_dns", "extract_http", "pcap_summary"):
            parameters = inspect.signature(getattr(network, tool)).parameters
            assert "packet_limit" in parameters, tool
            assert int(parameters["packet_limit"].default) > 0, tool

    def test_the_limit_reaches_the_reader(
        self, network: Any, staging: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``rdpcap`` with no count reads the whole capture into memory."""
        asked: list[Any] = []

        def _fake_rdpcap(path: str, count: int = -1) -> list[Any]:
            asked.append(count)
            return []

        monkeypatch.setattr(network, "rdpcap", _fake_rdpcap)
        monkeypatch.setattr(network, "_SCAPY_MISSING", None)
        capture = staging / "c.pcap"
        capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

        network.extract_dns(str(capture))
        network.extract_http(str(capture), packet_limit=7)

        assert asked == [network.DEFAULT_PACKET_LIMIT, 7]
