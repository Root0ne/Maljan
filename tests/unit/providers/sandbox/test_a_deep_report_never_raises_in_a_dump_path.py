"""A report nested 10,000 levels deep never raises in any path that writes it out.

The upload is read (each container below the guard read as the mark), laid
out, sliced for the analysts, answered by every sandbox tool, indexed and
recorded by the pack, and its run model written out as the worker writes it.
A document nested as deeply in process (never read from a body) is written
out by the same paths with the mark below the guard.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from maljan.core.config import Settings
from maljan.core.safe_json import DEEPER_MARK, DEPTH_GUARD
from maljan.providers.sandbox.upload import UploadSandboxProvider
from maljan.schemas.sandbox_document import sandbox_document

DEPTH = 10_000


def _deep_text(depth: int = DEPTH) -> str:
    return "[" * depth + '"bottom"' + "]" * depth


def _cape_body() -> bytes:
    deep = _deep_text()
    return (
        '{"info": {"id": 9, "version": "CAPE 2"}, "CAPE": {"payloads": []},'
        ' "target": {"file": {"sha256": "' + "c" * 64 + '"}},'
        ' "behavior": {"processes": [{"pid": 1, "ppid": 0, "process_name": "a.exe",'
        ' "calls": [{"api": "X", "arguments": ' + deep + "}]}],"
        ' "summary": {"files": [' + deep + "]}},"
        ' "network": {"dns": [{"request": "deep-z.example", "answers": ' + deep + "}]},"
        ' "signatures": [{"name": "s", "data": ' + deep + "}],"
        ' "extra_block": ' + deep + "}"
    ).encode()


def _unread_body() -> bytes:
    return ('{"deep": ' + _deep_text() + ', "meta": {"k": 1}}').encode()


def _depth(value: Any) -> int:
    deepest = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict | list):
            deepest = max(deepest, depth)
            children = node.values() if isinstance(node, dict) else node
            stack.extend((child, depth + 1) for child in children)
    return deepest


def _provider(body: bytes, recorded: str, allowed: list[str]) -> Any:
    cfg = Settings(
        _env_file=None, sandbox={"provider": "upload", "upload": {"allowed_formats": allowed}}
    )  # type: ignore[call-arg]
    provider = UploadSandboxProvider.from_settings(cfg)
    provider.set_pending_blob(body, report_format=recorded)
    return provider


def _deep_in_process() -> dict[str, Any]:
    node: Any = "bottom"
    for _ in range(DEPTH):
        node = [node]
    return {
        "target": {"sha256": "c" * 64},
        "behavior": {"processes": [{"pid": 1, "process_name": "a", "calls": [node]}]},
        "network": {"dns": [{"request": "deep-z.example", "answers": node}]},
        "signatures": [{"name": "s", "data": node}],
        "channels": {"report.deep": node},
        "extra_block": node,
    }


def _every_dump(
    document: dict[str, Any], tmp_path: Path, sources: tuple[str, ...] = ()
) -> list[str]:
    """Each path that writes ``document`` or a part of it out, as the text it wrote."""
    from maljan.agents.evidence_recorder import result_text
    from maljan.analysis import sandbox_sections as ss
    from maljan.app import MaljanApp
    from maljan.providers import sandbox_tools as st

    texts: list[str] = []
    app = MaljanApp(mock=True)
    slices = sources or ("sandbox.target", "sandbox.network", "sandbox.behavior", "sandbox.full")
    for source in slices:
        chunks = app.container._sandbox_slice("dynamic", source, document)
        texts.append(" ".join(chunk.content for chunk in chunks))

    class _Sizer:
        def _apply_output_guardrail(self, text: str, narrowing: Any) -> str:
            return text

    for name in (
        "sandbox_processes",
        "sandbox_network",
        "sandbox_signatures",
        "sandbox_dropped_files",
        "sandbox_registry_ops",
        "sandbox_api_calls",
        "sandbox_mutexes",
        "sandbox_services_and_tasks",
        "sandbox_channels",
    ):
        func = getattr(st, name)
        texts.append(st._sized(func, _Sizer())(document))
        texts.append(result_text(func(document)))
    for key in document:
        texts.append(result_text(st.sandbox_report_section(document, key)))
    sections = ss.Sections(document)
    for section in ("processes", "network", "signatures", "channels"):
        texts.append(result_text(sections.query(section).items))
    texts.append(result_text(ss.section_index(document)))
    return texts


class TestADeepUpload:
    @pytest.mark.parametrize(
        ("body", "recorded", "allowed"),
        [(_cape_body(), "cape2", ["cape2"]), (_unread_body(), "unread", ["unread"])],
        ids=["cape2", "unread"],
    )
    def test_it_is_read_marked_and_written_out_everywhere(
        self, body: bytes, recorded: str, allowed: list[str], tmp_path: Path
    ) -> None:
        with pytest.raises(RecursionError):
            json.loads(body)
        run = _provider(body, recorded, allowed).fetch("uploaded")
        document = sandbox_document(run.report)
        assert _depth(document) <= DEPTH_GUARD + 1
        texts = _every_dump(document, tmp_path)
        assert any(DEEPER_MARK in text for text in texts)
        # The run model, as the worker stores it.
        assert run.model_dump_json()
        if recorded == "cape2":
            assert "deep-z.example" in " ".join(texts)


def test_a_document_nested_as_deeply_in_process_is_written_out_marked(tmp_path: Path) -> None:
    document = _deep_in_process()
    with pytest.raises(RecursionError):
        json.dumps(document)
    # Built in process, never read from a body, it reaches only the paths that
    # write it out as JSON: the whole-report slice, the tool answers, the pack's
    # sections. (A document from any body is marked when the body is read.)
    texts = _every_dump(document, tmp_path, sources=("sandbox.target", "sandbox.full"))
    assert any(DEEPER_MARK in text for text in texts)
    for text in texts:
        if text.startswith(("{", "[")):
            json.loads(text)


def test_the_pack_indexes_and_records_a_deep_upload(tmp_path: Path) -> None:
    from maljan.agents.evidence_recorder import EvidenceRecorder
    from maljan.pipeline.triage_pack import PIPELINE, run_pack
    from maljan.schemas.evidence import EvidenceCounter
    from tests.unit.pipeline.test_triage_pack import _inputs, _write
    from tests.unit.tools.test_binary import _pe

    for body, recorded in ((_cape_body(), "cape2"), (_unread_body(), "unread")):
        run = _provider(body, recorded, [recorded]).fetch("uploaded")
        document = sandbox_document(run.report)
        recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
        path = _write(tmp_path, "s.exe", _pe())
        result = run_pack(
            recorder,
            _inputs(
                path, "pe", sandbox_report=document, sandbox_normalised_by=("upload", recorded, "")
            ),
        )
        assert result.entries
        for entry in result.entries:
            assert entry.model_dump_json()
