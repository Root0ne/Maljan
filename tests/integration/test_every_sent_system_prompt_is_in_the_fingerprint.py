"""Every system prompt a run sends is one the run fingerprint rendered from its builder.

The in-process rehearsal runs the real pipeline against the loopback stub
model and writes every request body the stub receives. Each system prompt in
them — whoever sent it, through whatever alias, string prompt or role
mapping — is re-rendered for the placeholder job the fingerprint renders every
prompt for (``analysis.setup_prompts``): the run's own sample hash, path and
name become the placeholder's, and the sample's format fragment the neutral
one. Its digest must then be among the digests the fingerprint keeps
(``fingerprint.texts``): a prompt the fingerprint does not render fails here,
by its text.

Skipped where what an in-process run needs is absent, as the rehearsal
checklist test is.
"""

from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("starlette", reason="the stub model is served with starlette")
pytest.importorskip("uvicorn", reason="the stub model is served with uvicorn")
pytest.importorskip("mcp", reason="the tool sidecars speak the mcp package's protocol")

from scripts.rehearsal.inprocess import Rehearsal, rehearse  # noqa: E402

from maljan.analysis.setup_prompts import (  # noqa: E402
    PLACEHOLDER_FORMAT,
    PLACEHOLDER_NAME,
    PLACEHOLDER_PATH,
    PLACEHOLDER_SHA256,
    format_fragments,
)
from maljan.core.input_meter import digest  # noqa: E402


def _loopback_binds() -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
        return True
    except OSError:
        return False


pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(not _loopback_binds(), reason="no loopback port to bind the stub on"),
]


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(str(part.get("text") or "") for part in content if isinstance(part, dict))
    return ""


def _system_prompts(body: dict[str, Any]) -> list[str]:
    """The system prompts one request body carries, on either wire."""
    found = []
    if "system" in body:
        found.append(_text(body["system"]))
    for message in body.get("messages") or []:
        if isinstance(message, dict) and message.get("role") in ("system", "developer"):
            found.append(_text(message.get("content")))
    return [text for text in found if text]


def _placeholder_job(text: str, real: dict[str, str]) -> str:
    """``text`` as the builder writes it for the placeholder job."""
    from maljan.agents.prompt_fragments import format_fragment

    neutral = format_fragment(*PLACEHOLDER_FORMAT)
    for value, placeholder in sorted(real.items(), key=lambda kv: -len(kv[0])):
        if value:
            text = text.replace(value, placeholder)
    for fragment in format_fragments():
        if fragment != neutral and fragment in text:
            text = text.replace(fragment, neutral)
    return text


@pytest.mark.parametrize("wire", ["openai", "anthropic"])
def test_every_system_prompt_the_run_sent_is_rendered_by_the_fingerprint(
    wire: str, tmp_path: Path
) -> None:
    dumps = tmp_path / "requests"
    record = asyncio.run(
        rehearse(Rehearsal(provider=wire, work_dir=tmp_path / "work", dump_dir=dumps))
    )
    fingerprint = (record.run_summary.get("efficiency") or {}).get("fingerprint") or {}
    rendered = {d for held in (fingerprint.get("texts") or {}).values() for d in held}
    assert rendered, "the run's fingerprint renders its prompts"

    samples = [p for p in (tmp_path / "work").rglob("*") if p.is_file()]
    real = {str(record.run_summary.get("file_hash") or ""): PLACEHOLDER_SHA256}
    for sample in samples:
        real[str(sample)] = PLACEHOLDER_PATH
        real[sample.name] = PLACEHOLDER_NAME

    sent: list[tuple[str, str]] = []
    for path in sorted(dumps.glob("*.json")):
        for prompt in _system_prompts(json.loads(path.read_text(encoding="utf-8"))):
            sent.append((path.name, prompt))
    assert sent, "the run sent system prompts"

    missing = [
        f"{name}: {prompt[:160]!r}"
        for name, prompt in sent
        if digest(_placeholder_job(prompt, real)) not in rendered
    ]
    assert not missing, "system prompts the fingerprint does not render:\n" + "\n".join(missing)
