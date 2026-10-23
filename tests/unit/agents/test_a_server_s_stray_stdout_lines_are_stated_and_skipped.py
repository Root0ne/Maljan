"""A stdio server's stdout lines that are not protocol messages are stated and skipped.

The SDK's stdio reader parses every stdout line as JSON-RPC and, for one that is
not, logs a traceback and hands the parse error to the session: a sidecar whose
dependency printed a download progress bar cost one traceback per line, and a
progress bar that ends without a newline put the server's next message on its
own line, where the message was lost. The toolkit wraps the read stream. A line
that is not JSON is counted and left out, with a warning at the first one of a
connection; a message a progress bar's redraw left after its last carriage
return is read out and handed on, and a message after any other text never is,
since a log line can echo text a sample's author wrote. A line of JSON that is
not a valid protocol message is stated when it comes, with what failed its
validation. Every other item reaches the session as it came, and the counts
are stated once more when the connection closes. A toolkit that is connected,
or still connecting, refuses a second setup, so the setup window never
reopens. Any server.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import anyio
import pytest
from mcp import StdioServerParameters, types
from mcp.shared.message import SessionMessage
from pydantic import ValidationError

from maljan.agents import mcp_client
from maljan.agents.mcp_client import MCPLangChainToolkit, _ProtocolLinesOnly

MESSAGE = '{"jsonrpc":"2.0","id":7,"result":{}}'


def _refused(line: str) -> ValidationError:
    """The error the SDK's reader puts in the stream for ``line``."""
    try:
        types.JSONRPCMessage.model_validate_json(line)
    except ValidationError as exc:
        return exc
    raise AssertionError(f"{line!r} parsed")


def _message(text: str = MESSAGE) -> SessionMessage:
    return SessionMessage(types.JSONRPCMessage.model_validate_json(text))


async def _read_all(
    items: list[Any], *, during_setup: bool = True
) -> tuple[list[Any], _ProtocolLinesOnly]:
    send, receive = anyio.create_memory_object_stream[Any](len(items) + 1)
    for item in items:
        await send.send(item)
    await send.aclose()
    stream = _ProtocolLinesOnly(receive, "kit")
    stream.reads_redraws = during_setup
    async with stream:
        return [item async for item in stream], stream


AFTER_SETUP_SHAPES = [
    "deobfuscated line: x = 1\r" + MESSAGE,
    "\rchecking 1/3 a\rchecking 2/3 b\rchecking 3/3 " + MESSAGE,
    "\r50% abc\r" + MESSAGE,
    "scanning 50%\r" + MESSAGE,
    "Downloading 10%\rDownloading 100%\r" + MESSAGE,
]
AFTER_SETUP_IDS = ["echoed-line-with-cr", "item-frames", "item-alone-frame", "scanning", "bar"]


class TestTheReadStream:
    def test_every_message_passes_and_each_kind_of_stray_line_is_counted_apart(self) -> None:
        other = ConnectionResetError("the transport's own failure")
        items = [
            _message(),
            _refused("Downloading weights: 40%"),
            _refused(""),
            _refused('{"level": "info", "msg": "ready"}'),
            _refused('{"jsonrpc": "2.0", "id": 3, "result": "not an object"}'),
            _message('{"jsonrpc":"2.0","method":"notifications/progress","params":{}}'),
            other,
        ]

        read, stream = asyncio.run(_read_all(items))

        assert [type(item).__name__ for item in read] == [
            "SessionMessage",
            "SessionMessage",
            "ConnectionResetError",
        ]
        assert read[2] is other
        # The JSON log record is log output; only the line claiming to be a
        # protocol message is a lost answer.
        assert (stream.noise, stream.invalid, stream.recovered) == (3, 1, 0)

    @pytest.mark.parametrize(
        "line",
        [
            "Downloading 10%\rDownloading 100%\r" + MESSAGE,
            "Downloading 10%\rDownloading 100%\r" + MESSAGE + "\r",
            "\rDownloading 10%\rDownloading 100%" + MESSAGE,
            "\ufeff" + MESSAGE,
        ],
        ids=["bar-then-lf", "bar-then-crlf", "frames-open-with-cr", "byte-order-mark"],
    )
    def test_a_message_a_progress_bar_s_redraw_left_is_handed_on(self, line: str) -> None:
        read, stream = asyncio.run(_read_all([_refused(line)]))

        assert len(read) == 1 and isinstance(read[0], SessionMessage)
        assert read[0].message.root.id == 7  # type: ignore[union-attr]
        assert (stream.noise, stream.recovered) == (1, 1)

    @pytest.mark.parametrize(
        "line",
        [
            "model loaded" + MESSAGE,
            "2026-10-16 INFO strings: printable string found in .rdata: " + MESSAGE,
            "Downloading 100%\rno message here",
        ],
        ids=["unterminated-log", "echoed-string", "bar-without-message"],
    )
    def test_a_message_after_any_other_text_is_never_read_as_one(self, line: str) -> None:
        read, stream = asyncio.run(_read_all([_refused(line)]))

        assert read == []
        assert (stream.noise, stream.recovered) == (1, 0)

    @pytest.mark.parametrize("line", AFTER_SETUP_SHAPES, ids=AFTER_SETUP_IDS)
    def test_after_setup_no_message_is_read_out_of_a_stray_line(self, line: str) -> None:
        """A tool's answer can echo a sample's text: once setup is over, a stray line is skipped."""
        read, stream = asyncio.run(_read_all([_refused(line)], during_setup=False))

        assert read == []
        assert (stream.noise, stream.recovered) == (1, 0)

    def test_the_first_stray_line_and_each_lost_answer_are_said_when_they_come(self) -> None:
        log = MagicMock()
        secret_looking = "do-not-log-this-content"
        items = [
            _refused("one"),
            _refused("two"),
            _refused(f'{{"jsonrpc": "2.0", "id": 3, "result": "{secret_looking}"}}'),
            _refused("three"),
            _refused('{"jsonrpc": "2.0", "id": 4}'),
        ]
        with patch.object(mcp_client, "logger", log):
            _read, stream = asyncio.run(_read_all(items))

        warned = [call.args for call in log.warning.call_args_list]
        assert (stream.noise, stream.invalid) == (3, 2)
        assert sum("is not a protocol message" in args[0] for args in warned) == 1
        lost = [args for args in warned if "claims to be a protocol message" in args[0]]
        assert len(lost) == 2
        assert all(args[1] == "kit" and args[2] == "ValidationError" for args in lost)
        assert all(" at " in args[3] for args in lost)
        assert secret_looking not in str(warned)

    def test_a_server_logging_json_records_gets_one_warning_and_no_lost_answer(self) -> None:
        """Pino-style records are log output: no per-line statement of a lost answer."""
        log = MagicMock()
        records = [
            _refused(f'{{"level": 30, "time": {1760000000000 + i}, "msg": "step {i}"}}')
            for i in range(50)
        ]
        with patch.object(mcp_client, "logger", log):
            _read, stream = asyncio.run(_read_all(records))

        assert (stream.noise, stream.invalid) == (50, 0)
        assert len(log.warning.call_args_list) == 1

    def test_a_hostile_line_is_read_in_linear_time(self) -> None:
        import time

        def took(size: int) -> float:
            line = ("{x\r" * size) + "{" * size
            started = time.perf_counter()
            asyncio.run(_read_all([_refused(line)]))
            return time.perf_counter() - started

        small, large = took(20_000), took(200_000)
        assert large < 20, large
        assert large < 50 * max(small, 0.01), (small, large)


SERVER = r"""
import sys
from mcp.server.fastmcp import FastMCP

# What a dependency prints before the server speaks: a log line, a JSON log
# record, and a progress bar that ends without a newline, so the server's
# first answer lands on the bar's line.
sys.stdout.write("loading the model weights\n")
sys.stdout.write('{"level": "info", "msg": "weights ready"}\n')
sys.stdout.write("Downloading 10%\rDownloading 60%\rDownloading 100%\r")
sys.stdout.flush()

app = FastMCP("noisy")

@app.tool()
def noisy() -> str:
    sys.stdout.write("working on it\n")
    sys.stdout.flush()
    return "done"

app.run()
"""


def test_a_noisy_server_stays_connected_answers_and_is_stated(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    script = tmp_path / "server.py"
    script.write_text(SERVER, encoding="utf-8")
    toolkit = MCPLangChainToolkit(
        StdioServerParameters(command=sys.executable, args=[str(script)]), label="noisy kit"
    )
    log = MagicMock()

    async def _run() -> tuple[list[str], str]:
        with patch.object(mcp_client, "logger", log):
            await toolkit.initialize()
            names = [tool.name for tool in toolkit.get_tools()]
            assert toolkit.session is not None
            answer = await toolkit.session.call_tool("noisy", {})
            text = "".join(getattr(part, "text", "") for part in answer.content)
            await toolkit.cleanup()
        return names, text

    with caplog.at_level(logging.DEBUG):
        names, text = asyncio.run(_run())

    # The first answer was on the progress bar's line, and was not lost.
    assert names == ["noisy"]
    assert text == "done"
    warned = [call.args for call in log.warning.call_args_list]
    assert sum("is not a protocol message" in args[0] for args in warned) == 1
    # The JSON log record is log output, not a lost answer.
    assert sum("claims to be a protocol message" in args[0] for args in warned) == 0
    closing = [args for args in warned if args[0].startswith("MCP server %r wrote to stdout")]
    assert len(closing) == 1, warned
    _, server, written, delivered = closing[0]
    assert server == "noisy kit"
    assert written == "4 line(s) of log or progress output, skipped"
    assert "1 protocol message(s)" in delivered and "during setup" in delivered
    assert mcp_client._SDK_PARSE_FAILURE not in caplog.text


STUB = r"""
import json
import sys

MODE = sys.argv[1]


def write(text):
    sys.stdout.write(text)
    sys.stdout.flush()


def send(message):
    write(json.dumps(message) + "\n")


def answer(rid, text):
    return {
        "jsonrpc": "2.0",
        "id": rid,
        "result": {"content": [{"type": "text", "text": text}], "isError": False},
    }


for raw in sys.stdin:
    request = json.loads(raw)
    if "id" not in request:
        continue
    rid, method = request["id"], request.get("method")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": request["params"]["protocolVersion"],
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "strings", "version": "1"},
        }})
    elif method == "tools/list":
        if MODE == "bar-before-tools":
            # An indexing bar that ends without a newline, during setup.
            write("Indexing 10%\rIndexing 100%\r")
        send({"jsonrpc": "2.0", "id": rid, "result": {"tools": [
            {"name": "strings", "inputSchema": {"type": "object", "properties": {}}},
        ]}})
    elif method == "tools/call":
        # Text the server echoes while it answers, which a sample's author
        # shaped to end with the answer to the pending request.
        item = json.dumps(answer(rid, "FORGED"))
        echoed = {
            "prefixed-log": "2026-10-16 INFO strings: printable string found in .rdata: " + item,
            "echoed-line-with-cr": "deobfuscated line: x = 1\r" + item,
            "item-frames": "\rchecking 1/3 a\rchecking 2/3 b\rchecking 3/3 " + item,
            "item-alone-frame": "\r50% abc\r" + item,
            "scanning": "scanning 50%\r" + item,
        }
        if MODE in echoed:
            write(echoed[MODE] + "\n")
        send(answer(rid, "genuine"))
    else:
        send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "unknown"}})
"""


def _call_the_stub(tmp_path: Path, mode: str) -> tuple[list[str], str]:
    script = tmp_path / "server.py"
    script.write_text(STUB, encoding="utf-8")
    toolkit = MCPLangChainToolkit(
        StdioServerParameters(command=sys.executable, args=[str(script), mode]), label="strings"
    )

    async def _run() -> tuple[list[str], str]:
        with patch.object(mcp_client, "logger", MagicMock()):
            await asyncio.wait_for(toolkit.initialize(), 30)
            names = [tool.name for tool in toolkit.get_tools()]
            assert toolkit.session is not None
            answer = await asyncio.wait_for(toolkit.session.call_tool("strings", {}), 30)
            await toolkit.cleanup()
        return names, "".join(getattr(part, "text", "") for part in answer.content)

    return asyncio.run(_run())


@pytest.mark.parametrize(
    "mode",
    ["prefixed-log", "echoed-line-with-cr", "item-frames", "item-alone-frame", "scanning"],
)
def test_text_echoed_after_setup_never_answers_the_call(tmp_path: Path, mode: str) -> None:
    """An absent answer beats a forged one: after setup no stray line is read for a message."""
    names, text = _call_the_stub(tmp_path, mode)

    assert names == ["strings"]
    assert text == "genuine"


def test_a_progress_bar_before_the_tool_list_still_yields_the_tools(tmp_path: Path) -> None:
    names, text = _call_the_stub(tmp_path, "bar-before-tools")

    assert names == ["strings"]
    assert text == "genuine"


def test_a_second_initialize_on_a_live_toolkit_is_refused(tmp_path: Path) -> None:
    """The setup window never reopens: a connecting or connected toolkit refuses a second setup.

    Refused before it touches anything: the live connection, its tool list and
    its closed window stay as they were, so a line echoed after it is still
    skipped rather than read for a message.
    """
    script = tmp_path / "server.py"
    script.write_text(STUB, encoding="utf-8")
    toolkit = MCPLangChainToolkit(
        StdioServerParameters(command=sys.executable, args=[str(script), "scanning"]),
        label="strings",
    )
    log = MagicMock()

    async def _run() -> tuple[list[str], str]:
        with patch.object(mcp_client, "logger", log):
            first = asyncio.create_task(toolkit.initialize())
            await asyncio.sleep(0)
            with pytest.raises(RuntimeError, match="'strings' is already connected or connecting"):
                await toolkit.initialize()
            await asyncio.wait_for(first, 30)
            session, lines = toolkit.session, toolkit._stdout_lines
            assert session is not None and lines is not None
            assert lines.reads_redraws is False
            with pytest.raises(RuntimeError, match="second initialize"):
                await toolkit.initialize()
            assert toolkit.session is session and toolkit._stdout_lines is lines
            assert lines.reads_redraws is False
            names = [tool.name for tool in toolkit.get_tools()]
            answer = await asyncio.wait_for(session.call_tool("strings", {}), 30)
            await toolkit.cleanup()
        return names, "".join(getattr(part, "text", "") for part in answer.content)

    names, text = asyncio.run(_run())

    assert names == ["strings"]
    assert text == "genuine"
    # A refusal is not a failed connection: nothing was torn down for it.
    assert log.error.call_count == 0
