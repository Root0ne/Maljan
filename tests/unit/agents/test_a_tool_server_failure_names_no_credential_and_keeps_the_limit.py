"""A tool server's failure names no credential, and its words are held to the output limit.

The toolkit logged a network server's URL whole and a stdio server's
arguments as they were, and handed an exception's message to the ledger and
the model as it came: a URL's user name and password, a query's token and an
``--api-key`` all went with them. An ``isError`` reply's text and an
exception's message also skipped the output limit every answer is held to,
so a server could put any amount of text in front of the model by failing.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from mcp import StdioServerParameters
from mcp.types import CallToolResult, TextContent

from maljan.agents.mcp_client import TRUNCATION_MARKER, MCPLangChainToolkit
from maljan.core.truncation_ledger import TruncationLedger
from tests.credential_shapes import password


class _Session:
    def __init__(self, answer: Any) -> None:
        self._answer = answer

    async def call_tool(self, name: str, arguments: dict[str, Any], **_: Any) -> Any:
        if isinstance(self._answer, Exception):
            raise self._answer
        return self._answer


def _toolkit(answer: Any, **kwargs: Any) -> MCPLangChainToolkit:
    toolkit = MCPLangChainToolkit(None, **kwargs)
    toolkit.session = _Session(answer)  # type: ignore[assignment]
    return toolkit


class TestNoCredentialIsNamed:
    def test_a_network_server_is_logged_by_its_host(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        secret = password()
        url = f"https://op:{secret}@sandbox.example:8443/mcp?token={secret}"

        def _refuse(target: str, headers: Any = None) -> Any:
            raise ConnectionError(f"could not connect to {target}")

        import mcp.client.streamable_http as transport

        monkeypatch.setattr(transport, "streamablehttp_client", _refuse)
        toolkit = MCPLangChainToolkit(None, transport="http", http_url=url, label="sandbox")
        with caplog.at_level("INFO"), pytest.raises(ConnectionError):
            asyncio.run(toolkit.initialize())

        assert secret not in caplog.text
        assert "https://sandbox.example:8443" in caplog.text

    def test_a_stdio_server_s_credential_arguments_are_masked(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        secret = password()

        def _refuse(params: Any) -> Any:
            raise OSError("cannot start")

        monkeypatch.setattr("maljan.agents.mcp_client.stdio_client", _refuse)
        params = StdioServerParameters(command="tool-server", args=["--api-key", secret, "--v"])
        toolkit = MCPLangChainToolkit(params)
        with caplog.at_level("INFO"), pytest.raises(OSError):
            asyncio.run(toolkit.initialize())

        assert secret not in caplog.text
        assert "tool-server" in caplog.text and "--api-key" in caplog.text

    def test_an_exception_s_url_credential_reaches_neither_the_ledger_nor_the_log(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        secret = password()
        url = f"https://op:{secret}@sandbox.example/mcp"
        toolkit = _toolkit(ConnectionError(f"lost {url} mid-call"), transport="http", http_url=url)

        with caplog.at_level("WARNING"):
            marker = asyncio.run(toolkit._call("lookup", {}, ()))

        assert secret not in marker
        assert secret not in caplog.text
        detail = json.loads(marker)["detail"]
        assert "lost" in detail and "mid-call" in detail, "the message is still said"


class TestAnErrorIsHeldToTheLimit:
    def test_an_is_error_reply_longer_than_the_limit_is_cut_and_counted(self) -> None:
        ledger = TruncationLedger()
        reply = CallToolResult(content=[TextContent(type="text", text="x" * 5000)], isError=True)
        toolkit = _toolkit(reply, max_output_chars=400, truncation_ledger=ledger)

        marker = asyncio.run(toolkit._call("lookup", {}, ()))

        assert len(marker) <= 400
        parsed = json.loads(marker)
        assert parsed["tool_error"] == "tool_returned_error"
        assert TRUNCATION_MARKER in parsed["detail"]
        assert ledger.tool_output_hard_truncated == 1

    def test_an_exception_message_longer_than_the_limit_is_cut(self) -> None:
        toolkit = _toolkit(ValueError('"' * 3000), max_output_chars=300)

        marker = asyncio.run(toolkit._call("lookup", {}, ()))

        assert len(marker) <= 300
        parsed = json.loads(marker)
        assert parsed["type"] == "ValueError"
        assert TRUNCATION_MARKER in parsed["detail"]

    def test_an_error_within_the_limit_is_handed_on_whole(self) -> None:
        reply = CallToolResult(
            content=[TextContent(type="text", text="quota exceeded")], isError=True
        )
        marker = asyncio.run(_toolkit(reply, max_output_chars=400)._call("lookup", {}, ()))
        assert json.loads(marker)["detail"] == "quota exceeded"


class TestEveryArgumentShapeIsMasked:
    def test_a_credential_assignment_or_header_is_masked_whatever_flag_precedes_it(self) -> None:
        from maljan.core.settings_masking import masked_args

        secret = password()
        args = [
            "run",
            "-e",
            f"API_KEY={secret}",
            f"TOKEN={secret}",
            f"--env=DB_PASSWORD={secret}",
            "-H",
            f"Authorization: Bearer {secret}",
            "--header",
            f"X-Api-Key: {secret}",
            f"X-Auth-Token:{secret}",
            "-e",
            "LOG_LEVEL=debug",
            "Accept: text/plain",
            "https://host.example/path",
        ]
        masked = masked_args(args)
        assert secret not in " ".join(masked)
        assert masked[2] == "API_KEY=***"
        assert masked[4] == "--env=DB_PASSWORD=***"
        assert masked[6] == "Authorization: ***"
        assert masked[-4:] == [
            "-e",
            "LOG_LEVEL=debug",
            "Accept: text/plain",
            "https://host.example/path",
        ], "what names no credential is kept"


class TestEveryCredentialHeaderIsMasked:
    def test_a_cookie_and_a_secret_header_are_masked(self) -> None:
        from maljan.core.settings_masking import masked_args

        secret = password()
        masked = masked_args(["-H", f"Cookie: sid={secret}", "-H", f"X-Client-Secret: {secret}"])
        assert secret not in " ".join(masked)
        assert masked[1] == "Cookie: ***"


class TestTheServersOwnUrlIsNamedByItsHost:
    def _said(self, server: str, text: str) -> str:
        toolkit = MCPLangChainToolkit(None, transport="sse", http_url=server)
        return toolkit._said(ConnectionError(text))

    def test_a_path_keyed_url_is_replaced_whole(self) -> None:
        key = password()
        said = self._said(f"https://mcp.example/{key}/sse", f"lost https://mcp.example/{key}/sse")
        assert key not in said
        assert said == "lost https://mcp.example"

    def test_a_re_normalised_url_is_still_the_server_s(self) -> None:
        key = password()
        said = self._said(
            f"https://mcp.example/{key}/sse", f"GET HTTPS://MCP.Example:443/{key}/sse/ failed"
        )
        assert key not in said
        assert "failed" in said

    def test_a_quoted_url_ends_at_its_quote_and_a_double_encoded_one_is_read(self) -> None:
        key = password()
        said = self._said(
            f"https://mcp.example/{key}/sse",
            f'lost "https://mcp.example/{key}/sse", retry (https://mcp.example/{key}/sse)',
        )
        assert key not in said
        assert said == 'lost "https://mcp.example", retry (https://mcp.example)'
        secret = password(variant=1)
        twice = f"https%253A%252F%252Fop%253A{secret}%2540other.example%252Fx"
        said = self._said("https://mcp.example/sse", f"redirect to {twice}")
        assert secret not in said

    def test_a_server_at_an_ipv6_literal_is_recognised(self) -> None:
        key = password()
        said = self._said(f"http://[::1]:8080/{key}/sse", f"lost http://[::1]:8080/{key}/sse")
        assert key not in said
        assert said == "lost http://[::1]:8080"

    def test_a_decoded_control_character_is_written_out(self) -> None:
        said = self._said("https://mcp.example/sse", "bad%0D%0AFAKE LOG LINE%1b[31m")
        assert "\r" not in said and "\n" not in said and "\x1b" not in said
        assert "FAKE LOG LINE" in said

    def test_an_encoded_url_is_decoded_then_masked(self) -> None:
        secret = password()
        said = self._said(
            "https://mcp.example/sse",
            f"redirect to https%3A%2F%2Fop%3A{secret}%40other.example%2Fx refused",
        )
        assert secret not in said
        assert "other.example" in said


class TestAnErrorKeepsItsHeadAndTail:
    def test_both_ends_are_kept_with_the_marker_between(self) -> None:
        detail = "HEAD-" + "x" * 5000 + "-TAIL"
        reply = CallToolResult(content=[TextContent(type="text", text=detail)], isError=True)
        marker = asyncio.run(_toolkit(reply, max_output_chars=400)._call("lookup", {}, ()))
        held = json.loads(marker)["detail"]
        assert len(marker) <= 400
        assert held.startswith("HEAD-") and held.endswith("-TAIL")
        assert TRUNCATION_MARKER in held

    def test_an_is_error_reply_s_url_credential_is_masked(self) -> None:
        secret = password()
        text = f"denied for https://op:{secret}@store.example/x"
        reply = CallToolResult(content=[TextContent(type="text", text=text)], isError=True)
        marker = asyncio.run(_toolkit(reply, max_output_chars=4000)._call("lookup", {}, ()))
        assert secret not in marker
        assert "denied for" in marker
