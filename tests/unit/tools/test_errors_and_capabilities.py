"""A tool failure names its remedy, and a server says what it can do before a run.

The error shape is read both ways: the structured one the sidecars write and
the flat one every implementation still writes. The manifest is computed by
probing, so a module that is not there is reported as not there with the
reason the import gave.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import pytest

from maljan.tools import capabilities as caps
from maljan.tools import errors
from maljan.tools.errors import (
    BAD_ARGUMENT,
    MISSING_DEPENDENCY,
    NO_SUCH_FILE,
    REMEDIATIONS,
    TIMEOUT,
    TOOL_FAILED,
    UNSUPPORTED_FORMAT,
    code_for_exception,
    error_parts,
    error_sentence,
    normalise_error,
    tool_error,
)


class TestTheErrorShape:
    def test_a_structured_error_carries_code_message_and_remedy(self) -> None:
        payload = tool_error(MISSING_DEPENDENCY, "olefile is not installed", tool="document_info")
        assert payload == {
            "error": {
                "code": "missing_dependency",
                "message": "olefile is not installed",
                "remediation": REMEDIATIONS[MISSING_DEPENDENCY],
            },
            "tool": "document_info",
        }

    def test_an_authored_remedy_wins_over_the_code_s(self) -> None:
        payload = tool_error(
            TIMEOUT, "capa overran", remediation="raise static.capa.timeout_seconds"
        )
        assert payload["error"]["remediation"] == "raise static.capa.timeout_seconds"

    def test_a_code_this_module_does_not_know_is_kept(self) -> None:
        payload = tool_error("rate_limited", "429 from the service")
        assert payload["error"]["code"] == "rate_limited"
        assert payload["error"]["remediation"] == REMEDIATIONS[TOOL_FAILED]

    def test_the_flat_shape_is_still_read(self) -> None:
        assert error_parts({"error": "pefile is not installed", "tool": "pe_info"}) == (
            MISSING_DEPENDENCY,
            "pefile is not installed",
            None,
        )
        assert error_parts({"error": "no such file: /x"})[0] == NO_SUCH_FILE
        assert error_parts({"error": "not a PE file (no MZ magic)"})[0] == UNSUPPORTED_FORMAT
        assert error_parts({"error": "capa produced no result within its budget"})[0] == TIMEOUT
        assert error_parts({"error": "TypeError: missing argument"})[0] == BAD_ARGUMENT
        assert error_parts({"error": "something else entirely"})[0] == TOOL_FAILED

    def test_the_mcp_client_s_marker_is_read(self) -> None:
        text = (
            '{"tool_error": "exception", "tool": "strings", '
            '"type": "RuntimeError", "detail": "boom"}'
        )
        code, message, remedy = error_parts(text)
        assert message == "exception: boom" and remedy is None and code == TOOL_FAILED

    def test_an_answer_is_not_an_error(self) -> None:
        assert error_parts({"strings": ["a"]}) is None
        assert error_parts({"error": ""}) is None
        assert error_parts("plain text") is None
        assert error_parts(None) is None

    def test_normalising_a_flat_error_gives_it_the_code_s_remedy(self) -> None:
        out = normalise_error({"error": "olefile is not installed", "tool": "document_info"})
        assert out["error"] == {
            "code": MISSING_DEPENDENCY,
            "message": "olefile is not installed",
            "remediation": REMEDIATIONS[MISSING_DEPENDENCY],
        }
        assert out["tool"] == "document_info"

    def test_normalising_leaves_an_answer_and_a_complete_error_alone(self) -> None:
        answer = {"imports": []}
        assert normalise_error(answer) is answer
        complete = tool_error(TIMEOUT, "slow", remediation="wait")
        assert normalise_error(complete) is complete

    def test_the_sentence_a_reason_carries(self) -> None:
        assert error_sentence(tool_error(NO_SUCH_FILE, "no such file: /s")) == (
            f"no such file: /s; {REMEDIATIONS[NO_SUCH_FILE]}"
        )
        assert error_sentence({"error": "plain"}) == "plain"

    def test_exceptions_map_to_codes(self) -> None:
        assert code_for_exception(ImportError("x")) == MISSING_DEPENDENCY
        assert code_for_exception(FileNotFoundError("x")) == NO_SUCH_FILE
        assert code_for_exception(TimeoutError()) == TIMEOUT
        assert code_for_exception(ValueError("bad")) == BAD_ARGUMENT
        assert code_for_exception(RuntimeError("boom")) == TOOL_FAILED


class TestTheManifest:
    def test_a_tool_with_no_requirement_is_available(self) -> None:
        manifest = caps.manifest("x", [caps.ToolNeeds("hashes")], version="1")
        assert manifest == {
            "server": "x",
            "version": "1",
            "tools": [
                {
                    "name": "hashes",
                    "optional_dependency": None,
                    "available": True,
                    "reason": None,
                    "timeout_s": None,
                }
            ],
        }

    def _cell_for_a_failing_import(self, monkeypatch, raised: Exception) -> dict:
        real_import = caps.importlib.import_module

        def _import(name, *args, **kwargs):
            if name == "olefile":
                raise raised
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(caps.importlib, "import_module", _import)
        monkeypatch.delitem(sys.modules, "olefile", raising=False)
        return caps.manifest(
            "analysis",
            [caps.ToolNeeds("document_info", (caps.module("olefile"),), without="the PDF half")],
            version="1",
        )["tools"][0]

    def test_a_missing_module_is_reported_with_the_import_s_own_words(self, monkeypatch) -> None:
        cell = self._cell_for_a_failing_import(
            monkeypatch, ModuleNotFoundError("No module named 'olefile'")
        )
        assert cell["available"] is False
        assert cell["optional_dependency"] == "olefile"
        assert cell["reason"] == "olefile is not installed (No module named 'olefile')"
        assert cell["remediation"] == REMEDIATIONS[MISSING_DEPENDENCY]
        assert cell["without"] == "the PDF half"

    def test_a_broken_import_names_its_type_and_no_path_on_this_host(self, monkeypatch) -> None:
        """This reason reaches a probe response, the console and the judge's prompt."""
        cell = self._cell_for_a_failing_import(
            monkeypatch,
            ImportError("cannot import name x from y (/tmp/secretpath/y.py)"),
        )
        assert cell["available"] is False
        assert cell["reason"] == "olefile is not installed (ImportError)"
        assert "/" not in str(cell["reason"])

    def test_a_shared_library_that_will_not_load_leaks_nothing_either(self, monkeypatch) -> None:
        cell = self._cell_for_a_failing_import(
            monkeypatch, OSError("libyara.so.4: cannot open shared object file: /usr/lib/x")
        )
        assert cell["reason"] == "olefile is not installed (OSError)"
        assert "/" not in str(cell["reason"])

    def test_a_present_module_is_available(self) -> None:
        cell = caps.manifest("x", [caps.ToolNeeds("j", (caps.module("json"),))], version="1")
        assert cell["tools"][0]["available"] is True

    def test_a_setting_is_probed_from_the_environment(self, monkeypatch) -> None:
        monkeypatch.delenv("MALJAN_TEST_KEY", raising=False)
        cell = caps.manifest(
            "t", [caps.ToolNeeds("k", (caps.env("MALJAN_TEST_KEY"),))], version="1"
        )
        assert cell["tools"][0]["available"] is False
        assert cell["tools"][0]["reason"] == "MALJAN_TEST_KEY is not configured"
        assert "Settings" in cell["tools"][0]["remediation"]
        monkeypatch.setenv("MALJAN_TEST_KEY", "x")
        cell = caps.manifest(
            "t", [caps.ToolNeeds("k", (caps.env("MALJAN_TEST_KEY"),))], version="1"
        )
        assert cell["tools"][0]["available"] is True

    def test_a_binary_is_probed_on_path(self, monkeypatch) -> None:
        monkeypatch.setattr(caps.shutil, "which", lambda name: None)
        cell = caps.manifest("t", [caps.ToolNeeds("c", (caps.binary("capa"),))], version="1")
        assert cell["tools"][0]["reason"] == "capa is not on PATH"

    def test_the_timeout_travels(self) -> None:
        cell = caps.manifest("t", [caps.ToolNeeds("capa", timeout_s=300)], version="1")
        assert cell["tools"][0]["timeout_s"] == 300


class TestServerCapabilities:
    def _payload(self) -> dict:
        return {
            "server": "analysis",
            "version": "1.0",
            "tools": [
                {"name": "hashes", "available": True, "reason": None},
                {
                    "name": "document_info",
                    "available": False,
                    "reason": "olefile is not installed",
                    "remediation": "uv sync --extra tools",
                },
            ],
        }

    def test_it_reads_a_manifest_and_its_json_text(self) -> None:
        parsed = caps.ServerCapabilities.from_payload("analysis", self._payload())
        assert parsed is not None and parsed.version == "1.0"
        assert set(parsed.tools) == {"hashes", "document_info"}
        from_text = caps.ServerCapabilities.from_payload("analysis", json.dumps(self._payload()))
        assert from_text is not None and from_text.tools == parsed.tools

    def test_anything_else_is_not_a_manifest(self) -> None:
        assert caps.ServerCapabilities.from_payload("x", "not json") is None
        assert caps.ServerCapabilities.from_payload("x", {"error": "no"}) is None
        assert caps.ServerCapabilities.from_payload("x", '{"tools": "nope"}') is None

    def test_the_unavailable_tools_become_degradation_reasons(self) -> None:
        parsed = caps.ServerCapabilities.from_payload("analysis", self._payload())
        assert parsed is not None
        (missing,) = parsed.unavailable()
        assert missing.degradation_reason == (
            "server.analysis.document_info_unavailable(olefile is not installed); "
            "uv sync --extra tools"
        )
        assert parsed.unavailable(["hashes"]) == []
        assert [u.tool for u in parsed.unavailable(["document_info", "unknown"])] == [
            "document_info"
        ]

    @pytest.mark.parametrize("server", ["analysis", "knowledge", "network", "threatintel"])
    def test_each_built_in_sidecar_computes_a_manifest_at_import(self, server: str) -> None:
        import importlib.util
        from pathlib import Path

        path = Path(__file__).resolve().parents[3] / "services" / f"{server}-mcp" / "server.py"
        spec = importlib.util.spec_from_file_location(f"{server}_mcp_server", path)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        manifest = module.capabilities()
        assert manifest["server"] == server
        names = {cell["name"] for cell in manifest["tools"]}
        declared = {
            name
            for name in dir(module)
            if not name.startswith("_") and callable(getattr(module, name))
        }
        # Every tool the server registers is in its manifest, and the
        # manifest names no tool the server does not have.
        registered = {t.name for t in module.mcp._tool_manager.list_tools()}
        assert names == registered - {caps.CAPABILITIES_TOOL}, (server, names ^ registered)
        assert declared >= names
        self._timeouts_match_the_tools(module, manifest, server)

    def _timeouts_match_the_tools(self, module: Any, manifest: dict, server: str) -> None:
        """What the manifest declares is what the tool actually gives itself.

        Two shapes of real timeout. A tool that takes one as an argument
        declares that argument's default; a server whose every tool reaches
        the network under one client budget declares that budget. A cell that
        says ``null`` for a tool that gives up after a minute is the one
        structure whose premise is that it was computed lying about it.
        """
        import inspect

        declared = {cell["name"]: cell["timeout_s"] for cell in manifest["tools"]}
        shared = getattr(module, "HTTP_TIMEOUT_S", None)
        for name, said in declared.items():
            tool = getattr(module, name, None)
            if tool is None:
                continue
            parameter = inspect.signature(tool).parameters.get("timeout_s")
            if parameter is not None and parameter.default is not inspect.Parameter.empty:
                assert said == parameter.default, (server, name, said, parameter.default)
            elif shared is not None and "check_" in name:
                assert said == shared, (server, name, said, shared)
            else:
                assert said is None, (server, name, said)


class TestTheThreatIntelSidecarAnswersAFailureAsOne:
    """A lookup that timed out is not an answer that happens to say "timeout".

    These four tools answer with prose, so a failure written as prose reads to
    every consumer as a successful call: it never reaches the run summary's
    failures, the report header or the console's failed row. The structured
    shape is what tells them apart.
    """

    @pytest.fixture(scope="class")
    @classmethod
    def server(cls) -> Any:
        import importlib.util
        from pathlib import Path

        path = Path(__file__).resolve().parents[3] / "services" / "threatintel-mcp" / "server.py"
        spec = importlib.util.spec_from_file_location("threatintel_mcp_server", path)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module

    def _raising(self, server: Any, monkeypatch, exc: Exception) -> None:
        class _Client:
            def __init__(self, **_: Any) -> None:
                pass

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *_: Any) -> None:
                return None

            def get(self, *_: Any, **__: Any) -> Any:
                raise exc

        monkeypatch.setattr(server.httpx, "Client", _Client)

    def test_a_timeout_is_a_structured_failure_with_its_remedy(
        self, server: Any, monkeypatch
    ) -> None:
        import httpx

        self._raising(server, monkeypatch, httpx.TimeoutException("slow"))

        answer = errors.error_parts(server._vt_hash_lookup("ab" * 32))

        assert answer is not None
        code, message, remediation = answer
        assert code == errors.TIMEOUT
        assert "VirusTotal did not answer" in message and remediation

    def test_a_bad_status_is_a_structured_failure(self, server: Any, monkeypatch) -> None:
        import httpx

        request = httpx.Request("GET", "https://example.test")
        response = httpx.Response(429, request=request)
        self._raising(
            server, monkeypatch, httpx.HTTPStatusError("x", request=request, response=response)
        )

        answer = errors.error_parts(server._abuseipdb_lookup("1.2.3.4"))

        assert answer is not None
        assert answer[0] == errors.TOOL_FAILED and "429" in answer[1]

    def test_two_sources_that_both_failed_answer_as_one_failure(
        self, server: Any, monkeypatch
    ) -> None:
        """A structured error joined to a sentence parses as neither."""
        import httpx

        self._raising(server, monkeypatch, httpx.TimeoutException("slow"))
        failed = server._vt_ip_lookup("1.2.3.4")

        joined = server._joined([failed, failed], "check_ip_reputation")

        answer = errors.error_parts(joined)
        assert answer is not None and answer[0] == errors.TIMEOUT

    def test_one_source_that_answered_keeps_the_answer_prose(
        self, server: Any, monkeypatch
    ) -> None:
        import httpx

        self._raising(server, monkeypatch, httpx.TimeoutException("slow"))
        failed = server._vt_ip_lookup("1.2.3.4")

        joined = server._joined([failed, "IP 1.2.3.4 (TR): clean."], "check_ip_reputation")

        assert errors.error_parts(joined) is None, "the call answered"
        assert "{" not in joined, "no JSON document is glued to the sentence"
        assert "did not answer" in joined and "clean." in joined

    def test_a_failure_is_never_cached(self, server: Any, monkeypatch) -> None:
        """The cache has no expiry, so one timeout would be replayed for ever."""
        import httpx

        self._raising(server, monkeypatch, httpx.TimeoutException("slow"))
        server._cache.clear()

        server._set_cache("ip", "1.2.3.4", server._vt_ip_lookup("1.2.3.4"))

        assert server._check_cache("ip", "1.2.3.4") is None
        server._set_cache("ip", "1.2.3.4", "IP 1.2.3.4: clean.")
        assert server._check_cache("ip", "1.2.3.4") == "IP 1.2.3.4: clean."

    def test_a_lookup_that_found_nothing_is_still_an_answer(self, server: Any, monkeypatch) -> None:
        """VirusTotal having nothing on a hash is a result, not a failed call."""

        class _Client:
            def __init__(self, **_: Any) -> None:
                pass

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *_: Any) -> None:
                return None

            def get(self, *_: Any, **__: Any) -> Any:
                import httpx

                return httpx.Response(404, request=httpx.Request("GET", "https://example.test"))

        monkeypatch.setattr(server.httpx, "Client", _Client)

        text = server._vt_hash_lookup("ab" * 32)

        assert errors.error_parts(text) is None
        assert "not found in VirusTotal" in text
