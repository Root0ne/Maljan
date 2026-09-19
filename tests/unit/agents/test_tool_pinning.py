"""The path guard, and the per-server path a remote tool server was given.

``test_configurable_analyst`` covers the guard as that analyst sees it. What is
here is the shared function it now delegates to, and the half that is new: a
tool from a server the sample was uploaded to must be called with *that*
server's path, not the worker's.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.tool_pinning import is_path_argument, pin_paths, server_of

LOCAL = "/data/samples/abc123.exe"
REMOTE = "/remote/staging/abc123.exe"
# What a real staging directory looks like: the sidecar prefixes the digest, so
# the remote basename is *not* the local one. The pair above shares a basename
# and cannot tell a working guard from a broken one.
STAGED = "/remote/staging/30e555b6093af9fd_evil.exe"
HOST = "/data/samples/evil.exe"


class _Args(BaseModel):
    file_path: str = ""
    query: str = ""


class _PcapArgs(BaseModel):
    """A qualified path argument: it names a capture, not the sample."""

    pcap_path: str = ""


def _tool(
    name: str,
    seen: list[dict[str, Any]],
    server: str = "",
    schema: type[BaseModel] = _Args,
) -> StructuredTool:
    def _run(**kwargs: Any) -> str:
        seen.append(dict(kwargs))
        return "ok"

    return StructuredTool.from_function(
        func=_run,
        name=name,
        description=name,
        args_schema=schema,
        infer_schema=False,
        metadata={"maljan_server": server} if server else None,
    )


class TestIsPathArgument:
    def test_a_name_that_says_path_or_file_qualifies(self) -> None:
        assert all(
            is_path_argument(n) for n in ("path", "file", "file_path", "filename", "target_file")
        )

    def test_the_exact_set_covers_names_that_hold_a_file_without_saying_so(self) -> None:
        assert all(is_path_argument(n) for n in ("binary", "sample", "target", "program"))

    def test_free_text_arguments_are_left_alone(self) -> None:
        assert not any(is_path_argument(n) for n in ("query", "input", "text", "rule"))


class TestPinPaths:
    def test_with_no_pin_the_tools_come_back_unwrapped(self) -> None:
        seen: list[dict[str, Any]] = []
        tool = _tool("identify_file", seen)
        assert pin_paths([tool], default_path=None) == [tool]

    def test_a_bare_basename_in_a_path_argument_becomes_the_absolute_path(self) -> None:
        seen: list[dict[str, Any]] = []
        pinned = pin_paths([_tool("identify_file", seen)], default_path=LOCAL)

        pinned[0].invoke({"file_path": "abc123.exe"})

        assert seen == [{"file_path": LOCAL, "query": ""}]

    def test_a_wrong_directory_with_the_right_file_name_is_corrected(self) -> None:
        """A live run sent the sample's own name under a directory whose name
        the model had mistyped, and every call after it read "no such file"."""
        seen: list[dict[str, Any]] = []
        pinned = pin_paths([_tool("identify_file", seen)], default_path=LOCAL)

        pinned[0].invoke({"file_path": "/home/user/Belleges/kingston/abc123.exe"})

        assert seen[0]["file_path"] == LOCAL

    def test_a_directory_that_holds_such_a_file_is_left_exactly_as_it_is(
        self, tmp_path: Any
    ) -> None:
        """The correction is for a path that leads nowhere. A model that named
        a file which is really there named that file."""
        elsewhere = tmp_path / "abc123.exe"
        elsewhere.write_bytes(b"MZ")
        seen: list[dict[str, Any]] = []
        pinned = pin_paths([_tool("identify_file", seen)], default_path=LOCAL)

        pinned[0].invoke({"file_path": str(elsewhere)})

        assert seen[0]["file_path"] == str(elsewhere)

    def test_another_file_name_under_a_missing_directory_is_left_alone(self) -> None:
        seen: list[dict[str, Any]] = []
        pinned = pin_paths([_tool("identify_file", seen)], default_path=LOCAL)

        pinned[0].invoke({"file_path": "/elsewhere/other.exe"})

        assert seen[0]["file_path"] == "/elsewhere/other.exe"

    def test_a_free_text_argument_holding_the_name_is_not_rewritten(self) -> None:
        seen: list[dict[str, Any]] = []
        pinned = pin_paths([_tool("search", seen)], default_path=LOCAL)

        pinned[0].invoke({"query": "abc123.exe"})

        assert seen[0]["query"] == "abc123.exe"

    def test_the_wrapper_is_a_new_tool_and_the_original_is_untouched(self) -> None:
        """The resolved tool is shared with the registry; wrapping in place
        would leak this sample's path into the next agent that borrows it."""
        seen: list[dict[str, Any]] = []
        original = _tool("identify_file", seen)

        pinned = pin_paths([original], default_path=LOCAL)

        assert pinned[0] is not original
        original.invoke({"file_path": "abc123.exe"})
        assert seen[0]["file_path"] == "abc123.exe", "the original keeps its own behaviour"


class TestPerServerPaths:
    def test_a_tool_from_a_staged_server_gets_that_server_s_path(self) -> None:
        seen: list[dict[str, Any]] = []
        pinned = pin_paths(
            [_tool("identify_file", seen, server="analysis")],
            default_path=LOCAL,
            path_by_server={"analysis": REMOTE},
        )

        pinned[0].invoke({"file_path": "abc123.exe"})

        assert seen[0]["file_path"] == REMOTE

    def test_a_tool_from_an_unstaged_server_keeps_the_local_path(self) -> None:
        seen: list[dict[str, Any]] = []
        pinned = pin_paths(
            [_tool("read_pcap_summary", seen, server="network")],
            default_path=LOCAL,
            path_by_server={"analysis": REMOTE},
        )

        pinned[0].invoke({"file_path": "abc123.exe"})

        assert seen[0]["file_path"] == LOCAL

    def test_two_servers_in_one_tool_set_get_two_different_paths(self) -> None:
        local_seen: list[dict[str, Any]] = []
        remote_seen: list[dict[str, Any]] = []
        pinned = pin_paths(
            [
                _tool("read_pcap_summary", local_seen, server="network"),
                _tool("identify_file", remote_seen, server="analysis"),
            ],
            default_path=LOCAL,
            path_by_server={"analysis": REMOTE},
        )

        for tool in pinned:
            tool.invoke({"file_path": "abc123.exe"})

        assert local_seen[0]["file_path"] == LOCAL
        assert remote_seen[0]["file_path"] == REMOTE

    def test_a_per_server_path_alone_is_enough_to_wrap(self) -> None:
        """No worker-side path at all — a run whose sample only ever existed on
        the remote server — still substitutes for that server."""
        seen: list[dict[str, Any]] = []
        pinned = pin_paths(
            [_tool("identify_file", seen, server="analysis")],
            default_path=None,
            path_by_server={"analysis": REMOTE},
        )

        pinned[0].invoke({"file_path": "abc123.exe"})

        assert seen[0]["file_path"] == REMOTE

    def test_the_name_the_prompt_showed_is_corrected_to_the_name_the_server_has(
        self,
    ) -> None:
        """The regression that matters. The staged file is
        ``30e555b6093af9fd_evil.exe`` and the prompt header showed the model
        ``/data/samples/evil.exe``, so the model sends ``evil.exe`` — a name
        that appears nowhere in the staged path. A guard matching only the
        target's basename waits for a spelling the model was never given, and
        the whole static tool surface goes unprotected."""
        seen: list[dict[str, Any]] = []
        pinned = pin_paths(
            [_tool("identify_file", seen, server="analysis")],
            default_path=HOST,
            path_by_server={"analysis": STAGED},
        )

        pinned[0].invoke({"file_path": "evil.exe"})

        assert seen[0]["file_path"] == STAGED

    def test_the_staged_basename_is_corrected_too(self) -> None:
        """A model that did read the staged name back still gets an absolute
        path: a bare ``30e555b6093af9fd_evil.exe`` resolves against the
        server's working directory, not its staging directory."""
        seen: list[dict[str, Any]] = []
        pinned = pin_paths(
            [_tool("identify_file", seen, server="analysis")],
            default_path=HOST,
            path_by_server={"analysis": STAGED},
        )

        pinned[0].invoke({"file_path": "30e555b6093af9fd_evil.exe"})

        assert seen[0]["file_path"] == STAGED

    def test_the_full_worker_path_is_rewritten_for_a_server_that_cannot_open_it(
        self,
    ) -> None:
        """The model obeyed the prompt exactly and sent the worker path. A
        remote server cannot open it, so obedience must not be punished."""
        seen: list[dict[str, Any]] = []
        pinned = pin_paths(
            [_tool("identify_file", seen, server="analysis")],
            default_path=HOST,
            path_by_server={"analysis": STAGED},
        )

        pinned[0].invoke({"file_path": HOST})

        assert seen[0]["file_path"] == STAGED

    def test_an_unrelated_file_name_is_left_alone_on_a_qualified_argument(self) -> None:
        """Widening the match set must not widen it to every string: a tool
        reading a capture or a rule file keeps the name it was given."""
        seen: list[dict[str, Any]] = []
        pinned = pin_paths(
            [_tool("read_pcap_summary", seen, server="network", schema=_PcapArgs)],
            default_path=HOST,
            path_by_server={"network": STAGED},
        )

        pinned[0].invoke({"pcap_path": "capture.pcap"})

        assert seen[0]["pcap_path"] == "capture.pcap"

    def test_the_server_stamp_survives_the_wrap(self) -> None:
        seen: list[dict[str, Any]] = []
        pinned = pin_paths([_tool("identify_file", seen, server="analysis")], default_path=LOCAL)
        assert server_of(pinned[0]) == "analysis"


class TestTheRegistryStampsTheServer:
    def test_merge_tools_records_which_server_each_tool_came_from(self) -> None:
        from maljan.core.config import Settings
        from maljan.providers.servers import ServerRegistry

        registry = ServerRegistry(Settings(_env_file=None))
        seen: list[dict[str, Any]] = []
        tools: list[Any] = []

        registry.merge_tools("analysis", [_tool("identify_file", seen)], tools, {})

        assert server_of(tools[0]) == "analysis"

    def test_a_renamed_tool_is_stamped_with_the_server_that_renamed_it(self) -> None:
        from maljan.core.config import Settings
        from maljan.providers.servers import ServerRegistry

        registry = ServerRegistry(Settings(_env_file=None))
        seen_calls: list[dict[str, Any]] = []
        tools: list[Any] = []
        claimed: dict[str, str] = {}

        registry.merge_tools("analysis", [_tool("identify_file", seen_calls)], tools, claimed)
        registry.merge_tools("other", [_tool("identify_file", seen_calls)], tools, claimed)

        assert [t.name for t in tools] == ["identify_file", "other__identify_file"]
        assert [server_of(t) for t in tools] == ["analysis", "other"]


class _PathArgs(BaseModel):
    """``vt-mcp``'s ``submit_local_file`` signature: one plain ``path``."""

    path: str = ""


class TestTheVirustotalStdioUpload:
    """``submit_local_file`` takes ``path``, and the guard has to cover it.

    The stdio form of VirusTotal's server is the only way to upload a sample
    by path, and a model that calls it with the bare file name uploads
    nothing. The argument is named ``path`` and nothing else, which is the
    narrowest name the guard recognises, so it is worth pinning that it does.
    """

    def _tool(self, seen: list[dict[str, Any]]) -> StructuredTool:
        def _run(**kwargs: Any) -> str:
            seen.append(dict(kwargs))
            return "ok"

        return StructuredTool.from_function(
            func=_run,
            name="submit_local_file",
            description="upload a local file to VirusTotal",
            args_schema=_PathArgs,
            infer_schema=False,
            metadata={"maljan_server": "virustotal"},
        )

    def test_a_bare_file_name_becomes_the_path_the_server_can_open(self) -> None:
        seen: list[dict[str, Any]] = []
        pinned = pin_paths([self._tool(seen)], default_path=HOST)

        pinned[0].invoke({"path": "evil.exe"})

        assert seen[0]["path"] == HOST

    def test_a_staged_server_gets_the_path_the_sample_was_uploaded_to(self) -> None:
        seen: list[dict[str, Any]] = []
        pinned = pin_paths(
            [self._tool(seen)],
            default_path=HOST,
            path_by_server={"virustotal": STAGED},
        )

        pinned[0].invoke({"path": HOST})

        assert seen[0]["path"] == STAGED
