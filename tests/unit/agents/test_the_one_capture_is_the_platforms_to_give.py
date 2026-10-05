"""With one capture in the job, the capture argument is the platform's to fill.

The network analyst of one live run had a capture and no way to name it: the
pack printed no arguments, the parser dropped the path on purpose, and the
argument was the model's to write. It invented four file names, eight calls
were refused, and the refusal told it to leave out an argument the tools
require. With exactly one capture the argument is hidden from the schema the
network tools are bound with and filled in, the way the sample's own path is;
with several it stays the model's, and the server's refusal lists them.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.tool_pinning import pin_paths
from maljan.pipeline.nodes import brief_agent, job_captures
from maljan.providers.sandbox_tools import sandbox_report_section
from maljan.tools import staging


class _PcapArgs(BaseModel):
    pcap_path: str
    packet_limit: int | None = None


def _tool(seen: list[dict[str, Any]], server: str = "network") -> StructuredTool:
    def _run(**kwargs: Any) -> str:
        seen.append(dict(kwargs))
        return "ok"

    return StructuredTool.from_function(
        func=_run,
        name="extract_dns",
        description="extract_dns",
        args_schema=_PcapArgs,
        infer_schema=False,
        metadata={"maljan_server": server},
    )


def _fields(tool: Any) -> set[str]:
    return set(tool.args_schema.model_fields)


class TestPinning:
    def test_one_capture_is_hidden_and_filled(self) -> None:
        seen: list[dict[str, Any]] = []
        capture = "/srv/staging/job-1/captures/run.pcap"

        [tool] = pin_paths([_tool(seen)], default_path=None, captures=(capture,))
        tool.invoke({})

        assert _fields(tool) == {"packet_limit"}
        assert seen[0]["pcap_path"] == capture

    def test_a_name_the_model_sends_anyway_does_not_replace_the_capture(self) -> None:
        seen: list[dict[str, Any]] = []
        capture = "/srv/staging/job-1/captures/run.pcap"

        [tool] = pin_paths([_tool(seen)], default_path=None, captures=(capture,))
        tool.func(pcap_path="capture.pcap")  # type: ignore[misc]

        assert seen == [{"pcap_path": capture}]

    def test_a_filled_capture_the_server_cannot_read_is_said_to_be_the_platform_s(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import json

        from maljan.tools.errors import PATH_OUTSIDE_ROOTS, tool_error

        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(tmp_path))
        capture = str(staging.job_capture_dir("abc") / "run.pcap")

        def _refuse(**_kwargs: Any) -> str:
            return json.dumps(tool_error(PATH_OUTSIDE_ROOTS, "outside", tool="extract_dns"))

        refusing = StructuredTool.from_function(
            func=_refuse,
            name="extract_dns",
            description="extract_dns",
            args_schema=_PcapArgs,
            infer_schema=False,
            metadata={"maljan_server": "network"},
        )
        [tool] = pin_paths([refusing], default_path=None, captures=(capture,))

        error = json.loads(tool.invoke({}))["error"]

        assert (
            "the platform filled pcap_path with this run's capture, captures/run.pcap"
            in (error["message"])
        )
        assert "not yours to give" in error["remediation"]
        assert str(tmp_path) not in json.dumps(error)

    def test_several_captures_leave_the_argument_to_the_model(self) -> None:
        seen: list[dict[str, Any]] = []
        original = _tool(seen)

        [tool] = pin_paths(
            [original], default_path=None, captures=("/a/captures/1.pcap", "/a/captures/2.pcap")
        )

        assert tool is original
        assert "pcap_path" in _fields(tool)

    def test_no_capture_changes_nothing(self) -> None:
        original = _tool([])

        assert pin_paths([original], default_path=None, captures=()) == [original]

    def test_a_server_an_operator_added_keeps_its_own_arguments(self) -> None:
        original = _tool([], server="operators_pcap_server")

        [tool] = pin_paths([original], default_path=None, captures=("/a/captures/1.pcap",))

        assert "pcap_path" in _fields(tool)

    def test_the_sample_and_the_capture_are_filled_together(self) -> None:
        class _Both(BaseModel):
            path: str
            pcap_path: str

        seen: list[dict[str, Any]] = []

        def _run(**kwargs: Any) -> str:
            seen.append(dict(kwargs))
            return "ok"

        both = StructuredTool.from_function(
            func=_run,
            name="t",
            description="t",
            args_schema=_Both,
            infer_schema=False,
            metadata={"maljan_server": "analysis"},
        )

        [tool] = pin_paths([both], default_path="/s/sample.exe", captures=("/c/captures/1.pcap",))
        tool.invoke({})

        assert _fields(tool) == set()
        assert seen == [{"path": "/s/sample.exe", "pcap_path": "/c/captures/1.pcap"}]


class TestTheJobsCaptures:
    @staticmethod
    def _state(capture: Path | None) -> dict[str, Any]:
        network = {"pcap_local_path": str(capture)} if capture else {}
        return {"sandbox_report": {"network": network}}

    def test_every_file_in_the_capture_directory(self, tmp_path: Path) -> None:
        captures = tmp_path / "job-1" / "captures"
        captures.mkdir(parents=True)
        (captures / "a.pcap").write_bytes(b"x")
        (captures / "b.pcap").write_bytes(b"x")

        assert job_captures(self._state(captures / "a.pcap")) == (
            str(captures / "a.pcap"),
            str(captures / "b.pcap"),
        )

    def test_none_when_the_report_names_none(self) -> None:
        assert job_captures(self._state(None)) == ()
        assert job_captures({}) == ()

    def test_the_brief_hands_them_to_every_analyst(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.pipeline import nodes

        captures = tmp_path / "job-1" / "captures"
        captures.mkdir(parents=True)
        (captures / "a.pcap").write_bytes(b"x")
        monkeypatch.setattr(nodes, "pack_text", lambda state, container: "")
        monkeypatch.setattr(nodes, "pack_ledger_ids", lambda state: [])
        monkeypatch.setattr(nodes, "render_run_state", lambda state: "")

        class _Agent:
            _captures: tuple[str, ...] = ("/stale/captures/old.pcap",)

        agent = _Agent()
        brief_agent(agent, self._state(captures / "a.pcap"), object())  # type: ignore[arg-type]
        assert agent._captures == (str(captures / "a.pcap"),)

        brief_agent(agent, self._state(None), object())  # type: ignore[arg-type]
        assert agent._captures == ()


class TestNoHostPathReachesAModel:
    def test_the_network_section_names_the_capture_relative_to_its_job(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(tmp_path))
        capture = staging.job_capture_dir("abc") / "run.pcap"
        capture.parent.mkdir(parents=True)
        capture.write_bytes(b"x")
        report = {"network": {"pcap_local_path": str(capture), "tcp": []}}

        answer = sandbox_report_section(report, "network")

        assert answer["value"]["pcap_local_path"] == "captures/run.pcap"
        assert str(tmp_path) not in str(answer)

    def test_the_job_s_captures_are_listed_by_job_relative_name(self, tmp_path: Path) -> None:
        (tmp_path / "captures").mkdir()
        (tmp_path / "captures" / "b.pcap").write_bytes(b"x")
        (tmp_path / "captures" / "a.pcap").write_bytes(b"x")

        assert staging.job_captures(tmp_path) == ["captures/a.pcap", "captures/b.pcap"]
