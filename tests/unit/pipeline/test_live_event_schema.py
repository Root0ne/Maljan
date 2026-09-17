"""The shape of every event the live conversation is drawn from.

One test per type, because the console switches on the type and reads the
fields by name: a field that quietly changes spelling is a bubble that stops
drawing, and nothing else in the suite would notice.

``seq`` is deliberately absent from all of it. It is assigned by the
publisher, which is the only place that knows the job; an event emitted here
carries none, and a test that expected one would be pinning a second counter
into existence.
"""

from __future__ import annotations

from typing import Any

from maljan.pipeline import events as ev


def _sink() -> tuple[list[tuple[str, dict[str, Any]]], ev.EventSink]:
    recorded: list[tuple[str, dict[str, Any]]] = []

    def sink(event_type: str, data: dict[str, Any]) -> None:
        recorded.append((event_type, data))

    return recorded, sink


class TestAgentMessage:
    def test_a_plain_line_is_a_says_line(self) -> None:
        recorded, sink = _sink()
        ev.emit_agent_message(sink, speaker="static", role="analyst", text="hello")
        (event_type, data) = recorded[0]
        assert event_type == "agent_message"
        assert data["kind"] == "says"
        assert "display_name" not in data
        assert "seq" not in data

    def test_the_new_fields_travel_when_they_are_given(self) -> None:
        recorded, sink = _sink()
        ev.emit_agent_message(
            sink,
            speaker="lead",
            role="analyst",
            text="check the imports",
            stage="analysis",
            addressed_to="static",
            kind="delegation_ask",
            display_name="Lead analyst",
        )
        data = recorded[0][1]
        assert data["stage"] == "analysis"
        assert data["addressed_to"] == "static"
        assert data["kind"] == "delegation_ask"
        assert data["display_name"] == "Lead analyst"

    def test_an_unknown_kind_is_recorded_as_a_plain_line(self) -> None:
        recorded, sink = _sink()
        ev.emit_agent_message(sink, speaker="s", role="analyst", text="t", kind="whistles")
        assert recorded[0][1]["kind"] == "says"

    def test_every_kind_the_console_draws_is_accepted(self) -> None:
        for kind in ev.MESSAGE_KINDS:
            recorded, sink = _sink()
            ev.emit_agent_message(sink, speaker="s", role="analyst", text="t", kind=kind)
            assert recorded[0][1]["kind"] == kind


class TestToolCalls:
    def test_the_start_names_the_call_and_summarises_its_arguments(self) -> None:
        recorded, sink = _sink()
        ev.emit_tool_call_started(
            sink,
            stage="analysis",
            agent="static",
            tool="strings",
            server="analysis-mcp",
            args_summary="pattern=http",
        )
        (event_type, data) = recorded[0]
        assert event_type == "tool_call_started"
        assert set(data) == {"stage", "agent", "tool", "server", "args_summary"}
        assert data["server"] == "analysis-mcp"

    def test_an_in_process_tool_has_no_server(self) -> None:
        recorded, sink = _sink()
        ev.emit_tool_call_started(sink, stage="triage_pack", agent="pipeline", tool="pe_info")
        assert recorded[0][1]["server"] is None

    def test_the_finish_carries_the_ledger_id_the_result_is_under(self) -> None:
        recorded, sink = _sink()
        ev.emit_tool_call_finished(
            sink,
            stage="analysis",
            agent="static",
            tool="strings",
            server=None,
            evidence_id="ev_0007",
            ok=False,
            duration_ms=1234,
            summary="tool call failed",
        )
        (event_type, data) = recorded[0]
        assert event_type == "tool_call_finished"
        assert set(data) == {
            "stage",
            "agent",
            "tool",
            "server",
            "evidence_id",
            "ok",
            "duration_ms",
            "summary",
        }
        assert data["evidence_id"] == "ev_0007"
        assert data["ok"] is False
        assert data["duration_ms"] == 1234

    def test_a_negative_duration_is_not_published(self) -> None:
        recorded, sink = _sink()
        ev.emit_tool_call_finished(
            sink, stage="s", agent="a", tool="t", evidence_id="ev_0001", duration_ms=-5
        )
        assert recorded[0][1]["duration_ms"] == 0


class TestArgumentSummaries:
    def test_nothing_that_reads_like_a_credential_travels(self) -> None:
        summary = ev.summarize_args(
            {
                "api_key": "sk-real-secret-value",
                "auth_token": "Bearer abcdef",
                "password": "hunter2",
                "url": "https://vt.example/api",
            }
        )
        assert "sk-real-secret-value" not in summary
        assert "abcdef" not in summary
        assert "hunter2" not in summary
        assert summary.count("***") == 3

    def test_a_host_path_is_cut_to_the_file_it_names(self) -> None:
        summary = ev.summarize_args({"path": "/home/operator/maljan/data/samples/ab12/evil.exe"})
        assert summary == "path=evil.exe"
        assert "/home/operator" not in summary

    def test_a_windows_path_is_cut_the_same_way(self) -> None:
        assert ev.summarize_args({"path": r"C:\\Users\\op\\samples\\evil.exe"}) == "path=evil.exe"

    def test_a_long_value_is_capped(self) -> None:
        summary = ev.summarize_args({"pattern": "word " * 200})
        assert len(summary) <= ev.ARGUMENT_SUMMARY_CHARS
        assert summary.endswith("…")

    def test_a_url_with_userinfo_and_no_path_still_loses_the_userinfo(self) -> None:
        summary = ev.summarize_args({"endpoint": "https://operator:hunter2@vt.example"})
        assert "hunter2" not in summary
        assert "operator" not in summary
        assert summary == "endpoint=https://vt.example/…"

    def test_a_url_query_never_travels(self) -> None:
        summary = ev.summarize_args({"url": "https://vt.example/v3/files?apikey=SECRETKEY"})
        assert "SECRETKEY" not in summary
        assert summary == "url=https://vt.example/…"

    def test_a_bearer_value_under_a_neutral_name_is_replaced(self) -> None:
        summary = ev.summarize_args({"header": "Bearer abc123"})
        assert "abc123" not in summary
        assert summary == "header=Bearer ***"

    def test_a_hex_key_under_a_neutral_name_is_replaced(self) -> None:
        summary = ev.summarize_args({"query": "a1b2c3d4e5f60718293a4b5c6d7e8f90"})
        assert summary == "query=***"

    def test_a_vendor_key_prefix_is_replaced_wherever_it_appears(self) -> None:
        summary = ev.summarize_args({"value": "sk-liveKey", "note": "nvapi-abc"})
        assert summary == "value=***, note=***"

    def test_a_command_line_loses_every_host_path_it_names(self) -> None:
        summary = ev.summarize_args(
            {"cmd": "/opt/maljan/bin/run.sh /home/op/data/samples/ab12/evil.exe --out /tmp/x/r.json"}
        )
        assert "/home/op" not in summary
        assert "/opt/maljan" not in summary
        assert "/tmp/x" not in summary
        assert summary == "cmd=run.sh evil.exe --out r.json"

    def test_a_short_word_is_left_alone(self) -> None:
        assert ev.summarize_args({"pattern": "http", "start": 0}) == "pattern=http, start=0"

    def test_many_arguments_are_counted_rather_than_listed(self) -> None:
        summary = ev.summarize_args({f"k{i}": i for i in range(10)})
        assert "+4 more" in summary

    def test_nested_values_are_shaped_rather_than_dumped(self) -> None:
        summary = ev.summarize_args({"hashes": ["a", "b", "c"], "opts": {"deep": True}})
        assert summary == "hashes=<3 items>, opts=<1 keys>"

    def test_no_arguments_is_an_empty_summary(self) -> None:
        assert ev.summarize_args({}) == ""
        assert ev.summarize_args(None) == ""

    def test_a_result_summary_is_one_capped_line(self) -> None:
        summary = ev.summarize_result("first line\nsecond line " + "word " * 200)
        assert "\n" not in summary
        assert len(summary) <= ev.RESULT_SUMMARY_CHARS

    def test_a_result_that_echoes_a_key_is_scrubbed_like_an_argument(self) -> None:
        summary = ev.summarize_result("called with sk-liveKeyValue against https://u:p@vt.example")
        assert "sk-liveKeyValue" not in summary
        assert "u:p@" not in summary

    def test_a_failure_says_what_would_fix_it_and_not_what_broke(self) -> None:
        summary = ev.summarize_result(
            "FileNotFoundError: /home/operator/maljan/data/samples/ab12/evil.exe is missing",
            ok=False,
            remediation="submit the sample again",
        )
        assert "/home/operator" not in summary
        assert "FileNotFoundError" not in summary
        assert summary == "the call failed; submit the sample again"

    def test_a_failure_with_no_remediation_still_says_nothing_raw(self) -> None:
        summary = ev.summarize_result("Traceback: /etc/maljan/secrets.env", ok=False)
        assert summary == "the call failed"


class TestValidationFeedback:
    def test_the_correction_names_its_code_and_its_retry(self) -> None:
        recorded, sink = _sink()
        ev.emit_validation_feedback(
            sink,
            stage="analysis",
            agent="static",
            code="technique_unknown",
            message="T9999 is not in the catalogue",
            retry_index=1,
        )
        (event_type, data) = recorded[0]
        assert event_type == "validation_feedback"
        assert set(data) == {"stage", "agent", "code", "message", "retry_index"}
        assert data["retry_index"] == 1


class TestJudgeQuestion:
    def test_a_question_to_the_room_is_addressed_to_nobody(self) -> None:
        recorded, sink = _sink()
        ev.emit_judge_question(sink, stage="verdict", text="Which import set is this?")
        (event_type, data) = recorded[0]
        assert event_type == "judge_question"
        assert set(data) == {"stage", "text", "addressed_to"}
        assert data["addressed_to"] is None

    def test_a_question_to_one_agent_names_it(self) -> None:
        recorded, sink = _sink()
        ev.emit_judge_question(sink, stage="verdict", text="Confirm.", addressed_to="static")
        assert recorded[0][1]["addressed_to"] == "static"


class TestDeltas:
    def test_a_delta_carries_the_new_text_only(self) -> None:
        recorded, sink = _sink()
        ev.emit_agent_message_delta(sink, stage="analysis", agent="static", text_delta="partial")
        (event_type, data) = recorded[0]
        assert event_type == "agent_message_delta"
        assert set(data) == {"stage", "agent", "text_delta"}

    def test_an_empty_delta_is_not_an_event(self) -> None:
        recorded, sink = _sink()
        ev.emit_agent_message_delta(sink, stage="analysis", agent="static", text_delta="")
        assert recorded == []


class TestRoster:
    def _profile(self) -> dict[str, Any]:
        return {
            "label": "Default",
            "stages": [
                {"key": "triage_pack", "label": "Triage pack", "kind": "triage", "agents": []},
                {
                    "key": "analysis",
                    "label": "Analysis",
                    "kind": "analysis",
                    "agents": ["static", "dynamic"],
                },
                {"key": "verdict", "label": "Verdict", "kind": "verdict", "agents": ["judge"]},
            ],
        }

    def _definitions(self) -> dict[str, Any]:
        return {
            "static": {"role": "static", "label": "Static analyst"},
            "dynamic": {"role": "dynamic", "label": "Dynamic analyst"},
            "judge": {"role": "judge", "label": "Judge"},
        }

    def test_every_stage_and_every_speaker_is_listed(self) -> None:
        payload = ev.roster_payload(self._profile(), self._definitions())
        assert [s["key"] for s in payload["stages"]] == ["triage_pack", "analysis", "verdict"]
        assert [a["key"] for a in payload["agents"]] == ["static", "dynamic", "judge"]
        assert payload["agents"][0]["label"] == "Static analyst"
        assert payload["agents"][0]["stages"] == ["analysis"]

    def test_an_agent_in_two_stages_is_listed_once_with_both(self) -> None:
        profile = self._profile()
        profile["stages"].append(
            {"key": "second", "label": "Second look", "kind": "analysis", "agents": ["static"]}
        )
        payload = ev.roster_payload(profile, self._definitions())
        statics = [a for a in payload["agents"] if a["key"] == "static"]
        assert len(statics) == 1
        assert statics[0]["stages"] == ["analysis", "second"]

    def test_an_agent_with_no_definition_falls_back_to_its_key(self) -> None:
        payload = ev.roster_payload(self._profile(), {})
        assert payload["agents"][0] == {
            "key": "static",
            "label": "static",
            "role": "",
            "stages": ["analysis"],
        }

    def test_the_models_and_the_stored_documents_give_the_same_roster(self) -> None:
        from maljan.core.config import _builtin_definitions, _builtin_profiles

        profiles = _builtin_profiles()
        definitions = _builtin_definitions()
        from_models = ev.roster_payload(profiles["default"], definitions)
        from_documents = ev.roster_payload(
            profiles["default"].model_dump(mode="json"),
            {k: d.model_dump(mode="json") for k, d in definitions.items()},
        )
        assert from_models == from_documents

    def test_the_roster_is_emitted_under_its_own_type(self) -> None:
        recorded, sink = _sink()
        ev.emit_roster(sink, ev.roster_payload(self._profile(), self._definitions()))
        assert recorded[0][0] == "roster"
        assert set(recorded[0][1]) == {"agents", "stages"}
