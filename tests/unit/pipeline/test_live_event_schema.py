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

    def test_a_hex_run_that_is_not_a_digest_is_replaced(self) -> None:
        # 34 characters: longer than the rule's floor, and not the length of
        # any digest, so there is nothing to say it is not a key.
        summary = ev.summarize_args({"query": "a1b2c3d4e5f60718293a4b5c6d7e8f90ab"})
        assert summary == "query=***"

    def test_the_sample_hash_survives_under_any_name(self) -> None:
        # The subject of the analysis, not a secret: it is on the job, on the
        # report and in ``pipeline_started`` already, and a bubble reading
        # ``hash=***`` cannot say which artifact a lookup was for.
        md5 = "44d88612fea8a8f36de82e1278abb02f"
        sha1 = "3395856ce81f2b7382dee72602f798b642f14140"
        sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        assert ev.summarize_args({"hash": md5}) == f"hash={md5}"
        assert ev.summarize_args({"query": sha1}) == f"query={sha1}"
        assert ev.summarize_args({"value": sha256}) == f"value={sha256}"

    def test_a_digest_survives_a_result_summary_too(self) -> None:
        md5 = "44d88612fea8a8f36de82e1278abb02f"
        assert md5 in ev.summarize_result(f"known sample {md5}, 61/70 engines")

    def test_a_digest_under_a_credential_name_is_still_replaced(self) -> None:
        # The name is the stronger signal when it is explicit: an argument
        # called ``api_key`` is a credential whatever its value looks like.
        md5 = "44d88612fea8a8f36de82e1278abb02f"
        assert ev.summarize_args({"api_key": md5}) == "api_key=***"

    def test_an_argument_is_not_a_credential_for_containing_one_as_a_substring(
        self,
    ) -> None:
        summary = ev.summarize_args({"author": "mehmet", "obsession": "none"})
        assert summary == "author=mehmet, obsession=none"

    def test_a_credential_name_written_three_ways_is_still_caught(self) -> None:
        for name in ("api_key", "apiKey", "api-key", "private_key"):
            assert ev.summarize_args({name: "value"}) == f"{name}=***", name

    def test_a_camelcase_credential_name_is_caught(self) -> None:
        """The spelling most tool servers actually use.

        An MCP server written in JavaScript names its argument ``authToken``,
        and a fourteen-character session token has no vendor prefix and no
        ``Bearer`` word, so no value rule fires either — the name is the only
        thing that can catch it.
        """
        for name in ("authToken", "apiToken", "accessToken", "userPassword", "sessionId"):
            assert ev.summarize_args({name: "value"}) == f"{name}=***", name

    def test_a_plural_credential_name_is_caught(self) -> None:
        for name in ("secrets", "tokens", "passwords", "credentials"):
            assert ev.summarize_args({name: "value"}) == f"{name}=***", name

    def test_a_digit_ends_a_word_too(self) -> None:
        assert ev.summarize_args({"token2": "value"}) == "token2=***"

    def test_a_word_that_merely_contains_one_is_still_left_alone(self) -> None:
        for name in ("author", "authored", "obsession", "tokenizer"):
            assert ev.summarize_args({name: "kept"}) == f"{name}=kept", name

    def test_a_vendor_key_prefix_is_replaced_wherever_it_appears(self) -> None:
        summary = ev.summarize_args({"value": "sk-liveKey", "note": "nvapi-abc"})
        assert summary == "value=***, note=***"

    def test_a_command_line_loses_every_host_path_it_names(self) -> None:
        line = "/opt/maljan/bin/run.sh /home/op/data/samples/ab12/evil.exe --out /tmp/x/r.json"
        summary = ev.summarize_args({"cmd": line})
        assert "/home/op" not in summary
        assert "/opt/maljan" not in summary
        assert "/tmp/x" not in summary
        assert summary == "cmd=run.sh evil.exe --out r.json"

    def test_only_a_token_shaped_like_a_path_is_cut(self) -> None:
        """A slash alone does not make a path.

        Found in a live run: a ``tool_call_finished`` summary read
        ``"mime": x-msdownload"`` because the output said
        ``"application/x-msdownload"``. A MIME type, a sub-technique id, a
        date and a ratio all carry a slash and all have to survive whole.
        """
        for value in ("application/x-msdownload", "T1055/012", "2026/09/17", "1/2"):
            assert ev.scrub(value) == value, value

    def test_a_relative_path_with_no_marker_is_left_alone(self) -> None:
        # It names no host directory, which is the thing that must not travel.
        assert ev.scrub("data/samples/a.exe") == "data/samples/a.exe"

    def test_every_shape_a_host_path_takes_is_cut(self) -> None:
        for value in (
            "/home/x/samples/a.exe",
            "./rel/a.exe",
            "../up/a.exe",
            "~/home/a.exe",
            "C:\\Users\\x\\a.exe",
        ):
            assert ev.scrub(value) == "a.exe", value

    def test_a_url_still_keeps_only_its_scheme_and_host(self) -> None:
        assert ev.scrub("https://u:p@h/x") == "https://h/…"

    def test_a_path_that_does_not_start_its_word_is_still_cut(self) -> None:
        """A host path travels wherever it sits, not only at a word boundary.

        Anchoring the marker at the start of a whitespace-separated word let
        an ``--out=`` option, a colon-separated value and a compact JSON body
        carry the per-job directory and the install prefix out verbatim.
        """
        assert ev.scrub("run.exe --out=/tmp/maljan/jobs/9f2c-uuid/r.json") == "run.exe --out=r.json"
        assert ev.scrub("key:/var/lib/x/y") == "key:y"

    def test_a_compact_json_body_loses_its_host_path(self) -> None:
        # A tool server that pre-serialises its answer sends no spaces at all,
        # so the whole body is one whitespace-separated word.
        body = '{"path":"/home/op/data/samples/ab12/evil.exe","size":1024}'
        assert ev.scrub(body) == '{"path":"evil.exe","size":1024}'

    def test_a_windows_path_inside_a_json_string_is_cut(self) -> None:
        # JSON escapes each separator, so the value arrives doubled.
        assert ev.scrub('{"path": "C:\\\\Users\\\\x\\\\a.exe"}') == '{"path": "a.exe"}'

    def test_a_file_url_keeps_no_more_than_any_other(self) -> None:
        # It has no authority, so everything after the scheme is a host path.
        assert ev.scrub("file:///home/op/data/samples/x/evil.exe") == "file:///…"

    def test_a_key_in_a_compact_json_body_is_still_replaced(self) -> None:
        body = '{"api_key":"sk-liveSecretValue0123456789"}'
        assert ev.scrub(body) == '{"api_key":"***"}'

    def test_a_scheme_and_its_secret_stop_at_the_closing_quote(self) -> None:
        assert ev.scrub('{"Authorization": "Bearer abc123"}') == '{"Authorization": "Bearer ***"}'

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

    def test_a_key_echoed_inside_json_is_replaced(self) -> None:
        """The shape a tool result actually arrives in.

        Every rule here is anchored to the whole token, and a JSON result
        hands it ``"sk-liveKey",`` rather than ``sk-liveKey`` — so before the
        punctuation was peeled off first, a key echoed by an API response
        travelled verbatim while the same key passed as a bare argument was
        replaced.
        """
        summary = ev.summarize_result('{"api_key": "sk-liveSecretValue0123456789"}')
        assert "sk-liveSecretValue0123456789" not in summary
        assert summary == '{"api_key": "***"}'

    def test_the_pack_s_hashes_result_travels_whole(self) -> None:
        """The path a real ``hashes`` entry takes, not a bare token.

        Pinned on the JSON the ledger stores rather than on the digest alone,
        because that is what ``summarize_result`` is given and because the
        digests used to survive it for the wrong reason — the quotes and the
        comma defeated the whole-token credential test rather than the digest
        exemption doing it.
        """
        output = (
            '{"md5": "44d88612fea8a8f36de82e1278abb02f", '
            '"sha1": "3395856ce81f2b7382dee72602f798b642f14140", '
            '"sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", '
            '"mime": "application/x-msdownload"}'
        )
        assert ev.summarize_result(output) == output

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

    def test_a_specialist_a_lead_can_ask_is_on_the_roster(self) -> None:
        """The defect a live ``team_lead`` run showed.

        The stage list named three participants and the run then produced
        messages from five more: the specialists are the lead's tools, not
        stages, so nothing had put them on the roster and the console had no
        name for the first delegated message that arrived.
        """
        from maljan.core.config import _builtin_definitions, _builtin_profiles

        payload = ev.roster_payload(
            _builtin_profiles()["team_lead"], _builtin_definitions(), depth=2
        )
        by_key = {a["key"]: a for a in payload["agents"]}

        # The specialists: reachable only through the lead's ask tools.
        for key in ("static", "dynamic", "network", "reverser", "triage"):
            assert key in by_key, key
            assert by_key[key]["via"] == ["lead"], key
            assert by_key[key]["stages"] == [], key
            assert by_key[key]["label"], key
            assert by_key[key]["role"], key

        # The agents the stages name carry no ``via``.
        for key in ("lead", "judge", "reporter"):
            assert "via" not in by_key[key], key
            assert by_key[key]["stages"], key

        # The stage list itself is unchanged by any of it.
        assert [s["key"] for s in payload["stages"]] == [
            "triage_pack",
            "lead",
            "verdict",
            "report",
        ]

    def test_the_walk_stops_at_the_depth_the_asks_stop_at(self) -> None:
        profile = {
            "stages": [{"key": "lead", "label": "Lead", "kind": "analysis", "agents": ["a"]}]
        }
        definitions = {
            "a": {"role": "lead", "label": "A", "tools": [{"kind": "agent", "agent": "b"}]},
            "b": {"role": "generic", "label": "B", "tools": [{"kind": "agent", "agent": "c"}]},
            "c": {"role": "generic", "label": "C", "tools": [{"kind": "agent", "agent": "d"}]},
            "d": {"role": "generic", "label": "D"},
        }
        one = {a["key"] for a in ev.roster_payload(profile, definitions, depth=1)["agents"]}
        two = {a["key"] for a in ev.roster_payload(profile, definitions, depth=2)["agents"]}
        assert one == {"a", "b"}
        assert two == {"a", "b", "c"}

    def test_a_callee_two_agents_can_ask_is_listed_once_with_both(self) -> None:
        profile = {
            "stages": [{"key": "lead", "label": "Lead", "kind": "analysis", "agents": ["a", "b"]}]
        }
        definitions = {
            "a": {"role": "lead", "label": "A", "tools": [{"kind": "agent", "agent": "c"}]},
            "b": {"role": "lead", "label": "B", "tools": [{"kind": "agent", "agent": "c"}]},
            "c": {"role": "generic", "label": "C"},
        }
        agents = ev.roster_payload(profile, definitions, depth=2)["agents"]
        specialists = [a for a in agents if a["key"] == "c"]
        assert len(specialists) == 1
        assert specialists[0]["via"] == ["a", "b"]

    def test_a_disabled_specialist_is_not_listed(self) -> None:
        # An ask of it is refused by name, so it can never speak.
        profile = {
            "stages": [{"key": "lead", "label": "Lead", "kind": "analysis", "agents": ["a"]}]
        }
        definitions = {
            "a": {"role": "lead", "label": "A", "tools": [{"kind": "agent", "agent": "b"}]},
            "b": {"role": "generic", "label": "B", "enabled": False},
        }
        keys = {a["key"] for a in ev.roster_payload(profile, definitions)["agents"]}
        assert keys == {"a"}

    def test_a_cycle_is_walked_once(self) -> None:
        profile = {
            "stages": [{"key": "lead", "label": "Lead", "kind": "analysis", "agents": ["a"]}]
        }
        definitions = {
            "a": {"role": "lead", "label": "A", "tools": [{"kind": "agent", "agent": "b"}]},
            "b": {"role": "generic", "label": "B", "tools": [{"kind": "agent", "agent": "a"}]},
        }
        agents = ev.roster_payload(profile, definitions, depth=5)["agents"]
        assert [a["key"] for a in agents] == ["a", "b"]
        # ``a`` is named by a stage, so being asked back does not give it one.
        assert "via" not in agents[0]

    def test_the_roster_is_emitted_under_its_own_type(self) -> None:
        recorded, sink = _sink()
        ev.emit_roster(sink, ev.roster_payload(self._profile(), self._definitions()))
        assert recorded[0][0] == "roster"
        assert set(recorded[0][1]) == {"agents", "stages"}
