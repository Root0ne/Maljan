"""The served window is learned for free, and it is what sizes a tool answer.

Three claims, tested apart:

* the probe reads a window out of the shapes the four server kinds answer with,
  and it can reach nothing but the metadata paths it names;
* the arithmetic that turns a window into a character cap is a function of its
  inputs, with the two properties the design rests on — the answers of one
  conversation sum to less than the room it started with, and the floor holds;
* what could not be learned is said in words rather than guessed at.

Everything runs against hand-written fixtures and a stub transport. No server
is started and none is asked for.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from maljan.llm import context_window as cw


def _client(handler: Any) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


class TestWhatEachServerKindReports:
    """One shape per server kind, written the way the server writes it."""

    def test_llama_cpp_props_gives_the_window_the_server_was_started_with(self) -> None:
        payload = {
            "default_generation_settings": {"n_ctx": 32768, "n_predict": -1},
            "total_slots": 1,
        }
        assert cw.window_from_llama_props(payload) == 32768

    def test_llama_cpp_per_slot_window_is_read_when_the_whole_one_is_absent(self) -> None:
        payload = {"default_generation_settings": {"n_ctx_per_seq": 16384}}
        assert cw.window_from_llama_props(payload) == 16384

    def test_a_props_answer_without_a_window_reports_nothing(self) -> None:
        assert cw.window_from_llama_props({"default_generation_settings": {}}) == 0
        assert cw.window_from_llama_props(["not a mapping"]) == 0

    def test_a_vllm_model_entry_carries_max_model_len(self) -> None:
        payload = {"object": "list", "data": [{"id": "qwen3-8b", "max_model_len": 40960}]}
        assert cw.window_from_model_list(payload, "qwen3-8b") == 40960

    def test_an_openrouter_entry_carries_context_length(self) -> None:
        payload = {
            "data": [
                {"id": "openai/gpt-4o", "context_length": 128000},
                {"id": "anthropic/claude-sonnet-4", "context_length": 200000},
            ]
        }
        assert cw.window_from_model_list(payload, "anthropic/claude-sonnet-4") == 200000

    def test_a_server_with_one_model_answers_for_it_whatever_it_is_called(self) -> None:
        """A local server advertises the file it loaded, not the tag configured."""
        payload = {"data": [{"id": "/models/Qwen3-35B.gguf", "max_model_len": 32768}]}
        assert cw.window_from_model_list(payload, "qwen3.5:9b") == 32768

    def test_a_model_list_that_names_no_window_reports_nothing(self) -> None:
        payload = {"data": [{"id": "gpt-4o", "object": "model"}, {"id": "gpt-4o-mini"}]}
        assert cw.window_from_model_list(payload, "gpt-4o") == 0

    def test_ollama_reports_the_window_under_its_architecture(self) -> None:
        payload = {
            "model_info": {"general.architecture": "qwen3", "qwen3.context_length": 40960},
            "parameters": 'stop "<|im_end|>"\n',
        }
        assert cw.window_from_ollama_show(payload) == 40960

    def test_an_ollama_num_ctx_parameter_is_the_served_window(self) -> None:
        """The Modelfile's own setting binds below whatever the weights allow."""
        payload = {
            "model_info": {"qwen3.context_length": 40960},
            "parameters": 'num_ctx 8192\nstop "<|im_end|>"\n',
        }
        assert cw.window_from_ollama_show(payload) == 8192

    def test_text_generation_inference_reports_max_total_tokens(self) -> None:
        assert cw.window_from_tgi_info({"max_total_tokens": 8192}) == 8192
        assert cw.window_from_tgi_info({"model_id": "a/b"}) == 0


class TestTheProbeCanReachNothingThatGenerates:
    """The guard. A window is learned for free or it is not learned."""

    MATRIX = [
        ("openai", "http://127.0.0.1:8080/v1", "qwen3"),
        ("openai", "http://127.0.0.1:8080", "qwen3"),
        ("openai", "https://api.openai.com/v1", "gpt-4o-mini"),
        ("openai", "https://openrouter.ai/api/v1", "openai/gpt-4o"),
        ("ollama", "http://localhost:11434", "qwen3.5:9b"),
        ("ollama", "", "qwen3.5:9b"),
        ("anthropic", "the Anthropic API", "claude-sonnet-4-20250514"),
        ("gemini", "the Gemini API", "gemini-2.5-pro"),
        ("", "", ""),
    ]

    def test_every_request_the_module_can_plan_is_a_metadata_path(self) -> None:
        """A plan is the configured address plus one of four fixed suffixes."""
        for provider, endpoint, model in self.MATRIX:
            for ask in cw.probe_plan(provider, endpoint, model):
                assert ask.url.endswith(cw.PROBE_PATHS), (provider, endpoint, ask.url)
                suffix = next(p for p in cw.PROBE_PATHS if ask.url.endswith(p))
                root = ask.url[: -len(suffix)]
                assert root, ask.url
                configured = str(endpoint).rstrip("/")
                assert not configured or configured.startswith(root), (endpoint, ask.url)

    def test_no_planned_path_is_one_a_model_answers_on(self) -> None:
        forbidden = ("completion", "/chat", "generate", "/messages", "generatecontent", "/invoke")
        for path in cw.PROBE_PATHS:
            assert not any(word in path.lower() for word in forbidden), path

    def test_a_probe_that_is_pointed_elsewhere_never_sends_the_request(self) -> None:
        """Driven through a transport that refuses anything off the list."""
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.url.path)
            assert request.url.path.endswith(cw.PROBE_PATHS), request.url.path
            return httpx.Response(404, json={})

        for provider, endpoint, model in self.MATRIX:
            with _client(handler) as client:
                for ask in cw.probe_plan(provider, endpoint, model):
                    if ask.method == "POST":
                        client.post(ask.url, json=ask.body or {})
                    else:
                        client.get(ask.url)
        assert seen, "the matrix planned nothing at all"

    def test_the_module_never_asks_a_model_to_produce_anything(self) -> None:
        """The source itself carries no path a generation call is made on."""
        from pathlib import Path

        source = Path(cw.__file__).read_text(encoding="utf-8").lower()
        for word in ("completions", "generatecontent", "/api/generate", "/v1/messages"):
            assert word not in source, word


class TestLearningTheWindow:
    def setup_method(self) -> None:
        cw.forget_learned_windows()

    def teardown_method(self) -> None:
        cw.forget_learned_windows()

    def test_a_declared_window_short_circuits_everything(self) -> None:
        fact = cw.learn_window("openai", endpoint="http://x/v1", model="gpt-4o", declared=65536)
        assert (fact.tokens, fact.source) == (65536, cw.DECLARED)

    def test_a_model_the_table_names_is_answered_without_the_network(self) -> None:
        fact = cw.learn_window("anthropic", endpoint="the Anthropic API", model="claude-3-5-haiku")
        assert (fact.tokens, fact.source) == (200000, cw.TABLE)

    def test_a_model_nothing_knows_falls_back_and_says_so(self) -> None:
        fact = cw.learn_window("anthropic", endpoint="the Anthropic API", model="a-private-build")
        assert fact.tokens == cw.FALLBACK_WINDOW_TOKENS
        assert fact.source == cw.FALLBACK
        assert fact.detail.strip(), "a fallback with no reason is a guess"

    def test_an_endpoint_that_cannot_be_reached_never_raises(self) -> None:
        fact = cw.learn_window(
            "openai",
            endpoint="http://127.0.0.1:1/v1",
            model="qwen3",
            probe=True,
        )
        assert fact.source in (cw.TABLE, cw.FALLBACK)

    def test_the_table_is_matched_on_the_longest_family(self) -> None:
        assert cw.table_window("gpt-4o-mini").tokens == 128000
        assert cw.table_window("gpt-4").tokens == 8192

    def test_a_vendor_prefix_and_a_tag_are_not_part_of_the_family(self) -> None:
        assert cw.model_family("openrouter/qwen/qwen3:32b") == "qwen3"
        assert cw.model_family("Qwen3.5:9B") == "qwen3.5"


class TestTheArithmetic:
    """One function, and the two properties the design rests on."""

    def test_an_unknown_window_is_the_floor(self) -> None:
        assert cw.derive_tool_output_chars(window_tokens=0) == cw.MIN_TOOL_OUTPUT_CHARS

    def test_the_window_this_deployment_serves(self) -> None:
        """32,768 tokens, an empty conversation, the configured reply reserve."""
        assert cw.derive_tool_output_chars(window_tokens=32768, reply_tokens=8192) == 9216

    def test_a_million_token_window_is_not_spent_as_if_it_were_small(self) -> None:
        cap = cw.derive_tool_output_chars(window_tokens=1_000_000, reply_tokens=8192)
        assert cap == 371_928

    def test_a_fuller_conversation_gets_a_smaller_answer(self) -> None:
        empty = cw.derive_tool_output_chars(window_tokens=32768, reply_tokens=8192)
        half = cw.derive_tool_output_chars(
            window_tokens=32768, reply_tokens=8192, held_chars=30_000
        )
        assert half < empty

    def test_a_nearly_full_conversation_still_gets_a_usable_answer(self) -> None:
        cap = cw.derive_tool_output_chars(
            window_tokens=32768, reply_tokens=8192, held_chars=10_000_000
        )
        assert cap == cw.MIN_TOOL_OUTPUT_CHARS

    def test_the_floor_leaves_room_for_the_notice_and_a_document(self) -> None:
        from maljan.agents.output_shortening import MAX_SENTENCE_ROOM, shorten_target

        assert cw.MIN_TOOL_OUTPUT_CHARS > MAX_SENTENCE_ROOM
        assert shorten_target(cw.MIN_TOOL_OUTPUT_CHARS, ("limit", "offset")) > 1000

    def test_the_answers_of_one_conversation_sum_to_less_than_its_room(self) -> None:
        """The property that makes the share a count rather than a safety margin."""
        window, reply = 32768, 8192
        free_chars = (window - reply) * cw.CHARS_PER_TOKEN
        held = 0
        spent = 0
        for _ in range(40):
            cap = cw.derive_tool_output_chars(
                window_tokens=window, reply_tokens=reply, held_chars=held, floor=0
            )
            spent += cap
            held += cap
        assert spent < free_chars

    def test_twelve_answers_clear_the_floor_on_the_smallest_window(self) -> None:
        """The count the share is argued from, computed rather than asserted."""
        window, reply = 32768, 8192
        held = 0
        above = 0
        for _ in range(40):
            cap = cw.derive_tool_output_chars(
                window_tokens=window, reply_tokens=reply, held_chars=held
            )
            if cap > cw.MIN_TOOL_OUTPUT_CHARS:
                above += 1
            held += cap
        assert above == 12

    def test_the_first_answer_beats_the_constant_it_replaces(self) -> None:
        """6,000 characters was tuned against this deployment's own model."""
        assert cw.derive_tool_output_chars(window_tokens=32768, reply_tokens=8192) > 6000

    def test_the_reply_reserve_never_eats_a_small_window_whole(self) -> None:
        assert cw.reply_reserve_tokens(8192, 8192) == 2048
        assert cw.reply_reserve_tokens(32768, 8192) == 8192
        assert cw.reply_reserve_tokens(32768, 0) == cw.DEFAULT_REPLY_TOKENS

    def test_the_characters_per_token_figure_is_the_measured_one(self) -> None:
        """Nineteen answers of 6,000 characters measured at 38,868 tokens."""
        measured = (19 * 6000) / 38_868
        assert round(measured) == cw.CHARS_PER_TOKEN


class TestTheBudgetOneRunSpends:
    def test_an_empty_budget_reports_the_window_it_was_built_with(self) -> None:
        budget = cw.ContextBudget(cw.WindowFact(32768, cw.PROBED, "props"), reply_tokens=8192)
        assert budget.chars_for_one_answer() == 9216
        snapshot = budget.snapshot()
        assert snapshot["window_tokens"] == 32768
        assert snapshot["window_source"] == cw.PROBED
        assert snapshot["chars_per_token"] == cw.CHARS_PER_TOKEN
        assert snapshot["cap_largest"] == 9216

    def test_the_fullest_live_conversation_decides(self) -> None:
        budget = cw.ContextBudget(cw.WindowFact(32768, cw.PROBED, "props"), reply_tokens=8192)
        budget.note_conversation("static", 60_000)
        budget.note_conversation("network", 1_000)
        assert budget.chars_for_one_answer() == cw.MIN_TOOL_OUTPUT_CHARS

    def test_a_finished_loop_stops_binding(self) -> None:
        budget = cw.ContextBudget(cw.WindowFact(32768, cw.PROBED, "props"), reply_tokens=8192)
        budget.note_conversation("static", 60_000)
        budget.forget_conversation("static")
        assert budget.chars_for_one_answer() == 9216

    def test_a_toolkit_without_a_budget_gets_the_conservative_one(self) -> None:
        budget = cw.budget_or_unknown(None)
        assert budget.window.source == cw.FALLBACK
        assert budget.chars_for_one_answer() == 2304

    def test_the_snapshot_records_the_smallest_and_largest_cap_in_force(self) -> None:
        budget = cw.ContextBudget(cw.WindowFact(32768, cw.PROBED, "props"), reply_tokens=8192)
        budget.chars_for_one_answer()
        budget.note_conversation("static", 60_000)
        budget.chars_for_one_answer()
        snapshot = budget.snapshot()
        assert snapshot["cap_largest"] == 9216
        assert snapshot["cap_smallest"] == cw.MIN_TOOL_OUTPUT_CHARS


class TestTheVendoredTable:
    def test_the_file_says_it_is_a_fallback_and_how_to_correct_it(self) -> None:
        from maljan.core.paths import resolve_data

        raw = json.loads(resolve_data(cw.TABLE_PATH).read_text(encoding="utf-8"))
        note = " ".join(raw["_comment"]).lower()
        assert "fallback" in note
        assert "core.llm.openai.context_size" in note

    def test_every_row_is_a_positive_token_count(self) -> None:
        from maljan.core.paths import resolve_data

        raw = json.loads(resolve_data(cw.TABLE_PATH).read_text(encoding="utf-8"))
        for key, value in raw["windows"].items():
            assert isinstance(value, int) and value > 0, key
            assert key == key.lower(), key


@pytest.mark.parametrize(
    ("provider", "endpoint", "payload", "path", "expected"),
    [
        (
            "openai",
            "http://127.0.0.1:8080/v1",
            {"default_generation_settings": {"n_ctx": 32768}},
            "/props",
            32768,
        ),
        (
            "ollama",
            "http://localhost:11434",
            {"model_info": {"qwen3.context_length": 40960}},
            "/api/show",
            40960,
        ),
    ],
)
def test_a_server_that_answers_is_reported_as_probed(
    provider: str, endpoint: str, payload: dict, path: str, expected: int
) -> None:
    """The transport is a stub; the reading and the wording are the real ones."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path != path:
            return httpx.Response(404, json={})
        return httpx.Response(200, json=payload)

    real_client = httpx.Client

    def stub(**_kwargs: Any) -> httpx.Client:
        return real_client(transport=httpx.MockTransport(handler))

    try:
        httpx.Client = stub  # type: ignore[assignment,misc]
        fact = cw.probe_window(provider, endpoint=endpoint, model="qwen3")
    finally:
        httpx.Client = real_client  # type: ignore[misc]
    assert fact is not None
    assert (fact.tokens, fact.source) == (expected, cw.PROBED)
    assert f"{expected:,}" in fact.detail
